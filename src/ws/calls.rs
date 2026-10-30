//! Appels : DM 1:1, groupe (P2P mesh puis SFU), serveur (SFU), signalisation WebRTC, relais SFU.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tracing::{error, info, warn};

use super::helpers::*;
use super::{on, Ack, SockCtx};
use crate::http::routes_misc::{is_id, js_string, truthy};
use crate::perms::{CONNECT, MOVE_MEMBERS, READ};
use crate::state::event;
use crate::validation::field;

/// Au-delà de ce nombre de participants, un appel de groupe bascule du P2P vers le SFU.
pub fn group_sfu_threshold() -> usize {
    std::env::var("GROUP_SFU_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(10)
}

fn call_type(data: &Value) -> &'static str {
    if field(data, "type") == "video" {
        "video"
    } else {
        "voice"
    }
}

/// Sockets d'une room d'appel : nombre total (toutes instances) et clients locaux connus.
async fn call_room(c: &SockCtx, call_id: &str) -> (usize, Vec<crate::state::ConnectedClient>) {
    let sockets = c.io().within(format!("call:{call_id}")).fetch_sockets().await.unwrap_or_default();
    let clients = c.app.conns.clients.lock();
    let known = sockets.iter().filter_map(|s| clients.get(&s.data().id.to_string()).cloned()).collect();
    (sockets.len(), known)
}

fn existing_participants(clients: &[crate::state::ConnectedClient], me: &str) -> Vec<Value> {
    clients
        .iter()
        .filter(|cl| !cl.user_id.is_empty() && cl.user_id != me)
        .map(|cl| {
            let name = ["displayName", "username"].iter().find_map(|k| cl.user.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty())).unwrap_or("Utilisateur");
            json!({ "userId": cl.user_id, "userName": name, "userAvatar": cl.user.get("avatarUrl").filter(|v| !v.is_null()).cloned() })
        })
        .collect()
}

/// `existingCallId` renvoyé par le service calls dans un 409.
fn existing_call_id_of(message: &str) -> Option<String> {
    let rest = message.strip_prefix("Service error: ")?;
    let body = rest.get(4..)?;
    let id = serde_json::from_str::<Value>(body).ok()?.get("existingCallId")?.as_str()?.to_string();
    is_id(&id).then_some(id)
}

async fn clear_active_call(c: &SockCtx, call_id: &str) {
    if let Ok(Some(channel_id)) = c.app.redis.get(&format!("call:channel:{call_id}")).await {
        let _ = c.app.redis.del(&format!("call:active:group:{channel_id}")).await;
        let _ = c.app.redis.del(&format!("call:channel:{call_id}")).await;
        let _ = c.io().to(format!("conversation:{channel_id}")).emit("CALL_ACTIVE_ENDED", &json!({ "callId": call_id })).await;
    }
}

fn reply(ack: &mut Ack, v: Value) {
    ack.send(&v);
}

pub fn register(c: &Arc<SockCtx>) {
    // ── Appel DM 1:1 ──────────────────────────────────────────────────────
    on(c, "CALL_INITIATE", |c, data, mut ack| async move {
        let r: Result<(), String> = async {
            info!("CALL_INITIATE DM de {} ({}) vers {} type={}", c.user_id, c.username(), data.get("recipientId").map(|v| js_string(Some(v))).unwrap_or_else(|| "?".into()), js_string(data.get("type")));
            let app = &c.app;
            let ctype = call_type(&data);
            let (conversation_id, recipient_id): (Option<String>, Option<String>);
            match data.get("recipientId") {
                Some(r) if !r.is_null() => {
                    if !val_is_uuid(r) || r.as_str() == Some(c.user_id.as_str()) {
                        reply(&mut ack, json!({ "error": "INVALID_RECIPIENT" }));
                        return Ok(());
                    }
                    let rid = r.as_str().unwrap().to_string();
                    conversation_id = Some(dm_id_for(&c.user_id, &rid));
                    recipient_id = Some(rid);
                }
                _ => {
                    if has_conversation_access(app, &c.user_id, field(&data, "conversationId")).await {
                        conversation_id = Some(js_string(data.get("conversationId")));
                        recipient_id = dm_peer(&json!(conversation_id), &c.user_id);
                    } else {
                        reply(&mut ack, json!({ "error": "FORBIDDEN" }));
                        return Ok(());
                    }
                }
            }
            if let Some(rid) = &recipient_id {
                if crate::nodes::is_dm_blocked(app, &c.user_id, rid).await || !can_direct_message(app, &c.user_id, rid).await {
                    reply(&mut ack, json!({ "error": "CALL_NOT_ALLOWED" }));
                    return Ok(());
                }
            }
            let call = app.svc.calls_initiate(ctype, &c.user_id, conversation_id.as_deref(), None, recipient_id.as_deref()).await.map_err(|e| e.message)?;
            let call_id = ["id", "callId"].iter().find_map(|k| call.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty())).unwrap_or("").to_string();
            if call_id.is_empty() {
                return Err("Calls service returned no call ID".into());
            }
            let _ = c.socket.join(format!("call:{call_id}"));
            reply(&mut ack, json!({ "callId": call_id, "id": call_id }));

            let call_payload = json!({
                "callId": call_id, "conversationId": conversation_id, "initiatorId": c.user_id,
                "recipientId": recipient_id, "callerName": c.display_name(), "callerAvatar": c.user.get("avatarUrl").filter(|v| !v.is_null()),
                "callType": ctype, "isGroup": false,
            });
            let incoming = event("CALL_INCOMING", call_payload);
            if let Some(rid) = &recipient_id {
                // Un `emit` par socket du destinataire (et sur chaque instance)
                let _ = c.io().to(format!("user:{rid}")).emit("CALL_INCOMING", &incoming).await;
                let _ = app.redis.set(&format!("pending_call:user:{rid}"), &incoming.to_string(), Some(60)).await;
            } else if let Some(cid) = &conversation_id {
                let _ = c.socket.to(format!("conversation:{cid}")).emit("CALL_INCOMING", &incoming).await;
            }
            info!("Appel DM créé: {call_id}");
            Ok(())
        }
        .await;
        if let Err(m) = r {
            c.emit_error("CALL_ERROR", &m);
            reply(&mut ack, json!({ "error": "Failed to initiate call" }));
        }
    });

    // ── Appel groupe (WebRTC P2P mesh) ────────────────────────────────────
    on(c, "CALL_INITIATE_GROUP", |c, data, mut ack| async move {
        let r: Result<(), String> = async {
            let channel = field(&data, "channelId");
            info!("CALL_INITIATE_GROUP de {} ({}) channel={} type={}", c.user_id, c.username(), js_string(Some(channel)), js_string(data.get("type")));
            if !truthy(Some(channel)) {
                reply(&mut ack, json!({ "error": "channelId requis" }));
                return Ok(());
            }
            // `channelId` désigne une conversation de groupe : sans contrôle on sonnait n'importe quel groupe.
            if !has_conversation_access(&c.app, &c.user_id, channel).await {
                reply(&mut ack, json!({ "error": "FORBIDDEN" }));
                return Ok(());
            }
            let ctype = call_type(&data);
            let channel_id = js_string(Some(channel));
            let group_call = c.app.svc.calls_create_group(json!({ "channelId": channel_id, "initiatorId": c.user_id, "type": ctype }), &c.user_id).await.map_err(|e| e.message)?;
            let call_id = ["id", "callId"].iter().find_map(|k| group_call.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty())).unwrap_or("").to_string();
            if call_id.is_empty() {
                return Err("Calls service returned no call ID".into());
            }
            let _ = c.socket.join(format!("call:{call_id}"));
            reply(&mut ack, json!({ "callId": call_id, "id": call_id }));

            let call_payload = json!({
                "callId": call_id, "channelId": channel_id, "callType": ctype, "isGroup": true, "initiatorId": c.user_id,
                "callerName": c.display_name(), "callerAvatar": c.user.get("avatarUrl").filter(|v| !v.is_null()),
            });
            let _ = c.socket.to(format!("conversation:{channel_id}")).emit("CALL_INCOMING", &event("CALL_INCOMING", call_payload.clone())).await;
            // Appel actif persisté pour les membres qui rejoignent après le démarrage
            let mut active = call_payload;
            active["callCategory"] = json!("group");
            let _ = c.app.redis.set(&format!("call:active:group:{channel_id}"), &active.to_string(), Some(4 * 3600)).await;
            let _ = c.app.redis.set(&format!("call:channel:{call_id}"), &channel_id, Some(4 * 3600)).await;
            info!("Appel groupe créé: {call_id} channel={channel_id}");
            Ok(())
        }
        .await;
        if let Err(m) = r {
            c.emit_error("CALL_ERROR", &m);
            reply(&mut ack, json!({ "error": "Failed to initiate group call" }));
        }
    });

    // ── Rejoindre un appel existant ───────────────────────────────────────
    on(c, "CALL_JOIN", |c, data, mut ack| async move {
        let call_id_v = field(&data, "callId");
        if !truthy(Some(call_id_v)) {
            return;
        }
        let call_id = js_string(Some(call_id_v));
        let r: Result<(), crate::svc::SvcErr> = async {
            let app = &c.app;
            let call = app.svc.calls_get(&call_id).await;
            let call = match call {
                Some(call) if call.get("status").and_then(|s| s.as_str()) != Some("ended") => call,
                _ => {
                    reply(&mut ack, json!({ "error": "Appel introuvable ou terminé" }));
                    return Ok(());
                }
            };
            app.svc.calls_join(&call_id, &c.user_id).await?;
            let _ = app.redis.del(&format!("pending_call:user:{}", c.user_id)).await;

            // Participants déjà dans la room Socket.IO (avec infos utilisateur)
            let (count, clients) = call_room(&c, &call_id).await;
            let existing = existing_participants(&clients, &c.user_id);
            let _ = c.socket.join(format!("call:{call_id}"));

            // Le groupe franchit-il le seuil P2P → SFU ?
            let new_count = count + 1;
            let cat = call.get("callCategory").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("group").to_string();
            let mut mode = "p2p";
            if cat == "server" {
                mode = "sfu";
            } else if cat == "group" && new_count > group_sfu_threshold() {
                mode = "sfu";
                let current = app.redis.get(&format!("call:mode:{call_id}")).await.ok().flatten();
                if current.as_deref() != Some("sfu") {
                    let _ = app.redis.set(&format!("call:mode:{call_id}"), "sfu", Some(3600)).await;
                    let _ = app.svc.sfu_create_room(&call_id, "group").await; // ok si existe déjà
                    broadcast_mode_switch(&c, &call_id, "sfu").await;
                }
            }

            c.to_room_others(
                &format!("call:{call_id}"),
                "CALL_PARTICIPANT_JOINED",
                json!({ "callId": call_id, "userId": c.user_id, "userName": c.display_name(), "userAvatar": c.user.get("avatarUrl").filter(|v| !v.is_null()), "existingParticipants": [], "callMode": mode }),
            )
            .await;
            c.to_room(&format!("call:{call_id}"), "CALL_PARTICIPANT_COUNT", json!({ "callId": call_id, "count": new_count })).await;

            // SFU : producteurs déjà publiés dans la salle (micros, caméras, écrans)
            let mut existing_producers: Vec<Value> = vec![];
            if mode == "sfu" {
                match app.svc.sfu_get_producers(&call_id).await {
                    Ok(res) => {
                        existing_producers = res.get("producers").and_then(|p| p.as_array()).map(|a| a.iter().filter(|p| p.get("userId").and_then(|u| u.as_str()) != Some(c.user_id.as_str())).cloned().collect()).unwrap_or_default();
                    }
                    Err(_) => {
                        // Salle absente (media-server redémarré) : on la recrée, vide.
                        let _ = app.svc.sfu_create_room(&call_id, if cat == "server" { "server" } else { "group" }).await;
                    }
                }
            }
            let ack_payload = json!({ "callId": call_id, "existingParticipants": existing, "existingProducers": existing_producers, "callMode": mode });
            if ack.present {
                reply(&mut ack, ack_payload);
            } else {
                let _ = c.socket.emit("CALL_JOIN_ACK", &ack_payload);
            }
            info!("{} a rejoint l'appel {cat} {call_id} ({new_count} participants, mode={mode})", c.user_id);
            Ok(())
        }
        .await;
        if let Err(e) = r {
            if e.status == Some(404) {
                c.emit_event("CALL_END", json!({ "callId": call_id }));
                reply(&mut ack, json!({ "error": "Appel déjà terminé" }));
            } else {
                c.emit_error("CALL_ERROR", &e.message);
                reply(&mut ack, json!({ "error": "Failed to join call" }));
            }
        }
    });

    on(c, "CALL_ACCEPT", |c, data, _| async move {
        let call_id = js_string(data.get("callId"));
        let r: Result<(), crate::svc::SvcErr> = async {
            // Idempotence : déjà dans la room (double acceptation depuis un autre onglet)
            let (_, clients) = call_room(&c, &call_id).await;
            if clients.iter().any(|cl| cl.user_id == c.user_id) {
                let _ = c.socket.join(format!("call:{call_id}"));
                return Ok(());
            }
            c.app.svc.calls_join(&call_id, &c.user_id).await?;
            let _ = c.app.redis.del(&format!("pending_call:user:{}", c.user_id)).await;
            let (_, clients) = call_room(&c, &call_id).await;
            let existing = existing_participants(&clients, &c.user_id);
            let _ = c.socket.join(format!("call:{call_id}"));
            c.to_room_others(
                &format!("call:{call_id}"),
                "CALL_PARTICIPANT_JOINED",
                json!({ "callId": call_id, "userId": c.user_id, "userName": c.display_name(), "userAvatar": c.user.get("avatarUrl").filter(|v| !v.is_null()), "existingParticipants": [] }),
            )
            .await;
            c.to_room(&format!("call:{call_id}"), "CALL_ACCEPT", json!({ "callId": call_id, "userId": c.user_id, "existingParticipants": existing })).await;
            info!("Appel {call_id} accepté par {}", c.user_id);
            Ok(())
        }
        .await;
        if let Err(e) = r {
            if e.status == Some(404) {
                // L'appel s'est terminé avant l'acceptation : fermeture propre côté accepteur
                c.emit_event("CALL_END", json!({ "callId": call_id }));
            } else {
                c.emit_error("CALL_ERROR", &e.message);
            }
        }
    });

    on(c, "CALL_REJECT", |c, data, _| async move {
        let call_id = js_string(data.get("callId"));
        match c.app.svc.calls_reject(&call_id, &c.user_id).await {
            Ok(_) => {
                let _ = c.app.redis.del(&format!("pending_call:user:{}", c.user_id)).await;
                c.to_room(&format!("call:{call_id}"), "CALL_REJECT", json!({ "callId": data.get("callId"), "userId": c.user_id })).await;
            }
            Err(e) => c.emit_error("CALL_ERROR", &e.message),
        }
    });

    on(c, "CALL_LEAVE", |c, data, _| async move {
        let call_id = js_string(data.get("callId"));
        let r: Result<(), crate::svc::SvcErr> = async {
            c.app.svc.calls_leave(&call_id, &c.user_id).await?;
            let _ = c.socket.leave(format!("call:{call_id}"));
            c.to_room(&format!("call:{call_id}"), "CALL_PARTICIPANT_LEFT", json!({ "callId": data.get("callId"), "userId": c.user_id })).await;
            // Plus aucun participant dans la room → l'appel est terminé
            let (remaining, _) = call_room(&c, &call_id).await;
            if remaining == 0 {
                c.app.svc.calls_end(&call_id, &c.user_id).await?;
                let (a, id) = (c.app.clone(), call_id.clone());
                tokio::spawn(async move {
                    let _ = a.svc.sfu_destroy_room(&id).await;
                });
                c.to_room(&format!("call:{call_id}"), "CALL_END", json!({ "callId": data.get("callId") })).await;
                clear_active_call(&c, &call_id).await;
            }
            info!("{} a quitté l'appel {call_id}", c.user_id);
            Ok(())
        }
        .await;
        if let Err(e) = r {
            c.emit_error("CALL_ERROR", &e.message);
        }
    });

    on(c, "CALL_END", |c, data, _| async move {
        let call_id = js_string(data.get("callId"));
        match c.app.svc.calls_end(&call_id, &c.user_id).await {
            Ok(_) => {
                c.to_room(&format!("call:{call_id}"), "CALL_END", json!({ "callId": data.get("callId") })).await;
                // Éjecter tous les sockets de la room
                let _ = c.io().within(format!("call:{call_id}")).leave(format!("call:{call_id}")).await;
                clear_active_call(&c, &call_id).await;
            }
            Err(e) => c.emit_error("CALL_ERROR", &e.message),
        }
    });

    // ── Signalisation WebRTC : ciblée vers targetUserId (ou diffusion à l'appel) ──
    for (ev, key) in [("WEBRTC_OFFER", "offer"), ("WEBRTC_ANSWER", "answer"), ("WEBRTC_ICE_CANDIDATE", "candidate")] {
        on(c, ev, move |c, data, _| async move {
            relay_webrtc(&c, ev, &data, key).await;
        });
    }

    on(c, "CALL_SCREEN_SHARE", |c, data, _| async move {
        let call_id = field(&data, "callId");
        if !truthy(Some(call_id)) || !c.in_room(&format!("call:{}", js_string(Some(call_id)))) {
            return;
        }
        c.to_room_others(&format!("call:{}", js_string(Some(call_id))), "CALL_SCREEN_SHARE", json!({ "callId": call_id, "fromUserId": c.user_id, "active": data.get("active") })).await;
    });

    // Reconnexion à un appel après perte de la connexion WebSocket
    on(c, "CALL_REJOIN", |c, data, _| async move {
        let Some(call_id) = field(&data, "callId").as_str().filter(|s| !s.is_empty()).map(str::to_string) else { return };
        // Sécurité : vérifier que l'utilisateur fait bien partie de l'appel avant de lui rendre la room.
        let Some(call) = c.app.svc.calls_get(&call_id).await else {
            warn!("CALL_REJOIN refusé: {} n'est pas participant de {call_id}", c.user_id);
            return;
        };
        let participates = call.get("participants").and_then(|p| p.as_array()).map(|a| a.iter().any(|p| p.as_str() == Some(c.user_id.as_str()))).unwrap_or(false);
        if !participates {
            warn!("CALL_REJOIN refusé: {} n'est pas participant de {call_id}", c.user_id);
            return;
        }
        if call.get("status").and_then(|s| s.as_str()) == Some("ended") {
            return;
        }
        let _ = c.socket.join(format!("call:{call_id}"));
        c.to_room_others(&format!("call:{call_id}"), "CALL_PEER_RECONNECTED", json!({ "callId": call_id, "userId": c.user_id })).await;
        info!("{} rejoint la room call:{call_id} après reconnexion", c.user_id);
    });

    // ── Appel serveur / communauté (SFU toujours) ─────────────────────────
    on(c, "CALL_INITIATE_SERVER", |c, data, mut ack| async move {
        let r: Result<(), String> = async {
            let app = &c.app;
            let (channel, server) = (field(&data, "channelId"), field(&data, "serverId"));
            info!("CALL_INITIATE_SERVER de {} channel={} serveur={}", c.user_id, js_string(Some(channel)), js_string(Some(server)));
            if !val_is_id(channel) || !val_is_id(server) {
                reply(&mut ack, json!({ "error": "channelId et serverId requis" }));
                return Ok(());
            }
            let (channel_id, server_id) = (channel.as_str().unwrap().to_string(), server.as_str().unwrap().to_string());
            if !check_server_permission(app, &c.user_id, &server_id, READ).await {
                reply(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
                return Ok(());
            }
            // Le salon doit appartenir à CE serveur
            if !node_owns_channel(&c, &server_id, &channel_id).await {
                reply(&mut ack, json!({ "error": "CHANNEL_NOT_IN_SERVER" }));
                return Ok(());
            }
            // Droit de connexion dans CE salon, et limite d'utilisateurs du salon
            if !check_channel_permission(app, &c.user_id, &server_id, &channel_id, CONNECT).await {
                reply(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
                return Ok(());
            }
            let meta = get_channel_meta(app, &server_id, &channel_id).await;
            if let Some(limit) = meta.as_ref().map(|m| m.user_limit).filter(|l| *l > 0) {
                let (present, has_me) = {
                    let v = app.conns.voice.lock();
                    let ch = v.channels.get(&channel_id);
                    (ch.map(|m| m.len()), ch.map(|m| m.contains_key(&c.user_id)).unwrap_or(false))
                };
                if let Some(n) = present {
                    if !has_me && n as i64 >= limit && !check_server_permission(app, &c.user_id, &server_id, MOVE_MEMBERS).await {
                        reply(&mut ack, json!({ "error": "CHANNEL_FULL", "userLimit": limit }));
                        return Ok(());
                    }
                }
            }
            let ctype = call_type(&data);

            // Limite de participants du serveur (appel déjà actif sur ce salon)
            let limit = app.svc.calls_get_server_limit(&server_id).await;
            let limit_n = crate::perms::js_number(&limit);
            if let Ok(Some(active)) = app.redis.get(&format!("call:channel:active:{channel_id}")).await {
                let (n, _) = call_room(&c, &active).await;
                if (n as f64) >= limit_n {
                    reply(&mut ack, json!({ "error": "CALL_FULL", "maxParticipants": limit }));
                    return Ok(());
                }
            }

            let call_id: String;
            match app.svc.calls_create_server(json!({ "channelId": channel_id, "serverId": server_id, "initiatorId": c.user_id, "type": ctype }), &c.user_id).await {
                Ok(call) => call_id = js_string(call.get("id")),
                Err(e) => {
                    // 409 : un appel est déjà ouvert sur ce salon
                    let existing = if e.status == Some(409) { existing_call_id_of(&e.message) } else { None };
                    let Some(existing) = existing else { return Err(e.message) };
                    let (live, _) = call_room(&c, &existing).await;
                    if live > 0 {
                        // Des membres y sont : le client le rejoint (CALL_JOIN, producteurs existants compris).
                        reply(&mut ack, json!({ "existingCallId": existing }));
                        return Ok(());
                    }
                    // Appel fantôme (onglet fermé, passerelle redémarrée) : repris à neuf.
                    let _ = app.svc.calls_join(&existing, &c.user_id).await;
                    let _ = app.svc.sfu_destroy_room(&existing).await;
                    call_id = existing;
                }
            }
            let _ = c.socket.join(format!("call:{call_id}"));
            let _ = app.redis.set(&format!("call:channel:active:{channel_id}"), &call_id, Some(4 * 3600)).await;
            if let Err(e) = app.svc.sfu_create_room(&call_id, "server").await {
                error!("Impossible de créer la salle SFU pour appel serveur: {}", e.message);
            }
            // Pas de CALL_INCOMING : rejoindre un vocal de serveur ne sonne chez personne.
            reply(&mut ack, json!({ "callId": call_id, "id": call_id }));
            Ok(())
        }
        .await;
        if let Err(m) = r {
            c.emit_error("CALL_ERROR", &m);
            reply(&mut ack, json!({ "error": "Impossible de créer l'appel serveur" }));
        }
    });

    register_sfu(c);
}

/// Le salon appartient-il bien à ce serveur ? La liste vient du node (sinon du service servers),
/// avec un cache Redis court : un salon créé devient diffusable en moins d'une minute.
pub async fn node_owns_channel(c: &SockCtx, server_id: &str, channel_id: &str) -> bool {
    node_owns_channel_app(&c.app, server_id, channel_id).await
}

pub async fn node_owns_channel_app(app: &Arc<crate::state::AppState>, server_id: &str, channel_id: &str) -> bool {
    if !is_id(server_id) || !is_id(channel_id) {
        return false;
    }
    let key = format!("nodechans:{server_id}");
    if let Ok(Some(cached)) = app.redis.get(&key).await {
        if let Ok(Value::Array(ids)) = serde_json::from_str::<Value>(&cached) {
            if ids.iter().any(|i| i.as_str() == Some(channel_id)) {
                return true;
            }
        }
    }
    let ids: Vec<String> = match crate::nodes::forward_to_node(app, server_id, "CHANNEL_LIST", &json!({}), 5_000).await {
        Ok(r) => r.get("channels").and_then(|c| c.as_array()).map(|a| a.iter().filter_map(|c| c.get("id").and_then(|i| i.as_str()).map(str::to_string)).collect()).unwrap_or_default(),
        Err(_) => match app.svc.servers_get_channels(server_id, None).await {
            Ok(v) => v.as_array().map(|a| a.iter().filter_map(|c| c.get("id").filter(|v| !v.is_null()).or_else(|| c.get("channelId")).and_then(|i| i.as_str()).map(str::to_string)).collect()).unwrap_or_default(),
            // Impossible de vérifier → refuser plutôt que de relayer à l'aveugle.
            Err(_) => return false,
        },
    };
    let _ = app.redis.set(&key, &serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()), Some(60)).await;
    ids.iter().any(|i| i == channel_id)
}

async fn is_user_in_call(c: &SockCtx, call_id: &str, target: &str) -> bool {
    {
        let g = c.call_members.lock();
        if let Some((ids, at)) = g.get(call_id) {
            if at.elapsed().as_secs() < 5 && ids.contains(target) {
                return true;
            }
        }
    }
    let (_, clients) = call_room(c, call_id).await;
    let ids: HashSet<String> = clients.into_iter().map(|cl| cl.user_id).filter(|u| !u.is_empty()).collect();
    let found = ids.contains(target);
    c.call_members.lock().insert(call_id.to_string(), (ids, Instant::now()));
    found
}

/// L'émetteur doit lui-même être dans la room de l'appel, et la cible aussi : sinon n'importe quel
/// compte injectait des offres SDP et des candidats ICE chez n'importe qui.
async fn relay_webrtc(c: &SockCtx, ev: &str, data: &Value, key: &str) {
    let call_id = field(data, "callId");
    if !val_is_id(call_id) {
        return;
    }
    let call_id = call_id.as_str().unwrap();
    if !c.in_room(&format!("call:{call_id}")) {
        warn!("{ev} refusé : {} n'est pas dans l'appel {call_id}", c.user_id);
        return;
    }
    let mut target = format!("call:{call_id}");
    if let Some(t) = data.get("targetUserId").filter(|t| !t.is_null()) {
        if !val_is_uuid(t) || !is_user_in_call(c, call_id, t.as_str().unwrap()).await {
            return;
        }
        target = format!("user:{}", t.as_str().unwrap());
    }
    let mut payload = serde_json::Map::new();
    payload.insert("callId".into(), json!(call_id));
    payload.insert("fromUserId".into(), json!(c.user_id));
    if let Some(v) = data.get(key) {
        payload.insert(key.into(), v.clone());
    }
    c.to_room(&target, ev, Value::Object(payload)).await;
}

async fn broadcast_mode_switch(c: &SockCtx, call_id: &str, new_mode: &str) {
    c.to_room(&format!("call:{call_id}"), "CALL_MODE_SWITCH", json!({ "callId": call_id, "newMode": new_mode })).await;
}

/// Diffusion d'un changement de qualité émis par le media-server (endpoint HTTP interne).
pub async fn broadcast_quality_update(app: &Arc<crate::state::AppState>, call_id: &str, tier: &Value, participant_count: &Value, tier_params: &Value) {
    let ev = "CALL_QUALITY_UPDATE";
    let _ = app
        .io()
        .to(format!("call:{call_id}"))
        .emit(ev, &event(ev, json!({ "callId": call_id, "tier": tier, "participantCount": participant_count, "tierParams": tier_params })))
        .await;
}

// ── Relais SFU (mediasoup) ──────────────────────────────────────────────────

/// Le socket doit avoir rejoint l'appel : connaître un callId ne suffit pas à consommer l'audio/vidéo.
fn in_call(c: &SockCtx, call_id: &Value) -> Option<String> {
    let id = call_id.as_str().filter(|s| is_id(s))?;
    c.in_room(&format!("call:{id}")).then(|| id.to_string())
}

fn deny(ack: &mut Ack) {
    reply(ack, json!({ "error": "NOT_IN_CALL" }));
}

fn sfu_err(c: &SockCtx, message: &str) {
    // Les messages « media-server … » (corps bruts) ne sortent jamais tels quels.
    c.emit_error("SFU_ERROR", message);
}

fn register_sfu(c: &Arc<SockCtx>) {
    on(c, "SFU_GET_RTP_CAPABILITIES", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        match c.app.svc.sfu_get_rtp_capabilities(&call_id).await {
            Ok(r) => reply(&mut ack, r),
            Err(e) => {
                sfu_err(&c, &e.message);
                reply(&mut ack, json!({ "error": "Impossible de récupérer les capabilities" }));
            }
        }
    });

    on(c, "SFU_CREATE_TRANSPORT", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        match c.app.svc.sfu_create_transport(&call_id, &c.user_id, &js_string(data.get("direction"))).await {
            Ok(mut r) => {
                if ack.present {
                    reply(&mut ack, r);
                } else {
                    if let Value::Object(m) = &mut r {
                        m.insert("callId".into(), json!(call_id));
                    }
                    let _ = c.socket.emit("SFU_TRANSPORT_CREATED", &r);
                }
            }
            Err(e) => {
                sfu_err(&c, &e.message);
                reply(&mut ack, json!({ "error": "Erreur création transport" }));
            }
        }
    });

    on(c, "SFU_CONNECT_TRANSPORT", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        let dtls = data.get("dtlsParameters").cloned().unwrap_or(Value::Null);
        match c.app.svc.sfu_connect_transport(&call_id, &js_string(data.get("transportId")), &dtls, &c.user_id).await {
            Ok(_) => reply(&mut ack, json!({ "success": true })),
            Err(e) => {
                sfu_err(&c, &e.message);
                reply(&mut ack, json!({ "error": "Erreur connexion transport" }));
            }
        }
    });

    on(c, "SFU_PRODUCE", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        let kind = field(&data, "kind").as_str().filter(|k| *k == "audio" || *k == "video");
        let Some(kind) = kind else { return deny(&mut ack) };
        let rtp = data.get("rtpParameters").cloned().unwrap_or(Value::Null);
        match c.app.svc.sfu_produce(&call_id, &js_string(data.get("transportId")), kind, &rtp, &c.user_id, data.get("appData")).await {
            Ok(mut result) => {
                if ack.present {
                    reply(&mut ack, result.clone());
                } else {
                    if let Value::Object(m) = &mut result {
                        m.insert("callId".into(), json!(call_id));
                    }
                    let _ = c.socket.emit("SFU_PRODUCED", &result);
                }
                // Les autres participants savent qu'un nouveau producer est disponible
                c.to_room_others(
                    &format!("call:{call_id}"),
                    "SFU_NEW_PRODUCER",
                    json!({ "callId": call_id, "producerId": result.get("producerId"), "userId": c.user_id, "kind": kind }),
                )
                .await;
            }
            Err(e) => {
                sfu_err(&c, &e.message);
                reply(&mut ack, json!({ "error": "Erreur création producer" }));
            }
        }
    });

    on(c, "SFU_CLOSE_PRODUCER", |c, data, _| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return };
        // Le media-server vérifie que ce producer appartient bien à `userId`.
        match c.app.svc.sfu_close_producer(&call_id, &js_string(data.get("producerId")), &c.user_id).await {
            Ok(_) => {
                c.to_room_others(&format!("call:{call_id}"), "SFU_PRODUCER_CLOSED", json!({ "callId": call_id, "producerId": data.get("producerId"), "userId": c.user_id })).await;
            }
            Err(e) => sfu_err(&c, &e.message),
        }
    });

    on(c, "SFU_CONSUME", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        let caps = data.get("rtpCapabilities").cloned().unwrap_or(Value::Null);
        match c.app.svc.sfu_consume(&call_id, &js_string(data.get("recvTransportId")), &js_string(data.get("producerId")), &caps, &c.user_id).await {
            Ok(mut result) => {
                if ack.present {
                    reply(&mut ack, result);
                } else {
                    if let Value::Object(m) = &mut result {
                        m.insert("callId".into(), json!(call_id));
                    }
                    let _ = c.socket.emit("SFU_CONSUMED", &result);
                }
            }
            Err(e) => {
                sfu_err(&c, &e.message);
                reply(&mut ack, json!({ "error": "Erreur création consumer" }));
            }
        }
    });

    on(c, "SFU_RESUME_CONSUMER", |c, data, mut ack| async move {
        let Some(call_id) = in_call(&c, field(&data, "callId")) else { return deny(&mut ack) };
        match c.app.svc.sfu_resume_consumer(&call_id, &js_string(data.get("consumerId")), &c.user_id).await {
            Ok(_) => reply(&mut ack, json!({ "success": true })),
            Err(e) => sfu_err(&c, &e.message),
        }
    });

    // Lever / baisser la main (appels serveur)
    for (ev, out) in [("CALL_RAISE_HAND", "CALL_HAND_RAISED"), ("CALL_LOWER_HAND", "CALL_HAND_LOWERED")] {
        on(c, ev, move |c, data, _| async move {
            let Some(call_id) = in_call(&c, field(&data, "callId")) else { return };
            c.to_room_others(&format!("call:{call_id}"), out, json!({ "callId": call_id, "userId": c.user_id })).await;
        });
    }
}
