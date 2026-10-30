//! Serveurs communautaires : adhésion, messages de salon, salons, permissions, rôles, membres, invitations.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use tracing::{info, warn};

use super::calls::node_owns_channel;
use super::helpers::*;
use super::messages::HErr;
use super::{ch_room, on, Ack, SockCtx};
use crate::http::routes_misc::{is_id, is_uuid, js_string, truthy};
use crate::nodes::forward_to_node;
use crate::perms::{self, ADMIN, ALL_PERMS_MASK, ATTACH_FILES, BAN_ANY, CREATE_INVITE, KICK_ANY, MANAGE_CHANNELS, MANAGE_MESSAGES, MANAGE_NICKNAMES, MANAGE_ROLES, MANAGE_SERVER, CHANGE_NICKNAME, REACT, READ, SEND};
use crate::state::event;
use crate::svc::obj;
use crate::validation::{field, validate_channel_input, validate_channel_reorder, validate_invite_input, validate_member_update, validate_message_content, validate_role_input, validate_server_input, validate_tags};

/// `data[k]` en chaîne ; `""` si absent ou null (équivalent d'un `serverId` indéfini pour les contrôles).
fn s(data: &Value, k: &str) -> String {
    match data.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(Some(v)),
    }
}

/// `a || b || …` : première valeur « truthy » (JavaScript), sinon `null`.
fn first_truthy(vals: &[Option<&Value>]) -> Value {
    vals.iter().flatten().find(|v| truthy(Some(v))).map(|v| (*v).clone()).unwrap_or(Value::Null)
}

fn respond(ack: &mut Ack, v: Value) {
    ack.send(&v);
}

fn some(v: Option<&Value>) -> Option<Value> {
    v.cloned()
}

fn payload(fields: Vec<(&str, Option<Value>)>) -> Value {
    obj(fields)
}

/// Résultat d'un forward vers le node : on distingue l'absence de node / le délai des autres erreurs.
fn is_no_node(e: &str) -> bool {
    e == "NO_NODE"
}
fn is_no_node_or_timeout(e: &str) -> bool {
    e == "NO_NODE" || e == "NODE_TIMEOUT"
}

fn err_msg(e: crate::svc::SvcErr) -> String {
    e.message
}

pub fn register(c: &Arc<SockCtx>) {
    on(c, "SERVER_JOIN", server_join);
    on(c, "SERVER_SELF_JOIN", server_self_join);
    on(c, "SERVER_LEAVE", server_leave);
    on(c, "SERVER_MESSAGE_SEND", server_message_send);
    on(c, "SERVER_MESSAGE_EDIT", server_message_edit);
    on(c, "SERVER_MESSAGE_DELETE", server_message_delete);

    for (ev, add) in [("SERVER_REACTION_ADD", true), ("SERVER_REACTION_REMOVE", false)] {
        on(c, ev, move |c, data, _| async move {
            let r: Result<(), HErr> = async {
                let (sid, cid, mid, emoji) = (field(&data, "serverId"), field(&data, "channelId"), field(&data, "messageId"), field(&data, "emoji"));
                let valid_emoji = emoji.as_str().map(|e| !e.is_empty() && e.encode_utf16().count() <= 50).unwrap_or(false);
                if !val_is_id(sid) || !val_is_id(cid) || !val_is_id(mid) || !valid_emoji || !node_owns_channel(&c, sid.as_str().unwrap(), cid.as_str().unwrap()).await {
                    return Err("INVALID_PAYLOAD".into());
                }
                let (sid, cid, mid, emoji) = (sid.as_str().unwrap(), cid.as_str().unwrap(), mid.as_str().unwrap(), emoji.as_str().unwrap());
                let need = if add { READ | REACT } else { READ };
                if !check_channel_permission(&c.app, &c.user_id, sid, cid, need).await {
                    return Err("PERMISSION_DENIED".into());
                }
                if add {
                    c.app.svc.servers_add_reaction(sid, mid, &c.user_id, emoji).await?;
                } else {
                    c.app.svc.servers_remove_reaction(sid, mid, &c.user_id, emoji).await?;
                }
                // Cet événement n'a pas de `timestamp` dans l'original.
                let body = json!({ "type": "SERVER_REACTION_UPDATE", "payload": { "messageId": mid, "userId": c.user_id, "emoji": emoji, "action": if add { "add" } else { "remove" } } });
                c.raw_to_room(&ch_room(sid, cid), "SERVER_REACTION_UPDATE", &body).await;
                Ok(())
            }
            .await;
            if let Err(HErr(m)) = r {
                c.emit_error("REACTION_ERROR", &m);
            }
        });
    }

    on(c, "SERVER_MESSAGE_HISTORY", server_message_history);
    on(c, "SERVER_GET_CHANNELS", server_get_channels);
    on(c, "CHANNEL_CREATE", channel_create);
    on(c, "CHANNEL_UPDATE", channel_update);
    on(c, "CHANNEL_DELETE", channel_delete);
    on(c, "CHANNEL_PERMS_GET", channel_perms_get);
    on(c, "CHANNEL_PERMS_DELETE", channel_perms_delete);
    on(c, "CHANNEL_PERMS_SYNC", channel_perms_sync);
    on(c, "CHANNEL_REORDER", channel_reorder);
    on(c, "CHANNEL_PERMS_SET", channel_perms_set);
    on(c, "ROLE_LIST", role_list);
    on(c, "ROLE_CREATE", role_create);
    on(c, "ROLE_UPDATE", role_update);
    on(c, "ROLE_DELETE", role_delete);
    on(c, "MY_PERMISSIONS", my_permissions);
    on(c, "ROLE_REORDER", role_reorder);
    on(c, "GET_BULK_PRESENCE", get_bulk_presence);
    on(c, "GET_VOICE_STATE", get_voice_state);
    on(c, "MEMBER_LIST", member_list);
    on(c, "MEMBER_UPDATE", member_update);
    on(c, "MEMBER_KICK", member_kick);
    on(c, "MEMBER_BAN", member_ban);
    on(c, "SERVER_INFO", server_info);
    on(c, "SERVER_OWNER_JOINED", server_owner_joined);
    on(c, "SERVER_UPDATE_NODE", server_update_node);
    on(c, "INVITE_LIST", invite_list);
    on(c, "INVITE_DELETE", invite_delete);
    on(c, "INVITE_CREATE", invite_create);
    on(c, "INVITE_VERIFY", invite_verify);

    for (ev, _) in [("SERVER_TYPING_START", true), ("SERVER_TYPING_STOP", false)] {
        on(c, ev, move |c, data, _| async move {
            let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
            if !val_is_id(sid) || !val_is_id(cid) {
                return;
            }
            let (sid, cid) = (sid.as_str().unwrap(), cid.as_str().unwrap());
            if !c.in_room(&ch_room(sid, cid)) {
                return;
            }
            c.to_room_others(&ch_room(sid, cid), ev, json!({ "userId": c.user_id, "channelId": cid, "serverId": sid })).await;
        });
    }
}

// ── Adhésion ────────────────────────────────────────────────────────────────

fn user_member(c: &SockCtx) -> Value {
    json!({ "userId": c.user_id, "username": c.username(), "displayName": c.display_name(), "avatarUrl": c.avatar() })
}

async fn server_join(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        if !app.ws_limits.check_server_join_rate(&c.user_id) {
            // Objet jeté (et non une `Error`) dans l'original : le message est générique.
            c.emit_error("RATE_LIMITED", super::GENERIC_ERROR);
            return Ok(());
        }
        let sid = field(&data, "serverId");
        let invite = data.get("inviteCode");
        if !val_is_id(sid) || invite.map(|i| !i.is_null() && !val_is_id(i)).unwrap_or(false) {
            return Err("INVALID_PAYLOAD".into());
        }
        let server_id = sid.as_str().unwrap().to_string();

        // Serveur privé ? Exiger un code d'invitation valide (un membre peut re-join librement).
        let check: Result<(), String> = async {
            let already = app.svc.servers_is_member(&server_id, &c.user_id).await.map_err(err_msg)?;
            if already {
                return Ok(());
            }
            let server = app.svc.servers_get_server(&server_id).await.map_err(err_msg)?;
            let is_public = [server.get("isPublic"), server.get("is_public")].into_iter().flatten().find(|v| !v.is_null()).map(|v| truthy(Some(v))).unwrap_or(false);
            if is_public {
                return Ok(());
            }
            let Some(code) = invite.filter(|i| truthy(Some(i))).and_then(|i| i.as_str()) else { return Err("INVITE_REQUIRED".into()) };
            let ok = match forward_to_node(&app, &server_id, "INVITE_VERIFY", &json!({ "code": code }), 15_000).await {
                Ok(r) => truthy(Some(&r)) && r.get("valid") != Some(&Value::Bool(false)) && !truthy(r.get("error")),
                Err(_) => match app.svc.servers_resolve_invite(code).await {
                    Ok(inv) => [inv.get("serverId"), inv.get("server_id")].into_iter().flatten().any(|v| v.as_str() == Some(server_id.as_str())),
                    Err(_) => false,
                },
            };
            if ok {
                Ok(())
            } else {
                Err("INVALID_INVITE".into())
            }
        }
        .await;
        match check {
            Ok(()) => {}
            Err(m) if m == "INVITE_REQUIRED" || m == "INVALID_INVITE" => return Err(HErr(m)),
            // Si le contrôle d'accès échoue techniquement, refuser par défaut.
            Err(_) => return Err("JOIN_CHECK_FAILED".into()),
        }

        // Toujours enregistrer dans le microservice (annuaire central), code d'invitation inclus.
        let member = app.svc.servers_join(&server_id, &c.user_id, invite.and_then(|i| i.as_str())).await?;
        invalidate_server_perms(&app, &server_id, Some(&c.user_id)).await;
        let _ = c.socket.join(format!("server:{server_id}"));

        // Si un node est connecté, lui notifier le join pour sa DB locale
        let node_res: Result<(), String> = async {
            forward_to_node(&app, &server_id, "MEMBER_JOIN", &user_member(&c), 15_000).await?;
            let ch = forward_to_node(&app, &server_id, "CHANNEL_LIST", &json!({ "userId": c.user_id }), 15_000).await?;
            let mut default_channel: Option<String> = None;
            if let Some(list) = ch.get("channels").and_then(|c| c.as_array()) {
                for chn in list {
                    let Some(id) = chn.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)) else { continue };
                    let _ = c.socket.join(ch_room(&server_id, id));
                    // Premier salon textuel = salon par défaut pour le message système
                    let t = chn.get("type").and_then(|t| t.as_str());
                    if default_channel.is_none() && (t == Some("text") || t == Some("announcement")) {
                        default_channel = Some(id.to_string());
                    }
                }
            }
            if let Some(dc) = default_channel {
                let _ = forward_to_node(
                    &app,
                    &server_id,
                    "MSG_FORWARD",
                    &json!({
                        "channelId": dc, "serverId": server_id, "content": format!("📥 **{}** a rejoint le serveur.", c.display_name()),
                        "senderId": c.user_id, "sender": user_member_sender(&c), "isSystem": true,
                    }),
                    15_000,
                )
                .await;
            }
            Ok(())
        }
        .await;
        if node_res.is_err() {
            // Pas de node → salons visibles depuis le microservice
            if let Ok(chs) = app.svc.servers_get_channels(&server_id, Some(&c.user_id)).await {
                for chn in chs.as_array().into_iter().flatten() {
                    if let Some(id) = chn.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)) {
                        let _ = c.socket.join(ch_room(&server_id, id));
                    }
                }
            }
            c.to_room(&format!("server:{server_id}"), "MEMBER_JOIN", json!({ "serverId": server_id, "member": member })).await;
        }

        // Tous les sockets de l'utilisateur (onglets, appareils) → mise à jour de la liste des serveurs
        if let Ok(info) = app.svc.servers_get_server(&server_id).await {
            let pick = |a: &str, b: &str| [info.get(a), info.get(b)].into_iter().flatten().find(|v| !v.is_null()).cloned();
            let ev = "SERVER_JOINED";
            let p = payload(vec![
                ("id", Some(json!(server_id))),
                ("name", Some(info.get("name").filter(|v| !v.is_null()).cloned().unwrap_or(json!("")))),
                ("iconUrl", pick("iconUrl", "icon_url")),
                ("ownerId", pick("ownerId", "owner_id")),
            ]);
            let _ = app.io().to(format!("user:{}", c.user_id)).emit(ev, &event(ev, p)).await;
        }
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_ERROR", &m);
    }
}

fn user_member_sender(c: &SockCtx) -> Value {
    json!({ "id": c.user_id, "username": c.username(), "displayName": c.display_name(), "avatarUrl": c.avatar() })
}

/// Émis par le client APRÈS un join HTTP : vérifie l'adhésion, rejoint les rooms, informe tous les onglets.
async fn server_self_join(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let sid = field(&data, "serverId");
        if !val_is_id(sid) {
            return Ok(());
        }
        let server_id = sid.as_str().unwrap().to_string();
        if !app.ws_limits.check_server_join_rate(&c.user_id) {
            c.emit_error("RATE_LIMITED", super::GENERIC_ERROR);
            return Ok(());
        }
        let record = app.svc.servers_get_member_record(&server_id, &c.user_id).await.ok();
        let is_member = record.as_ref().and_then(|r| r.get("isMember")).map(|v| truthy(Some(v))).unwrap_or(false);
        let Some(record) = record.filter(|_| is_member) else {
            let _ = c.socket.emit("SERVER_ERROR", &json!({ "type": "SERVER_ERROR", "error": "NOT_A_MEMBER", "serverId": server_id }));
            return Ok(());
        };
        invalidate_server_perms(&app, &server_id, Some(&c.user_id)).await;

        // Rejoindre les rooms (si pas déjà dedans), sur tous les onglets
        let _ = app.io().within(format!("user:{}", c.user_id)).join(format!("server:{server_id}")).await;
        let mut joined: Vec<String> = vec![];
        match forward_to_node(&app, &server_id, "CHANNEL_LIST", &json!({ "userId": c.user_id }), 15_000).await {
            Ok(r) => {
                for chn in r.get("channels").and_then(|c| c.as_array()).into_iter().flatten() {
                    if let Some(id) = chn.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)) {
                        joined.push(id.to_string());
                    }
                }
            }
            Err(_) => {
                if let Ok(chs) = app.svc.servers_get_channels(&server_id, Some(&c.user_id)).await {
                    for chn in chs.as_array().into_iter().flatten() {
                        if let Some(id) = chn.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)) {
                            joined.push(id.to_string());
                        }
                    }
                }
            }
        }
        for id in &joined {
            let _ = app.io().within(format!("user:{}", c.user_id)).join(ch_room(&server_id, id)).await;
        }

        // Cache des rooms (reconnexion)
        if let Ok(Some(cached)) = app.redis.get_user_rooms(&c.user_id).await {
            if !cached.server_ids.contains(&server_id) {
                let mut sids = cached.server_ids.clone();
                sids.push(server_id.clone());
                let mut cids = cached.channel_ids.clone();
                cids.extend(joined.iter().map(|id| format!("{server_id}:{id}")));
                let _ = app.redis.save_user_rooms(&c.user_id, &sids, &cids).await;
            }
        }

        // Nouveau membre (arrivé il y a moins de 2 min) : la liste des membres se met à jour chez tout le monde.
        let joined_ms = record.get("joinedAt").and_then(|j| j.as_str()).and_then(|j| chrono::DateTime::parse_from_rfc3339(j).ok()).map(|d| d.timestamp_millis());
        if let Some(ms) = joined_ms {
            if crate::redis_client::now_ms() - ms < 120_000 && !app.has_node(&server_id) {
                c.to_room(
                    &format!("server:{server_id}"),
                    "MEMBER_JOIN",
                    json!({
                        "serverId": server_id,
                        "member": {
                            "userId": c.user_id, "username": c.username(), "displayName": c.display_name(), "avatarUrl": c.avatar(),
                            "nickname": record.get("nickname").cloned().unwrap_or(Value::Null),
                            "roleIds": record.get("roleIds").filter(|v| !v.is_null()).cloned().unwrap_or(json!([])),
                            "joinedAt": record.get("joinedAt"), "status": "online",
                        },
                    }),
                )
                .await;
            }
        }

        let info = app.svc.servers_get_server(&server_id).await.ok();
        let pick = |a: &str, b: &str| info.as_ref().and_then(|i| [i.get(a), i.get(b)].into_iter().flatten().find(|v| !v.is_null()).cloned());
        let ev = "SERVER_JOINED";
        let body = json!({
            "type": "SERVER_ADDED",
            "payload": payload(vec![
                ("id", Some(json!(server_id))),
                ("name", Some(info.as_ref().and_then(|i| i.get("name")).filter(|v| !v.is_null()).cloned().or_else(|| data.get("name").filter(|v| !v.is_null()).cloned()).unwrap_or(json!("")))),
                ("iconUrl", pick("iconUrl", "icon_url").or_else(|| data.get("iconUrl").filter(|v| !v.is_null()).cloned())),
                ("ownerId", pick("ownerId", "owner_id")),
            ]),
            "timestamp": crate::iso::to_string(&chrono::Utc::now()),
        });
        let _ = app.io().to(format!("user:{}", c.user_id)).emit(ev, &body).await;
        info!("{} self-joined server {server_id} via HTTP → socket rooms updated", c.username());
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_ERROR", &m);
    }
}

async fn server_leave(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        if !app.ws_limits.check_server_join_rate(&c.user_id) {
            c.emit_error("RATE_LIMITED", super::GENERIC_ERROR);
            return Ok(());
        }
        let sid = field(&data, "serverId");
        if !val_is_id(sid) {
            return Ok(());
        }
        let server_id = sid.as_str().unwrap().to_string();
        app.svc.servers_leave(&server_id, &c.user_id).await?;
        invalidate_server_perms(&app, &server_id, Some(&c.user_id)).await;
        // Quitter le serveur ET ses salons, sur tous les appareils.
        let user_room = format!("user:{}", c.user_id);
        let _ = app.io().within(user_room.clone()).leave(format!("server:{server_id}")).await;
        let prefix = format!("ch:{server_id}:");
        for sock in app.io().within(user_room).fetch_sockets().await.unwrap_or_default() {
            for room in sock.rooms().await.unwrap_or_default() {
                if room.starts_with(&prefix) {
                    let _ = sock.leave(room.to_string()).await;
                }
            }
        }
        // Notifier le node si connecté (nouvel essai à 500 ms) — self-leave : actorId = userId
        let body = json!({ "userId": c.user_id, "actorId": c.user_id, "selfLeave": true });
        match forward_to_node(&app, &server_id, "MEMBER_KICK", &body, 15_000).await {
            Ok(_) => info!("Member {} removed from node for server {server_id}", c.user_id),
            Err(e) => {
                warn!("Failed to remove member {} from node for server {server_id}: {e}", c.user_id);
                let (a, sid, b) = (app.clone(), server_id.clone(), body.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    match forward_to_node(&a, &sid, "MEMBER_KICK", &b, 15_000).await {
                        Ok(_) => info!("Retry: member removed from node for server {sid}"),
                        Err(_) => warn!("Retry failed: member still in node for server {sid}"),
                    }
                });
            }
        }
        c.to_room(&format!("server:{server_id}"), "MEMBER_LEAVE", json!({ "serverId": server_id, "userId": c.user_id })).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_ERROR", &m);
    }
}

// ── Messages de salon ───────────────────────────────────────────────────────

async fn server_message_send(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
        let reply_to = Some(field(&data, "replyToId")).filter(|r| val_is_uuid(r)).cloned();
        if !val_is_id(sid) || !val_is_id(cid) {
            return Err("INVALID_PAYLOAD".into());
        }
        let (server_id, channel_id) = (sid.as_str().unwrap().to_string(), cid.as_str().unwrap().to_string());
        // La room est namespacée par serveur et n'est rejointe qu'après validation de l'appartenance.
        if !c.in_room(&ch_room(&server_id, &channel_id)) {
            // Repli : membership réelle ET salon appartenant bien à CE serveur.
            let is_member = app.svc.servers_is_member(&server_id, &c.user_id).await.unwrap_or(false);
            if !is_member || !node_owns_channel(&c, &server_id, &channel_id).await {
                return Err("NOT_A_CHANNEL_MEMBER".into());
            }
            let _ = c.socket.join(format!("server:{server_id}"));
            let _ = c.socket.join(ch_room(&server_id, &channel_id));
        }
        // READ + SEND dans CE salon (surcharges incluses) — inclut l'appartenance
        if !check_channel_permission(&app, &c.user_id, &server_id, &channel_id, READ | SEND).await {
            return Err("PERMISSION_DENIED".into());
        }
        if field(&data, "attachments").as_array().map(|a| !a.is_empty()).unwrap_or(false)
            && !check_channel_permission(&app, &c.user_id, &server_id, &channel_id, ATTACH_FILES).await
        {
            return Err("ATTACH_DENIED".into());
        }
        // Mode lent : un message par fenêtre, sauf pour qui gère le salon.
        if let Some(meta) = get_channel_meta(&app, &server_id, &channel_id).await.filter(|m| m.slow_mode > 0) {
            let exempt = check_channel_permission(&app, &c.user_id, &server_id, &channel_id, MANAGE_MESSAGES).await
                || check_channel_permission(&app, &c.user_id, &server_id, &channel_id, MANAGE_CHANNELS).await;
            if !exempt {
                let key = format!("slow:{channel_id}:{}", c.user_id);
                let until: i64 = app.redis.get(&key).await.ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
                let now = crate::redis_client::now_ms();
                if until > now {
                    let _ = c.socket.emit("SERVER_MESSAGE_ERROR", &json!({ "error": "SLOWMODE", "retryAfter": ((until - now) as f64 / 1000.0).ceil() as i64, "channelId": channel_id }));
                    return Ok(());
                }
                let _ = app.redis.set(&key, &(now + meta.slow_mode * 1000).to_string(), Some(meta.slow_mode as u64)).await;
            }
        }
        // Mute global (modération plateforme) — prime sur les permissions du serveur
        if let Some(mute) = get_active_mute(&app, &c.user_id).await {
            let _ = c.socket.emit("SERVER_MESSAGE_ERROR", &json!({ "error": "MUTED", "message": mute_message(&mute) }));
            return Ok(());
        }
        let v = validate_message_content(field(&data, "content"), field(&data, "attachments"), field(&data, "e2eeType"))?;
        let tags = validate_tags(field(&data, "tags"))?;
        let content = v.content;
        let attachments = v.attachments;

        // Règle du type de salon (lecture seule, médias seuls, liens seuls…), sauf pour la modération.
        if let Some(rule) = get_channel_meta(&app, &server_id, &channel_id).await.and_then(|m| crate::channel_kinds::rule_of(&m.kind)) {
            let has_files = attachments.as_ref().map(|a| !a.is_empty()).unwrap_or(false);
            if !rule.allows(&content, has_files) && !check_channel_permission(&app, &c.user_id, &server_id, &channel_id, MANAGE_MESSAGES).await {
                let _ = c.socket.emit(
                    "SERVER_MESSAGE_ERROR",
                    &json!({ "error": "CHANNEL_RULE", "rule": rule.code(), "message": rule.message(), "channelId": channel_id }),
                );
                return Ok(());
            }
        }

        // AutoMod : appliqué à tous sauf aux modérateurs
        if !content.is_empty() && !app.has_node(&server_id) {
            let exempt = check_server_permission_any(&app, &c.user_id, &server_id, MANAGE_MESSAGES | MANAGE_SERVER).await;
            if !exempt {
                if let Ok(verdict) = app.svc.servers_automod_check(&server_id, &content, &c.user_id).await {
                    if truthy(verdict.get("blocked")) {
                        let _ = c.socket.emit("SERVER_MESSAGE_ERROR", &json!({ "error": "AUTOMOD_BLOCKED", "reason": verdict.get("reason"), "channelId": channel_id }));
                        return Ok(());
                    }
                }
            }
        }

        let tags_v = tags.map(|t| json!(t));
        let att_v = attachments.map(Value::Array);
        // Forward au server-node si connecté
        let fwd = payload(vec![
            ("channelId", Some(json!(channel_id))),
            ("serverId", Some(json!(server_id))),
            ("content", Some(json!(content))),
            ("attachments", att_v.clone()),
            ("replyToId", reply_to.clone()),
            ("tags", tags_v.clone()),
            ("senderId", Some(json!(c.user_id))),
            ("sender", Some(user_member_sender(&c))),
        ]);
        match forward_to_node(&app, &server_id, "MSG_FORWARD", &fwd, 15_000).await {
            // Le node diffuse via NODE_BROADCAST
            Ok(_) => return Ok(()),
            Err(e) if !is_no_node_or_timeout(&e) => return Err(HErr(e)),
            Err(_) => {}
        }

        // Repli : pas de node connecté → microservice servers
        let body = payload(vec![
            ("senderId", Some(json!(c.user_id))),
            ("content", Some(json!(content))),
            ("attachments", att_v),
            ("replyToId", reply_to),
            ("tags", tags_v),
        ]);
        let message = app.svc.servers_create_message(&server_id, &channel_id, body, &c.user_id).await?;
        c.to_room(&ch_room(&server_id, &channel_id), "SERVER_MESSAGE_NEW", message).await;

        // Mentions dans les messages serveur
        handle_server_mentions(&c, &data, &server_id, &channel_id).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_MESSAGE_ERROR", &m);
    }
}

const MAX_MENTIONS: usize = 20;

/// Notifie les utilisateurs mentionnés (en ligne : temps réel ; hors ligne : base + Redis, repris à la reconnexion).
async fn handle_server_mentions(c: &Arc<SockCtx>, data: &Value, server_id: &str, channel_id: &str) {
    let app = &c.app;
    // Identifiants valides, dédupliqués, plafonnés, limités aux membres du serveur.
    let mut candidates: Vec<String> = vec![];
    if let Some(list) = field(data, "mentionedUserIds").as_array() {
        for id in list.iter().filter(|v| val_is_uuid(v)).filter_map(|v| v.as_str()) {
            if id != c.user_id && !candidates.iter().any(|x| x == id) {
                candidates.push(id.to_string());
            }
        }
        candidates.truncate(MAX_MENTIONS);
    }
    if candidates.is_empty() {
        return;
    }
    let checks = futures::future::join_all(candidates.iter().map(|id| check_server_permission(app, id, server_id, READ))).await;
    let ids: Vec<&String> = candidates.iter().zip(checks).filter(|(_, ok)| *ok).map(|(id, _)| id).collect();
    if ids.is_empty() {
        return;
    }
    let conv_key = format!("channel:{channel_id}");
    let content = data.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let preview = String::from_utf16_lossy(&content.encode_utf16().take(80).collect::<Vec<_>>());
    let channel_name = data.get("channelName").filter(|v| !v.is_null()).cloned();
    let sender_name = c.display_name();
    for mid in ids {
        let payload = json!({
            "conversationKey": conv_key, "channelId": channel_id, "serverId": server_id, "senderId": c.user_id,
            "senderName": sender_name, "senderAvatar": c.avatar(), "channelName": channel_name.clone().unwrap_or(Value::Null),
            "preview": preview, "notificationType": "mention",
        });
        match app.redis.is_user_online(mid).await {
            Ok(true) => c.to_room(&format!("user:{mid}"), "MENTION_NOTIFY", payload).await,
            Ok(false) => {
                let _ = app.redis.add_pending_ping(mid, &conv_key, &sender_name).await;
                let _ = app.svc.messages_save_notification(mid, &conv_key, &sender_name, Some(&c.user_id), Some("mention"), channel_name.as_ref().and_then(|v| v.as_str())).await;
            }
            Err(_) => {}
        }
    }
}

async fn server_message_edit(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let v = validate_message_content(field(&data, "content"), &Value::Null, field(&data, "e2eeType"))?;
        let (sid, mid, cid) = (field(&data, "serverId"), field(&data, "messageId"), field(&data, "channelId"));
        let content = v.content;
        if !val_is_id(sid) || !val_is_id(mid) || !val_is_id(cid) || !node_owns_channel(&c, sid.as_str().unwrap(), cid.as_str().unwrap()).await {
            return Err("INVALID_PAYLOAD".into());
        }
        let (sid, mid, cid) = (sid.as_str().unwrap(), mid.as_str().unwrap(), cid.as_str().unwrap());
        // L'auteur est vérifié par le node / le microservice (l'appel porte x-user-id).
        if !check_server_permission(&app, &c.user_id, sid, SEND).await {
            return Err("PERMISSION_DENIED".into());
        }
        match forward_to_node(&app, sid, "MSG_EDIT", &json!({ "messageId": mid, "content": content, "channelId": cid, "userId": c.user_id }), 15_000).await {
            Ok(_) => return Ok(()),
            Err(e) if !is_no_node_or_timeout(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        app.svc.servers_edit_message(sid, mid, &content, &c.user_id).await?;
        c.to_room(&ch_room(sid, cid), "SERVER_MESSAGE_EDITED", json!({ "messageId": mid, "content": content, "serverId": sid, "channelId": cid, "editedBy": c.user_id })).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_MESSAGE_ERROR", &m);
    }
}

async fn server_message_delete(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let (sid, mid, cid) = (field(&data, "serverId"), field(&data, "messageId"), field(&data, "channelId"));
        if !val_is_id(sid) || !val_is_id(mid) || !val_is_id(cid) || !node_owns_channel(&c, sid.as_str().unwrap(), cid.as_str().unwrap()).await {
            return Err("INVALID_PAYLOAD".into());
        }
        let (sid, mid, cid) = (sid.as_str().unwrap(), mid.as_str().unwrap(), cid.as_str().unwrap());
        // Au minimum l'appartenance ; l'auteur / MANAGE_MESSAGES est vérifié par le node / le microservice.
        if !check_server_permission(&app, &c.user_id, sid, READ).await {
            return Err("PERMISSION_DENIED".into());
        }
        match forward_to_node(&app, sid, "MSG_DELETE", &json!({ "messageId": mid, "channelId": cid, "userId": c.user_id }), 15_000).await {
            Ok(_) => return Ok(()),
            Err(e) if !is_no_node_or_timeout(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        app.svc.servers_delete_message(sid, mid, &c.user_id).await?;
        c.to_room(&ch_room(sid, cid), "SERVER_MESSAGE_DELETED", json!({ "messageId": mid, "serverId": sid, "channelId": cid, "deletedBy": c.user_id })).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_MESSAGE_ERROR", &m);
    }
}

async fn server_message_history(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
    let limit = {
        let n = perms::js_number(field(&data, "limit"));
        let n = if n.is_finite() && n != 0.0 { n } else { 50.0 };
        n.clamp(1.0, 100.0)
    };
    if !val_is_id(sid) || !val_is_id(cid) {
        return respond(&mut ack, json!({ "messages": [], "error": "INVALID_PAYLOAD" }));
    }
    let (sid, cid) = (sid.as_str().unwrap(), cid.as_str().unwrap());
    // READ évalué DANS le salon : un salon privé n'est pas lisible par @everyone.
    if !check_channel_permission(&app, &c.user_id, sid, cid, READ).await {
        return respond(&mut ack, json!({ "messages": [], "error": "PERMISSION_DENIED" }));
    }
    let before = data.get("before").cloned();
    let body = payload(vec![("channelId", Some(json!(cid))), ("before", before.clone()), ("limit", Some(json!(limit))), ("userId", Some(json!(c.user_id)))]);
    match forward_to_node(&app, sid, "MSG_HISTORY", &body, 15_000).await {
        Ok(r) => return respond(&mut ack, r),
        Err(e) if !is_no_node(&e) => return respond(&mut ack, json!({ "error": e })),
        Err(_) => {}
    }
    match app.svc.servers_get_channel_messages(sid, cid, &json!(limit), before.as_ref().and_then(|b| b.as_str()), Some(&c.user_id)).await {
        Ok(messages) => respond(&mut ack, json!({ "messages": messages })),
        Err(e) => respond(&mut ack, json!({ "error": e.message })),
    }
}

async fn server_get_channels(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let sid = s(&data, "serverId");
    // Un contrôle d'autorisation qui ne peut pas s'exécuter doit REFUSER (jamais « fail open »).
    match app.svc.servers_is_member(&sid, &c.user_id).await {
        Ok(false) => return respond(&mut ack, json!({ "channels": [], "error": "NOT_MEMBER" })),
        Err(_) => return respond(&mut ack, json!({ "channels": [], "error": "CHECK_FAILED" })),
        Ok(true) => {}
    }
    match forward_to_node(&app, &sid, "CHANNEL_LIST", &json!({}), 15_000).await {
        Ok(r) => return respond(&mut ack, r),
        Err(e) if !is_no_node(&e) => return respond(&mut ack, json!({ "channels": [], "error": e })),
        Err(_) => {}
    }
    match app.svc.servers_get_channels(&sid, Some(&c.user_id)).await {
        Ok(chs) => respond(&mut ack, json!({ "channels": if truthy(Some(&chs)) { chs } else { json!([]) } })),
        Err(_) => respond(&mut ack, json!({ "channels": [], "error": true })),
    }
}

// ── Salons ──────────────────────────────────────────────────────────────────

async fn channel_create(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_CHANNELS).await {
            c.emit_error("CHANNEL_ERROR", "PERMISSION_DENIED");
            respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
            return Ok(());
        }
        let mut input = data.as_object().cloned().unwrap_or_default();
        if !truthy(data.get("type")) {
            input.insert("type".into(), json!("text"));
        }
        let clean = validate_channel_input(&Value::Object(input)).map_err(|e| e.to_string())?;
        let cl = |k: &str| clean.get(k).cloned();
        let ctype = cl("type").filter(|t| truthy(Some(t))).unwrap_or(json!("text"));
        let body = payload(vec![("name", cl("name")), ("type", Some(ctype.clone())), ("topic", cl("topic")), ("parentId", cl("parentId")), ("userId", Some(json!(c.user_id)))]);
        match forward_to_node(&app, &server_id, "CHANNEL_CREATE", &body, 15_000).await {
            Ok(result) => {
                // Le node diffuse aussi ; on confirme à tout le serveur
                if let Some(ch) = result.get("channel").filter(|v| truthy(Some(v))) {
                    let mut p = ch.as_object().cloned().unwrap_or_default();
                    p.insert("serverId".into(), json!(server_id));
                    c.to_room(&format!("server:{server_id}"), "CHANNEL_CREATE", Value::Object(p.clone())).await;
                    respond(&mut ack, json!({ "channel": Value::Object(p) }));
                } else {
                    respond(&mut ack, json!({ "channel": Value::Null }));
                }
                return Ok(());
            }
            Err(e) if !is_no_node(&e) => {
                c.emit_error("CHANNEL_ERROR", &e);
                respond(&mut ack, json!({ "error": e }));
                return Ok(());
            }
            Err(_) => {}
        }
        // Repli microservice
        let parent = cl("parentId").filter(|p| !p.is_null());
        let body = payload(vec![
            ("name", cl("name")), ("type", Some(ctype)), ("parentId", parent), ("topic", cl("topic")), ("isNsfw", cl("isNsfw")),
            ("slowMode", cl("slowMode")), ("userLimit", cl("userLimit")), ("isPrivate", cl("isPrivate")),
        ]);
        let channel = app.svc.servers_create_channel(&server_id, body, &c.user_id, c.token.as_deref()).await.map_err(err_msg)?;
        invalidate_channel_meta(&app, &server_id).await;
        announce_channel(&app, &server_id, &channel, "CHANNEL_CREATE").await;
        respond(&mut ack, json!({ "channel": channel }));
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("CHANNEL_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

async fn channel_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let server_id = s(&data, "serverId");
        let channel_id = s(&data, "channelId");
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_CHANNELS).await {
            return Err("PERMISSION_DENIED".into());
        }
        let clean = validate_channel_input(&data)?;
        let cl = |k: &str| clean.get(k).cloned();
        let body = payload(vec![
            ("channelId", some(data.get("channelId"))), ("name", cl("name")), ("topic", cl("topic")), ("position", some(data.get("position"))),
            ("type", cl("type")), ("parentId", cl("parentId")), ("userId", Some(json!(c.user_id))),
        ]);
        match forward_to_node(&app, &server_id, "CHANNEL_UPDATE", &body, 15_000).await {
            Ok(_) => return Ok(()), // le node diffuse via NODE_BROADCAST
            Err(e) if !is_no_node(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        let mut updates = clean.clone();
        if data.get("position").is_some() && !clean.contains_key("position") {
            updates.insert("position".into(), data["position"].clone());
        }
        let channel = app.svc.servers_update_channel(&server_id, &channel_id, Value::Object(updates), &c.user_id, c.token.as_deref()).await?;
        invalidate_channel_meta(&app, &server_id).await;
        // Changer de catégorie peut changer la visibilité (salon synchronisé).
        if clean.contains_key("parentId") {
            invalidate_server_perms(&app, &server_id, None).await;
            schedule_channel_resync(&app, &server_id, None);
        }
        announce_channel(&app, &server_id, &channel, "CHANNEL_UPDATE").await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("CHANNEL_ERROR", &m);
    }
}

async fn channel_delete(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let (server_id, channel_id) = (s(&data, "serverId"), s(&data, "channelId"));
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_CHANNELS).await {
            return Err("PERMISSION_DENIED".into());
        }
        match forward_to_node(&app, &server_id, "CHANNEL_DELETE", &json!({ "channelId": data.get("channelId"), "userId": c.user_id }), 15_000).await {
            Ok(_) => return Ok(()),
            Err(e) if !is_no_node_or_timeout(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        app.svc.servers_delete_channel(&server_id, &channel_id, &c.user_id, c.token.as_deref()).await?;
        invalidate_channel_meta(&app, &server_id).await;
        let _ = app.io().within(format!("server:{server_id}")).leave(ch_room(&server_id, &channel_id)).await;
        c.to_room(&format!("server:{server_id}"), "CHANNEL_DELETE", json!({ "channelId": channel_id, "serverId": server_id })).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("CHANNEL_ERROR", &m);
    }
}

async fn channel_perms_get(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
    let empty = |e: &str| json!({ "permissions": [], "overrides": [], "error": e });
    if !val_is_id(sid) || !val_is_id(cid) {
        return respond(&mut ack, empty("INVALID_PAYLOAD"));
    }
    let (sid, cid) = (sid.as_str().unwrap(), cid.as_str().unwrap());
    // Les surcharges décrivent qui voit quoi : réservées à qui gère salons ou rôles.
    if !check_server_permission_any(&app, &c.user_id, sid, MANAGE_CHANNELS | MANAGE_ROLES).await {
        return respond(&mut ack, empty("PERMISSION_DENIED"));
    }
    match forward_to_node(&app, sid, "CHANNEL_PERMS_GET", &json!({ "channelId": cid }), 15_000).await {
        Ok(r) => return respond(&mut ack, r),
        Err(e) if !is_no_node(&e) => return respond(&mut ack, empty(&e)),
        Err(_) => {}
    }
    match app.svc.servers_get_channel_overrides(sid, cid).await {
        Ok(r) => respond(&mut ack, r),
        Err(e) => respond(&mut ack, empty(&e.message)),
    }
}

async fn channel_perms_delete(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let target_type = if field(&data, "targetType") == "member" { "member" } else { "role" };
    let (sid, cid, tid) = (field(&data, "serverId"), field(&data, "channelId"), field(&data, "targetId"));
    if !val_is_id(sid) || !val_is_id(cid) || !val_is_id(tid) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let (sid, cid, tid) = (sid.as_str().unwrap(), cid.as_str().unwrap(), tid.as_str().unwrap());
    if !check_server_permission_any(&app, &c.user_id, sid, MANAGE_CHANNELS | MANAGE_ROLES).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    if app.has_node(sid) {
        return respond(&mut ack, json!({ "error": "NOT_SUPPORTED_ON_NODE" }));
    }
    match app.svc.servers_delete_channel_override(sid, cid, target_type, tid, &c.user_id).await {
        Ok(_) => {
            after_overrides_changed(&app, sid, cid).await;
            respond(&mut ack, json!({ "success": true }));
        }
        Err(e) => respond(&mut ack, json!({ "error": e.message })),
    }
}

async fn channel_perms_sync(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
    if !val_is_id(sid) || !val_is_id(cid) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let (sid, cid) = (sid.as_str().unwrap(), cid.as_str().unwrap());
    if !check_server_permission(&app, &c.user_id, sid, MANAGE_CHANNELS).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    if app.has_node(sid) {
        return respond(&mut ack, json!({ "error": "NOT_SUPPORTED_ON_NODE" }));
    }
    match app.svc.servers_sync_channel_overrides(sid, cid, &c.user_id).await {
        Ok(_) => {
            after_overrides_changed(&app, sid, cid).await;
            respond(&mut ack, json!({ "success": true }));
        }
        Err(e) => respond(&mut ack, json!({ "error": e.message })),
    }
}

/// Glisser-déposer : un lot de positions / catégories, une seule diffusion.
async fn channel_reorder(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let sid = field(&data, "serverId");
        if !val_is_id(sid) {
            respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
            return Ok(());
        }
        let server_id = sid.as_str().unwrap().to_string();
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_CHANNELS).await {
            respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
            return Ok(());
        }
        let positions = validate_channel_reorder(field(&data, "positions")).map_err(|e| e.to_string())?;
        let mut channels: Vec<Value> = vec![];
        if app.has_node(&server_id) {
            for row in &positions {
                let body = payload(vec![("channelId", row.get("id").cloned()), ("position", row.get("position").cloned()), ("parentId", row.get("parentId").cloned()), ("userId", Some(json!(c.user_id)))]);
                forward_to_node(&app, &server_id, "CHANNEL_UPDATE", &body, 15_000).await?;
            }
        } else {
            let result = app.svc.servers_reorder_channels(&server_id, &Value::Array(positions.clone()), &c.user_id).await.map_err(err_msg)?;
            channels = result.get("channels").and_then(|c| c.as_array()).cloned().unwrap_or_default();
            invalidate_channel_meta(&app, &server_id).await;
            if positions.iter().any(|p| p.get("parentId").is_some()) {
                invalidate_server_perms(&app, &server_id, None).await;
                schedule_channel_resync(&app, &server_id, None);
            }
        }
        // Positions seules : aucun nom de salon privé ne fuit dans la diffusion.
        let visible: Vec<Value> = if !channels.is_empty() {
            channels.iter().map(|ch| json!({ "id": ch.get("id"), "position": ch.get("position"), "parentId": ch.get("parentId").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null) })).collect()
        } else {
            positions.iter().map(|p| p.clone()).collect()
        };
        c.to_room(&format!("server:{server_id}"), "CHANNELS_REORDERED", json!({ "serverId": server_id, "positions": visible })).await;
        respond(&mut ack, json!({ "success": true }));
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("CHANNEL_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

async fn channel_perms_set(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission_any(&app, &c.user_id, &server_id, MANAGE_CHANNELS | MANAGE_ROLES).await {
            respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
            return Ok(());
        }
        let num = |k: &str| {
            let v = data.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(json!(0));
            perms::js_number(&v)
        };
        let (allow, deny) = (num("allow"), num("deny"));
        // `roleId` reste accepté (ancien contrat, rôles seulement).
        let target_type = if field(&data, "targetType") == "member" { "member" } else { "role" };
        let target = data.get("targetId").filter(|v| !v.is_null()).or_else(|| data.get("roleId")).cloned().unwrap_or(Value::Null);
        let node_hosted = app.has_node(&server_id);
        let max = if node_hosted { 65535.0 } else { ALL_PERMS_MASK as f64 };
        let integer = |n: f64| n.is_finite() && n.fract() == 0.0;
        if !val_is_id(field(&data, "channelId")) || !val_is_id(&target) || !integer(allow) || !integer(deny) || allow < 0.0 || deny < 0.0 || allow > max || deny > max {
            respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
            return Ok(());
        }
        let (channel_id, target_id) = (s(&data, "channelId"), target.as_str().unwrap().to_string());
        if node_hosted {
            if target_type != "role" {
                respond(&mut ack, json!({ "error": "NOT_SUPPORTED_ON_NODE" }));
                return Ok(());
            }
            // Le node applique l'anti-escalade dans son propre espace de bits.
            let body = json!({ "channelId": channel_id, "roleId": target_id, "allow": allow as i64, "deny": deny as i64, "userId": c.user_id });
            let result = forward_to_node(&app, &server_id, "CHANNEL_PERMS_SET", &body, 15_000).await?;
            respond(&mut ack, result);
            return Ok(());
        }
        // Microservice : anti-escalade dans le salon, côté service.
        let body = json!({ "targetType": target_type, "targetId": target_id, "allow": allow as i64, "deny": deny as i64 });
        let result = app.svc.servers_set_channel_override(&server_id, &channel_id, body, &c.user_id).await.map_err(err_msg)?;
        after_overrides_changed(&app, &server_id, &channel_id).await;
        respond(&mut ack, result);
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("CHANNEL_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

// ── Rôles ───────────────────────────────────────────────────────────────────

async fn role_list(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let sid = s(&data, "serverId");
    if !check_server_permission(&app, &c.user_id, &sid, READ).await {
        return respond(&mut ack, json!({ "roles": [], "error": "PERMISSION_DENIED" }));
    }
    match forward_to_node(&app, &sid, "ROLE_LIST", &json!({}), 15_000).await {
        Ok(r) => respond(&mut ack, r),
        Err(e) => {
            if is_no_node(&e) {
                if let Ok(roles) = app.svc.servers_get_roles(&sid).await {
                    return respond(&mut ack, json!({ "roles": if truthy(Some(&roles)) { roles } else { json!([]) } }));
                }
            }
            respond(&mut ack, json!({ "roles": [], "error": e }));
        }
    }
}

/// Anti-escalade : un non-propriétaire ne peut accorder que des bits qu'il possède, et jamais ADMIN.
fn clamp_perms(p: i64, actor: &PermBits) -> i64 {
    if actor.is_owner {
        p
    } else {
        (p & actor.perms) & !ADMIN
    }
}

async fn role_create(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_ROLES).await {
            c.emit_error("ROLE_ERROR", "PERMISSION_DENIED");
            return Ok(());
        }
        let clean = validate_role_input(&data).map_err(|e| e.to_string())?;
        invalidate_server_perms(&app, &server_id, None).await;
        let actor = get_user_perm_bits(&app, &c.user_id, &server_id).await;
        let safe = clamp_perms(clean.get("permissions").and_then(|p| p.as_i64()).unwrap_or(0), &actor);
        let cl = |k: &str| clean.get(k).cloned();
        let body = payload(vec![("name", cl("name")), ("color", cl("color")), ("permissions", Some(json!(safe))), ("mentionable", cl("mentionable")), ("hoist", cl("hoist")), ("userId", Some(json!(c.user_id)))]);
        match forward_to_node(&app, &server_id, "ROLE_CREATE", &body, 15_000).await {
            Ok(result) => {
                if let Some(role) = result.get("role").filter(|v| truthy(Some(v))) {
                    let mut p = role.as_object().cloned().unwrap_or_default();
                    p.insert("serverId".into(), json!(server_id));
                    c.to_room(&format!("server:{server_id}"), "ROLE_CREATE", Value::Object(p)).await;
                }
                respond(&mut ack, json!({ "role": result.get("role").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null) }));
                return Ok(());
            }
            Err(e) if !is_no_node(&e) => {
                c.emit_error("ROLE_ERROR", &e);
                respond(&mut ack, json!({ "error": e }));
                return Ok(());
            }
            Err(_) => {}
        }
        let body = payload(vec![("name", cl("name")), ("color", cl("color")), ("permissions", Some(json!(safe))), ("hoist", cl("hoist")), ("mentionable", cl("mentionable")), ("iconEmoji", cl("iconEmoji"))]);
        let role = app.svc.servers_create_role(&server_id, body, Some(&c.user_id)).await.map_err(err_msg)?;
        let mut p = role.as_object().cloned().unwrap_or_default();
        p.insert("serverId".into(), json!(server_id));
        c.to_room(&format!("server:{server_id}"), "ROLE_CREATE", Value::Object(p.clone())).await;
        respond(&mut ack, json!({ "role": Value::Object(p) }));
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("ROLE_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

async fn role_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_ROLES).await {
            return Err("PERMISSION_DENIED".into());
        }
        let clean = validate_role_input(&data)?;
        invalidate_server_perms(&app, &server_id, None).await;
        let actor = get_user_perm_bits(&app, &c.user_id, &server_id).await;
        let safe_perms = clean.get("permissions").and_then(|p| p.as_i64()).map(|p| clamp_perms(p, &actor));
        // Un non-owner ne peut pas modifier la position d'un rôle (contournement de la hiérarchie).
        let safe_position = if actor.is_owner { data.get("position").cloned() } else { None };
        let cl = |k: &str| clean.get(k).cloned();
        let sp = safe_perms.map(|p| json!(p));
        let body = payload(vec![
            ("roleId", some(data.get("roleId"))), ("name", cl("name")), ("color", cl("color")), ("permissions", sp.clone()),
            ("position", safe_position.clone()), ("mentionable", cl("mentionable")), ("userId", Some(json!(c.user_id))),
        ]);
        match forward_to_node(&app, &server_id, "ROLE_UPDATE", &body, 15_000).await {
            Ok(result) => {
                if let Some(role) = result.get("role").filter(|v| truthy(Some(v))) {
                    let mut p = role.as_object().cloned().unwrap_or_default();
                    p.insert("serverId".into(), json!(server_id));
                    c.to_room(&format!("server:{server_id}"), "ROLE_UPDATE", Value::Object(p)).await;
                }
                return Ok(());
            }
            Err(e) if !is_no_node(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        let body = payload(vec![
            ("name", cl("name")), ("color", cl("color")), ("permissions", sp), ("position", safe_position), ("mentionable", cl("mentionable")),
            ("hoist", cl("hoist")), ("iconEmoji", cl("iconEmoji")),
        ]);
        let updated = app.svc.servers_update_role(&server_id, &s(&data, "roleId"), body, Some(&c.user_id)).await?;
        // Les droits d'un rôle décident des salons visibles.
        if safe_perms.is_some() {
            schedule_channel_resync(&app, &server_id, None);
        }
        let mut p = updated.as_object().cloned().unwrap_or_default();
        p.insert("roleId".into(), data.get("roleId").cloned().unwrap_or(Value::Null));
        p.insert("serverId".into(), json!(server_id));
        c.to_room(&format!("server:{server_id}"), "ROLE_UPDATE", Value::Object(p)).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("ROLE_ERROR", &m);
    }
}

async fn role_delete(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_ROLES).await {
            return Err("PERMISSION_DENIED".into());
        }
        invalidate_server_perms(&app, &server_id, None).await;
        let ev = json!({ "roleId": data.get("roleId"), "serverId": server_id });
        match forward_to_node(&app, &server_id, "ROLE_DELETE", &json!({ "roleId": data.get("roleId"), "userId": c.user_id }), 15_000).await {
            Ok(_) => {
                c.to_room(&format!("server:{server_id}"), "ROLE_DELETE", ev).await;
                return Ok(());
            }
            Err(e) if !is_no_node(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        app.svc.servers_delete_role(&server_id, &s(&data, "roleId"), Some(&c.user_id)).await?;
        schedule_channel_resync(&app, &server_id, None);
        c.to_room(&format!("server:{server_id}"), "ROLE_DELETE", ev).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("ROLE_ERROR", &m);
    }
}

/// Droits effectifs du membre courant — sur le serveur, ou DANS un salon (surcharges incluses).
async fn my_permissions(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    if !ack.present {
        return;
    }
    let sid = field(&data, "serverId");
    if !val_is_id(sid) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let sid = sid.as_str().unwrap();
    let cid = field(&data, "channelId");
    let (bits, channel) = if val_is_id(cid) {
        (get_channel_perm_bits(&c.app, &c.user_id, sid, cid.as_str().unwrap()).await, json!(cid))
    } else {
        (get_user_perm_bits(&c.app, &c.user_id, sid).await, Value::Null)
    };
    respond(&mut ack, json!({ "serverId": sid, "channelId": channel, "isOwner": bits.is_owner, "permissions": bits.perms }));
}

async fn role_reorder(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let sid = field(&data, "serverId");
        let positions = field(&data, "positions").as_array();
        if !val_is_id(sid) || positions.map(|p| p.is_empty() || p.len() > 250).unwrap_or(true) {
            respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
            return Ok(());
        }
        let server_id = sid.as_str().unwrap().to_string();
        if !check_server_permission(&app, &c.user_id, &server_id, MANAGE_ROLES).await {
            respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
            return Ok(());
        }
        if app.has_node(&server_id) {
            respond(&mut ack, json!({ "error": "NOT_SUPPORTED_ON_NODE" }));
            return Ok(());
        }
        let mut rows = vec![];
        for row in positions.unwrap() {
            let id = row.get("id").filter(|v| !v.is_null()).map(|v| js_string(Some(v))).unwrap_or_default();
            let p = perms::js_number(row.get("position").unwrap_or(&Value::Null)).floor();
            if !is_id(&id) || !p.is_finite() {
                respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
                return Ok(());
            }
            rows.push(json!({ "id": id, "position": p as i64 }));
        }
        invalidate_server_perms(&app, &server_id, None).await;
        let result = app.svc.servers_reorder_roles(&server_id, &Value::Array(rows), &c.user_id).await.map_err(err_msg)?;
        c.to_room(&format!("server:{server_id}"), "ROLES_REORDERED", json!({ "serverId": server_id, "roles": result.get("roles").filter(|v| !v.is_null()).cloned().unwrap_or(json!([])) })).await;
        respond(&mut ack, json!({ "success": true }));
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("ROLE_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

// ── Présence et vocal ───────────────────────────────────────────────────────

async fn get_bulk_presence(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let list = field(&data, "userIds").as_array().filter(|a| !a.is_empty());
    let Some(list) = list else { return respond(&mut ack, json!({ "presence": [] })) };
    // Liste bornée et assainie, et respect du réglage « afficher mon statut en ligne ».
    let mut ids: Vec<String> = vec![];
    for id in list.iter().filter(|v| val_is_uuid(v)).filter_map(|v| v.as_str()) {
        if !ids.iter().any(|x| x == id) {
            ids.push(id.to_string());
        }
    }
    ids.truncate(200);
    let Ok(presence) = app.redis.get_bulk_presence(&ids).await else { return respond(&mut ack, json!({ "presence": [] })) };
    let hidden = futures::future::join_all(presence.iter().map(|p| {
        let (app, uid, me) = (app.clone(), p.user_id.clone(), c.user_id.clone());
        async move { if uid == me { false } else { is_presence_hidden(&app, &uid).await } }
    }))
    .await;
    let visible: Vec<Value> = presence
        .iter()
        .zip(hidden)
        .map(|(p, h)| if h { json!({ "userId": p.user_id, "status": "offline", "customStatus": Value::Null, "emoji": Value::Null }) } else { serde_json::to_value(p).unwrap_or(Value::Null) })
        .collect();
    respond(&mut ack, json!({ "presence": visible }));
}

async fn get_voice_state(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let sid = field(&data, "serverId");
    if !truthy(Some(sid)) || !ack.present {
        return respond(&mut ack, json!({ "channels": [] }));
    }
    let server_id = js_string(Some(sid));
    // L'état vocal d'un serveur n'est visible que par ses membres.
    match c.app.svc.servers_is_member(&server_id, &c.user_id).await {
        Ok(true) => {}
        Ok(false) | Err(_) => return respond(&mut ack, json!({ "channels": [] })),
    }
    let channels: Vec<Value> = {
        let v = c.app.conns.voice.lock();
        v.channels
            .iter()
            .filter(|(_, parts)| parts.values().next().map(|p| p.server_id == server_id).unwrap_or(false))
            .map(|(cid, parts)| json!({ "channelId": cid, "participants": parts.values().map(|p| p.public()).collect::<Vec<_>>(), "status": v.status.get(cid) }))
            .collect()
    };
    respond(&mut ack, json!({ "channels": channels }));
}

// ── Membres ─────────────────────────────────────────────────────────────────

fn member_uid(m: &Value) -> String {
    ["userId", "user_id", "id"].iter().find_map(|k| m.get(*k).filter(|v| truthy(Some(v))).map(|v| js_string(Some(v)))).unwrap_or_default()
}

async fn member_list(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let server_id = s(&data, "serverId");
    if !check_server_permission(&app, &c.user_id, &server_id, READ).await {
        return respond(&mut ack, json!({ "members": [], "error": "PERMISSION_DENIED" }));
    }

    // Statut en ligne en un seul pipeline Redis ; invisible → hors ligne ; réglage « afficher mon statut ».
    let with_presence = |members: Vec<Value>| {
        let (app, me) = (app.clone(), c.user_id.clone());
        async move {
            let mut ids: Vec<String> = vec![];
            for m in &members {
                let u = member_uid(m);
                if !u.is_empty() && !ids.contains(&u) {
                    ids.push(u);
                }
            }
            let list = app.redis.get_bulk_presence(&ids).await.unwrap_or_default();
            let by_id: std::collections::HashMap<String, crate::redis_client::BulkPresence> = list.iter().cloned().map(|p| (p.user_id.clone(), p)).collect();
            let mut hidden = std::collections::HashSet::new();
            for p in list.iter().filter(|p| p.status != "offline" && p.user_id != me) {
                if is_presence_hidden(&app, &p.user_id).await {
                    hidden.insert(p.user_id.clone());
                }
            }
            members
                .into_iter()
                .map(|m| {
                    let u = member_uid(&m);
                    let mut o = m.as_object().cloned().unwrap_or_default();
                    match by_id.get(&u).filter(|_| !hidden.contains(&u)) {
                        None => {
                            o.insert("status".into(), json!("offline"));
                            o.insert("customStatus".into(), Value::Null);
                        }
                        Some(p) => {
                            o.insert("status".into(), json!(p.status));
                            o.insert("customStatus".into(), p.custom_status.clone().map(|s| json!(s)).unwrap_or(Value::Null));
                        }
                    }
                    Value::Object(o)
                })
                .collect::<Vec<_>>()
        }
    };

    // Les membres du microservice servent de référence et de source de secours.
    let ms_members: Option<Vec<Value>> = app.svc.servers_get_members(&server_id).await.ok().map(|v| v.as_array().cloned().unwrap_or_default());
    let (node_members, node_reachable) = match forward_to_node(&app, &server_id, "MEMBER_LIST", &json!({}), 15_000).await {
        Ok(r) => (r.get("members").and_then(|m| m.as_array()).cloned().unwrap_or_default(), true),
        Err(_) => (vec![], false),
    };
    let seed = |m: &Value| {
        let (app, sid) = (app.clone(), server_id.clone());
        let body = json!({
            "userId": member_uid(m), "username": m.get("username"),
            "displayName": first_truthy(&[m.get("displayName"), m.get("display_name")]),
            "avatarUrl": first_truthy(&[m.get("avatarUrl"), m.get("avatar_url")]),
        });
        tokio::spawn(async move {
            let _ = forward_to_node(&app, &sid, "MEMBER_JOIN", &body, 15_000).await;
        });
    };

    // Pas de node (ou node vide) → on sert la liste du microservice.
    if !node_reachable || node_members.is_empty() {
        let ms = ms_members.unwrap_or_default();
        if ms.is_empty() {
            return respond(&mut ack, json!({ "members": [] }));
        }
        if node_reachable {
            ms.iter().for_each(&seed);
        }
        return respond(&mut ack, json!({ "members": with_presence(ms).await }));
    }
    let ms = match ms_members {
        Some(m) if !m.is_empty() => m,
        _ => return respond(&mut ack, json!({ "members": with_presence(node_members).await })),
    };
    // Node + microservice : croiser les deux pour écarter les membres périmés.
    let valid: std::collections::HashSet<String> = ms.iter().map(member_uid).collect();
    let node_ids: std::collections::HashSet<String> = node_members.iter().map(member_uid).collect();
    let filtered: Vec<Value> = node_members.iter().filter(|m| valid.contains(&member_uid(m))).cloned().collect();
    for stale in node_members.iter().filter(|m| !valid.contains(&member_uid(m))) {
        info!("Cleaning stale member {} from node for server {server_id}", member_uid(stale));
        let (a, sid, uid) = (app.clone(), server_id.clone(), member_uid(stale));
        tokio::spawn(async move {
            let _ = forward_to_node(&a, &sid, "MEMBER_KICK", &json!({ "userId": uid, "systemCleanup": true }), 15_000).await;
        });
    }
    ms.iter().filter(|m| !node_ids.contains(&member_uid(m))).for_each(&seed);
    respond(&mut ack, json!({ "members": with_presence(filtered).await }));
}

async fn member_update(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), String> = async {
        let (sid, target) = (field(&data, "serverId"), field(&data, "targetUserId"));
        let clean = validate_member_update(&data).map_err(|e| e.to_string())?;
        let role_ids = clean.get("roleIds").and_then(|r| r.as_array()).cloned();
        let nickname = clean.get("nickname").cloned();
        if !val_is_id(sid) || !val_is_uuid(target) {
            respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
            return Ok(());
        }
        let (server_id, target_id) = (sid.as_str().unwrap().to_string(), target.as_str().unwrap().to_string());

        // Permissions par champ, comme Discord.
        let self_nick_only = target_id == c.user_id && role_ids.is_none();
        let has_perm = if self_nick_only {
            check_server_permission_any(&app, &c.user_id, &server_id, CHANGE_NICKNAME | MANAGE_NICKNAMES).await
        } else {
            (role_ids.is_none() || check_server_permission(&app, &c.user_id, &server_id, MANAGE_ROLES).await)
                && (nickname.is_none() || target_id == c.user_id || check_server_permission(&app, &c.user_id, &server_id, MANAGE_NICKNAMES).await)
        };
        if !has_perm {
            respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
            return Ok(());
        }
        // Hiérarchie : on ne modifie pas un membre dont les droits dépassent les siens.
        if target_id != c.user_id && !can_act_on_member(&app, &c.user_id, &target_id, &server_id).await {
            respond(&mut ack, json!({ "error": "TARGET_OUTRANKS_YOU" }));
            return Ok(());
        }
        // Anti-escalade : un non-owner ne peut assigner QUE des rôles dont les permissions sont incluses dans les siennes.
        let mut safe_role_ids = role_ids.clone();
        if let Some(ids) = role_ids.as_ref().filter(|r| !r.is_empty()) {
            let actor = get_user_perm_bits(&app, &c.user_id, &server_id).await;
            if !actor.is_owner {
                let roles = match app.svc.servers_get_roles(&server_id).await {
                    Ok(r) => r,
                    Err(_) => {
                        respond(&mut ack, json!({ "error": "ROLE_CHECK_FAILED" }));
                        return Ok(());
                    }
                };
                let mut allowed = std::collections::HashSet::new();
                for r in roles.as_array().into_iter().flatten() {
                    let raw = r.get("permissions").filter(|v| !v.is_null()).cloned().unwrap_or(json!("0"));
                    let p = match &raw {
                        Value::Number(_) => perms::mask_number(perms::js_number(&raw)),
                        other => parse_int_prefix(&js_string(Some(other))) & ALL_PERMS_MASK,
                    };
                    // Assignable si tous ses bits ⊆ bits de l'acteur, et pas ADMIN.
                    if p & !actor.perms == 0 && p & ADMIN == 0 {
                        if let Some(id) = r.get("id").and_then(|i| i.as_str()) {
                            allowed.insert(id.to_string());
                        }
                    }
                }
                let kept: Vec<Value> = ids.iter().filter(|rid| rid.as_str().map(|s| allowed.contains(s)).unwrap_or(false)).cloned().collect();
                if kept.len() != ids.len() {
                    warn!("MEMBER_UPDATE escalation blocked: {} tried to assign superior roles on server {server_id}", c.user_id);
                }
                safe_role_ids = Some(kept);
            }
        }
        invalidate_server_perms(&app, &server_id, Some(&target_id)).await;
        let roles_v = safe_role_ids.clone().map(Value::Array);
        let body = payload(vec![("userId", Some(json!(target_id))), ("roleIds", roles_v.clone()), ("nickname", nickname.clone())]);
        match forward_to_node(&app, &server_id, "MEMBER_UPDATE", &body, 15_000).await {
            Ok(result) => respond(&mut ack, result),
            Err(e) if !is_no_node(&e) => respond(&mut ack, json!({ "error": e })),
            Err(_) => {
                // Repli : mise à jour MySQL directe
                let upd = payload(vec![("roleIds", roles_v.clone()), ("nickname", nickname.clone())]);
                app.svc.servers_update_member(&server_id, &target_id, upd, Some(&c.user_id), c.token.as_deref()).await.map_err(err_msg)?;
                if safe_role_ids.is_some() {
                    schedule_channel_resync(&app, &server_id, Some(&target_id));
                }
                c.to_room(&format!("server:{server_id}"), "MEMBER_UPDATE", payload(vec![("userId", Some(json!(target_id))), ("serverId", Some(json!(server_id))), ("roleIds", roles_v), ("nickname", nickname)])).await;
                respond(&mut ack, json!({ "success": true }));
            }
        }
        Ok(())
    }
    .await;
    if let Err(m) = r {
        c.emit_error("MEMBER_ERROR", &m);
        respond(&mut ack, json!({ "error": m }));
    }
}

/// `parseInt(s, 10)` → 0 si NaN (équivaut à `NaN & mask` = 0).
fn parse_int_prefix(t: &str) -> i64 {
    let t = t.trim_start();
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let n = digits.parse::<f64>().unwrap_or(0.0);
    perms::mask_number(if neg { -n } else { n })
}

async fn member_kick_or_ban(c: Arc<SockCtx>, data: Value, ban: bool) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let server_id = s(&data, "serverId");
        let any = if ban { BAN_ANY } else { KICK_ANY };
        // Les deux paires historiques de bits coexistent dans les rôles existants.
        if !check_server_permission_any(&app, &c.user_id, &server_id, any).await {
            return Err("PERMISSION_DENIED".into());
        }
        let target = [data.get("targetUserId"), data.get("userId")].into_iter().flatten().find(|v| truthy(Some(v))).map(|v| js_string(Some(v))).unwrap_or_default();
        // Hiérarchie : sinon un modérateur expulsait un administrateur — ou le propriétaire.
        if !can_act_on_member(&app, &c.user_id, &target, &server_id).await {
            return Err("TARGET_OUTRANKS_YOU".into());
        }
        invalidate_server_perms(&app, &server_id, Some(&target)).await;
        let reason = data.get("reason").cloned();
        let (event_name, body) = if ban {
            ("MEMBER_BAN", payload(vec![("userId", Some(json!(target))), ("reason", reason.clone()), ("actorId", Some(json!(c.user_id)))]))
        } else {
            ("MEMBER_KICK", json!({ "userId": target, "actorId": c.user_id }))
        };
        match forward_to_node(&app, &server_id, event_name, &body, 15_000).await {
            Ok(_) => {}
            Err(e) if !is_no_node(&e) => return Err(HErr(e)),
            Err(_) => {
                if ban {
                    app.svc.servers_ban_member(&server_id, &target, &c.user_id, reason.as_ref().and_then(|r| r.as_str())).await?;
                } else {
                    app.svc.servers_kick_member(&server_id, &target, &c.user_id).await?;
                }
            }
        }
        if ban {
            c.to_room(&format!("user:{target}"), "SERVER_BANNED", payload(vec![("serverId", Some(json!(server_id))), ("reason", reason)])).await;
            c.to_room(&format!("server:{server_id}"), "MEMBER_LEAVE", json!({ "serverId": server_id, "userId": target, "banned": true })).await;
        } else {
            c.to_room(&format!("user:{target}"), "SERVER_KICKED", json!({ "serverId": server_id })).await;
            c.to_room(&format!("server:{server_id}"), "MEMBER_LEAVE", json!({ "serverId": server_id, "userId": target, "kicked": true })).await;
        }
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("MEMBER_ERROR", &m);
    }
}

async fn member_kick(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    member_kick_or_ban(c, data, false).await
}

async fn member_ban(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    member_kick_or_ban(c, data, true).await
}

// ── Informations de serveur ─────────────────────────────────────────────────

async fn server_info(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let sid = s(&data, "serverId");
    // Fail-closed : voir SERVER_GET_CHANNELS.
    match app.svc.servers_is_member(&sid, &c.user_id).await {
        Ok(false) => return respond(&mut ack, json!({ "error": "NOT_MEMBER" })),
        Err(_) => return respond(&mut ack, json!({ "error": "CHECK_FAILED" })),
        Ok(true) => {}
    }
    match forward_to_node(&app, &sid, "SERVER_INFO", &json!({}), 15_000).await {
        Ok(r) => respond(&mut ack, r),
        Err(e) => match app.svc.servers_get_server(&sid).await {
            Ok(mut server) => {
                // getServer est un appel interne (liste complète) : on n'expose au membre que les salons qu'il peut voir.
                if server.get("channels").map(|c| c.is_array()).unwrap_or(false) {
                    let vis = app.svc.servers_get_channels(&sid, Some(&c.user_id)).await.unwrap_or(json!([]));
                    server["channels"] = if vis.is_null() { json!([]) } else { vis };
                }
                respond(&mut ack, server);
            }
            Err(_) => respond(&mut ack, json!({ "error": e })),
        },
    }
}

/// Le frontend s'en sert pour masquer l'onglet Invitations : réservé au vrai propriétaire.
async fn server_owner_joined(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let sid = field(&data, "serverId");
    if !truthy(Some(sid)) {
        return;
    }
    let server_id = js_string(Some(sid));
    let srv = c.app.svc.servers_get_server(&server_id).await.ok();
    let owner = srv.as_ref().and_then(|s| [s.get("ownerId"), s.get("owner_id")].into_iter().flatten().find(|v| !v.is_null()).cloned());
    if !owner.as_ref().map(|o| truthy(Some(o)) && o.as_str() == Some(c.user_id.as_str())).unwrap_or(false) {
        warn!("SERVER_OWNER_JOINED refusé : {} n'est pas owner de {server_id}", c.user_id);
        return;
    }
    c.to_room(&format!("server:{server_id}"), "SERVER_OWNER_JOINED", json!({ "serverId": server_id, "ownerId": c.user_id })).await;
    info!("SERVER_OWNER_JOINED broadcasted pour serveur {server_id} par owner {}", c.user_id);
}

async fn server_update_node(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let server_id = s(&data, "serverId");
        if !check_server_permission_any(&app, &c.user_id, &server_id, MANAGE_SERVER).await {
            return Err("PERMISSION_DENIED".into());
        }
        let clean = validate_server_input(&data)?;
        // `Object.assign(data, clean)` : les valeurs nettoyées remplacent celles du client.
        let mut merged = data.as_object().cloned().unwrap_or_default();
        for (k, v) in &clean {
            merged.insert(k.clone(), v.clone());
        }
        let cl = |k: &str| clean.get(k).cloned();
        let body = payload(vec![("name", cl("name")), ("description", cl("description")), ("iconUrl", cl("iconUrl")), ("bannerUrl", cl("bannerUrl")), ("isPublic", cl("isPublic"))]);
        match forward_to_node(&app, &server_id, "SERVER_UPDATE", &body, 15_000).await {
            Ok(result) => {
                let mut p = Map::new();
                p.insert("id".into(), json!(server_id));
                if let Some(o) = result.as_object() {
                    for (k, v) in o {
                        p.insert(k.clone(), v.clone());
                    }
                }
                c.to_room(&format!("server:{server_id}"), "SERVER_UPDATE", Value::Object(p)).await;
                return Ok(());
            }
            Err(e) if !is_no_node_or_timeout(&e) => return Err(HErr(e)),
            Err(_) => {}
        }
        // Repli : pas de node → microservice
        let mut updates = Map::new();
        for k in ["name", "description", "iconUrl", "bannerUrl", "isPublic"] {
            if let Some(v) = merged.get(k) {
                updates.insert(k.into(), v.clone());
            }
        }
        let updated = app.svc.servers_update(&server_id, Value::Object(updates), &c.user_id, c.token.as_deref()).await.ok();
        let m = |k: &str| merged.get(k).cloned();
        let mut p = serde_json::from_value::<Map<String, Value>>(payload(vec![
            ("id", Some(json!(server_id))), ("name", m("name")), ("description", m("description")), ("iconUrl", m("iconUrl")),
            ("bannerUrl", m("bannerUrl")), ("isPublic", m("isPublic")),
        ]))
        .unwrap_or_default();
        if let Some(Value::Object(u)) = updated.as_ref().filter(|u| u.get("success").is_none()) {
            for (k, v) in u {
                p.insert(k.clone(), v.clone());
            }
        }
        c.to_room(&format!("server:{server_id}"), "SERVER_UPDATE", Value::Object(p)).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("SERVER_ERROR", &m);
    }
}

// ── Invitations ─────────────────────────────────────────────────────────────

async fn invite_list(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let sid = s(&data, "serverId");
    // Un code d'invitation ouvre l'accès à un serveur privé : réservé à ceux qui gèrent le serveur.
    if !check_server_permission_any(&app, &c.user_id, &sid, MANAGE_SERVER | MANAGE_CHANNELS).await {
        return respond(&mut ack, json!({ "invites": [], "error": "PERMISSION_DENIED" }));
    }
    match forward_to_node(&app, &sid, "INVITE_LIST", &json!({}), 15_000).await {
        Ok(r) => respond(&mut ack, r),
        Err(e) => match app.svc.servers_get_invites(&sid).await {
            Ok(inv) => respond(&mut ack, json!({ "invites": if truthy(Some(&inv)) { inv } else { json!([]) } })),
            Err(_) => respond(&mut ack, json!({ "invites": [], "error": e })),
        },
    }
}

async fn invite_delete(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let sid = s(&data, "serverId");
    if !check_server_permission_any(&app, &c.user_id, &sid, MANAGE_SERVER | MANAGE_CHANNELS).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    let iid = field(&data, "inviteId");
    if !val_is_id(iid) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let iid = iid.as_str().unwrap();
    match forward_to_node(&app, &sid, "INVITE_DELETE", &json!({ "inviteId": iid }), 15_000).await {
        Err(e) if !is_no_node(&e) => return respond(&mut ack, json!({ "error": e })),
        _ => {}
    }
    // La copie MySQL (liens HTTP /invite/<code>) doit disparaître aussi.
    match app.svc.servers_delete_invite(iid, &c.user_id).await {
        Err(e) if e.status != Some(404) => respond(&mut ack, json!({ "error": e.message })),
        _ => respond(&mut ack, json!({ "success": true })),
    }
}

async fn invite_create(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let clean = match validate_invite_input(&data) {
        Ok(c) => c,
        Err(e) => return respond(&mut ack, json!({ "error": e.to_string() })),
    };
    let sid = s(&data, "serverId");
    // « Créer une invitation » : droit de base de @everyone sur Discord.
    if !check_server_permission(&app, &c.user_id, &sid, CREATE_INVITE).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    let cl = |k: &str| clean.get(k).cloned();
    let body = payload(vec![("creatorId", Some(json!(c.user_id))), ("maxUses", cl("maxUses")), ("expiresIn", cl("expiresIn")), ("customSlug", cl("customSlug")), ("isPermanent", cl("isPermanent"))]);
    match forward_to_node(&app, &sid, "INVITE_CREATE", &body, 15_000).await {
        Ok(result) => {
            // Synchroniser l'invitation dans le MySQL central pour que le lien HTTP fonctionne
            if truthy(result.get("code")) {
                let b = payload(vec![
                    ("creatorId", Some(json!(c.user_id))), ("code", result.get("code").cloned()), ("id", result.get("id").cloned()), ("maxUses", cl("maxUses")),
                    ("expiresIn", cl("expiresIn")), ("customSlug", cl("customSlug")), ("isPermanent", cl("isPermanent")),
                ]);
                if app.svc.servers_create_invite(&sid, b, &c.user_id).await.is_err() {
                    warn!("INVITE_CREATE: échec sync MySQL (node fonctionnel)");
                }
            }
            respond(&mut ack, result);
        }
        Err(e) => match app.svc.servers_create_invite(&sid, body, &c.user_id).await {
            Ok(inv) => respond(&mut ack, inv),
            Err(_) => respond(&mut ack, json!({ "error": e })),
        },
    }
}

async fn invite_verify(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    if !app.ws_limits.check_invite_verify_rate(&c.user_id) {
        return respond(&mut ack, json!({ "error": "RATE_LIMITED" }));
    }
    let sid = s(&data, "serverId");
    match forward_to_node(&app, &sid, "INVITE_VERIFY", &json!({ "code": data.get("code") }), 15_000).await {
        Ok(r) => respond(&mut ack, r),
        Err(e) => match app.svc.servers_resolve_invite(&s(&data, "code")).await {
            Ok(inv) => respond(&mut ack, inv),
            Err(_) => respond(&mut ack, json!({ "error": e })),
        },
    }
}
