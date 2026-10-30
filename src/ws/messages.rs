//! Handlers de messagerie privée et de groupes : messages, E2EE, frappe, réactions, archive DM, amis.

use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};
use tracing::{error, info, warn};
use uuid::Uuid;

use super::helpers::*;
use super::{on, Ack, SockCtx};
use crate::http::routes_misc::{is_id, is_uuid, js_string, truthy};
use crate::redis_client::PresencePatch;
use crate::state::event;
use crate::svc::SvcErr;
use crate::validation::{field, validate_message_content, ValidationError};

/// Erreur de handler : le message est celui de l'`Error` JS (ou le message générique).
pub struct HErr(pub String);

impl From<ValidationError> for HErr {
    fn from(e: ValidationError) -> Self {
        HErr(e.to_string())
    }
}
impl From<SvcErr> for HErr {
    fn from(e: SvcErr) -> Self {
        HErr(e.message)
    }
}
impl From<String> for HErr {
    fn from(e: String) -> Self {
        HErr(e)
    }
}
impl From<&str> for HErr {
    fn from(e: &str) -> Self {
        HErr(e.to_string())
    }
}

type HResult = Result<(), HErr>;

const MAX_MENTIONS: usize = 20;
static NONCE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());

fn s_of(v: &Value) -> Option<&str> {
    v.as_str()
}

fn preview(content: &str) -> String {
    let n: Vec<u16> = content.encode_utf16().collect();
    if n.len() > 80 {
        format!("{}…", String::from_utf16_lossy(&n[..80]))
    } else {
        content.to_string()
    }
}

fn substring80(s: &str) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(80).collect::<Vec<_>>())
}

pub fn register(c: &Arc<SockCtx>) {
    // Heartbeat : activité + restauration du statut après un auto-idle
    on(c, "HEARTBEAT", |c, data, _ack| async move {
        let active = field(&data, "active") != &Value::Bool(false);
        if active {
            let _ = c.app.redis.touch_activity(&c.user_id).await;
            let app = c.app.clone();
            let uid = c.user_id.clone();
            tokio::spawn(async move {
                let Ok(Some(p)) = app.redis.get_presence(&uid).await else { return };
                let status = p.get("status").and_then(|v| v.as_str());
                let chosen = p.get("chosenStatus").and_then(|v| v.as_str());
                if status == Some("idle") && (truthy(p.get("autoIdle")) || chosen == Some("online")) {
                    let restored = chosen.filter(|c| *c != "idle" && !c.is_empty()).unwrap_or("online").to_string();
                    let patch = PresencePatch { status: Some(restored.clone()), auto_idle: Some(false), last_activity: Some(crate::redis_client::now_ms()), ..Default::default() };
                    if app.redis.set_presence(&uid, patch).await.is_err() {
                        return;
                    }
                    let friends = app.svc.friends_get_friends(&uid).await;
                    super::presence::broadcast_presence_update(&app, &uid, &restored, &friends, p.get("text"), p.get("emoji")).await;
                }
            });
        }
        c.emit_event("HEARTBEAT_ACK", json!({ "timestamp": crate::redis_client::now_ms() }));
    });

    // Synchronisation de lecture multi-appareils
    on(c, "MARK_READ", |c, data, _| async move {
        let Some(key) = field(&data, "key").as_str().filter(|k| !k.is_empty()) else { return };
        let _ = c.socket.to(format!("user:{}", c.user_id)).emit("NOTIFICATION_SYNC", &json!({ "key": key })).await;
    });

    // Synchronisation des préférences multi-appareils (relais simple)
    on(c, "PREFERENCES_UPDATE", |c, data, _| async move {
        c.raw_to_room_others(&format!("user:{}", c.user_id), "PREFERENCES_UPDATE", &data).await;
    });

    on(c, "MESSAGE_CREATE", |c, data, _| async move {
        if let Err(HErr(m)) = message_create(&c, &data).await {
            c.emit_error("MESSAGE_CREATE_ERROR", &m);
        }
    });
    on(c, "message:send", message_send);

    on(c, "MESSAGE_UPDATE", |c, data, _| async move {
        let r: HResult = async {
            if !has_conversation_access(&c.app, &c.user_id, field(&data, "conversationId")).await {
                return Err("FORBIDDEN".into());
            }
            let v = validate_message_content(field(&data, "content"), &Value::Null, field(&data, "e2eeType"))?;
            let message = c.app.svc.messages_update_message(&js_string(data.get("messageId")), &v.content, &c.user_id, None, None).await?;
            c.to_room(&format!("conversation:{}", js_string(data.get("conversationId"))), "MESSAGE_UPDATE", message).await;
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("MESSAGE_UPDATE_ERROR", &m);
        }
    });
    on(c, "message:edit", message_edit);

    on(c, "MESSAGE_DELETE", |c, data, _| async move {
        let r: HResult = async {
            if !has_conversation_access(&c.app, &c.user_id, field(&data, "conversationId")).await {
                return Err("FORBIDDEN".into());
            }
            c.app.svc.messages_delete_message(&js_string(data.get("messageId")), &c.user_id).await?;
            c.to_room(&format!("conversation:{}", js_string(data.get("conversationId"))), "MESSAGE_DELETE", json!({ "messageId": data.get("messageId") })).await;
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("MESSAGE_DELETE_ERROR", &m);
        }
    });
    on(c, "message:delete", message_delete);
    on(c, "conversation:join", conversation_join);

    on(c, "e2ee:history-request", e2ee_history_request);
    on(c, "e2ee:history-response", e2ee_history_response);

    for (ev, start) in [("TYPING_START", true), ("TYPING_STOP", false)] {
        on(c, ev, move |c, data, _| async move {
            if !has_conversation_access(&c.app, &c.user_id, field(&data, "conversationId")).await {
                return;
            }
            let conv = js_string(data.get("conversationId"));
            let _ = if start { c.app.redis.set_typing(&conv, &c.user_id).await } else { c.app.redis.remove_typing(&conv, &c.user_id).await };
            c.to_room_others(&format!("conversation:{conv}"), ev, json!({ "userId": c.user_id, "conversationId": data.get("conversationId") })).await;
        });
    }

    for (ev, add) in [("REACTION_ADD", true), ("REACTION_REMOVE", false)] {
        on(c, ev, move |c, data, _| async move {
            let r: HResult = async {
                if !has_conversation_access(&c.app, &c.user_id, field(&data, "conversationId")).await {
                    return Err("FORBIDDEN".into());
                }
                let (mid, emoji) = (js_string(data.get("messageId")), js_string(data.get("emoji")));
                if add {
                    c.app.svc.messages_add_reaction(&mid, &c.user_id, &emoji).await?;
                } else {
                    c.app.svc.messages_remove_reaction(&mid, &c.user_id, &emoji).await?;
                }
                c.to_room(
                    &format!("conversation:{}", js_string(data.get("conversationId"))),
                    ev,
                    json!({ "messageId": data.get("messageId"), "userId": c.user_id, "emoji": data.get("emoji"), "conversationId": data.get("conversationId") }),
                )
                .await;
                Ok(())
            }
            .await;
            if let Err(HErr(m)) = r {
                c.emit_error("REACTION_ERROR", &m);
            }
        });
    }

    // ── Archivage P2P des MP ──────────────────────────────────────────────
    on(c, "DM_ARCHIVE_CONFIRM", |c, data, _| async move {
        let r: HResult = async {
            let result = c
                .app
                .svc
                .messages_confirm_archive(&js_string(data.get("conversationId")), &js_string(data.get("archiveLogId")), c.token.as_deref())
                .await?;
            c.emit_event("DM_ARCHIVE_CONFIRM_ACK", result);
            info!("📦 Confirmation archive DM de {} pour {}", c.user_id, js_string(data.get("conversationId")));
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("DM_ARCHIVE_ERROR", &m);
        }
    });
    on(c, "DM_ARCHIVE_REQUEST", dm_archive_request);
    on(c, "DM_ARCHIVE_PEER_RESPONSE", dm_archive_peer_response);
    on(c, "DM_ARCHIVE_STATUS", |c, data, _| async move {
        let r: HResult = async {
            let status = c.app.svc.messages_get_archive_status(&js_string(data.get("conversationId")), c.token.as_deref()).await?;
            c.emit_event("DM_ARCHIVE_STATUS", status);
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("DM_ARCHIVE_ERROR", &m);
        }
    });

    // ── Amis ──────────────────────────────────────────────────────────────
    on(c, "FRIEND_REQUEST", |c, data, _| async move {
        let r: HResult = async {
            let to = field(&data, "toUserId");
            if !val_is_uuid(to) || to.as_str() == Some(c.user_id.as_str()) {
                return Err("INVALID_TARGET".into());
            }
            let to = to.as_str().unwrap().to_string();
            let msg = field(&data, "message").as_str().map(|m| m.encode_utf16().take(200).collect::<Vec<_>>()).map(|u| String::from_utf16_lossy(&u));
            let request = c.app.svc.friends_send_request(&c.user_id, &to, msg.as_deref()).await?;
            c.to_room(&format!("user:{to}"), "FRIEND_REQUEST", request.clone()).await;
            c.emit_event("FRIEND_REQUEST_SENT", request);
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("FRIEND_REQUEST_ERROR", &m);
        }
    });

    on(c, "FRIEND_ACCEPT", |c, data, _| async move {
        let r: HResult = async {
            let friendship = c.app.svc.friends_accept_request(&js_string(data.get("requestId")), &c.user_id).await?;
            for k in ["userId", "friendId"] {
                c.to_room(&format!("user:{}", js_string(friendship.get(k))), "FRIEND_ACCEPT", friendship.clone()).await;
            }
            Ok(())
        }
        .await;
        if let Err(HErr(m)) = r {
            c.emit_error("FRIEND_ACCEPT_ERROR", &m);
        }
    });
}

// ── Messages ────────────────────────────────────────────────────────────────

/// Alias historique de `message:send`, soumis aux mêmes barrières (débit, mute, blocage).
async fn message_create(c: &Arc<SockCtx>, data: &Value) -> HResult {
    let app = &c.app;
    if !app.ws_limits.check_message_rate(Some(&app.redis.raw()), &c.user_id).await {
        return Err("RATE_LIMITED".into());
    }
    if !has_conversation_access(app, &c.user_id, field(data, "conversationId")).await {
        return Err("FORBIDDEN".into());
    }
    if let Some(mute) = get_active_mute(app, &c.user_id).await {
        return Err(mute_message(&mute).into());
    }
    if let Some(peer) = dm_peer(field(data, "conversationId"), &c.user_id) {
        if crate::nodes::is_dm_blocked(app, &c.user_id, &peer).await {
            return Err("BLOCKED".into());
        }
        if !can_direct_message(app, &c.user_id, &peer).await {
            return Err("DM_NOT_ALLOWED".into());
        }
    }
    let v = validate_message_content(field(data, "content"), field(data, "attachments"), field(data, "e2eeType"))?;
    // Charge utile reconstruite champ par champ : le spread de `data` transmettait tout ce que le client ajoutait.
    let mut body = Map::new();
    body.insert("conversationId".into(), data.get("conversationId").cloned().unwrap_or(Value::Null));
    body.insert("content".into(), json!(v.content));
    body.insert("senderId".into(), json!(c.user_id));
    if let Some(sc) = field(data, "senderContent").as_str().filter(|s| s.encode_utf16().count() <= 131_072) {
        body.insert("senderContent".into(), json!(sc));
    }
    let e2ee = field(data, "e2eeType");
    if e2ee.as_f64() == Some(1.0) || e2ee.as_f64() == Some(3.0) {
        body.insert("e2eeType".into(), e2ee.clone());
    }
    if val_is_uuid(field(data, "replyToId")) {
        body.insert("replyToId".into(), data["replyToId"].clone());
    }
    let message = app.svc.messages_create_message(Value::Object(body)).await?;
    c.to_room(&format!("conversation:{}", js_string(data.get("conversationId"))), "MESSAGE_CREATE", message).await;
    Ok(())
}

fn msg_error(c: &SockCtx, code: &str, message: &str) {
    let _ = c.socket.emit("message:error", &json!({ "error": code, "message": message }));
}

/// Livraison optimiste (< 2 ms) : diffusion AVANT l'écriture en base, confirmation immédiate, écriture en arrière-plan.
async fn message_send(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let uid = c.user_id.clone();

    if !app.ws_limits.check_message_rate(Some(&app.redis.raw()), &uid).await {
        let _ = c.socket.emit("message:error", &json!({ "error": "RATE_LIMITED", "message": "Trop de messages envoyés. Calme-toi !" }));
        return;
    }
    if let Some(mute) = get_active_mute(&app, &uid).await {
        msg_error(&c, "MUTED", &mute_message(&mute));
        return;
    }
    let v = match validate_message_content(field(&data, "content"), field(&data, "attachments"), field(&data, "e2eeType")) {
        Ok(v) => v,
        Err(e) => {
            msg_error(&c, "INVALID", &e.to_string());
            return;
        }
    };
    let content = v.content.clone();

    let sender_content = data.get("senderContent");
    if let Some(sc) = sender_content {
        if !sc.as_str().map(|s| s.encode_utf16().count() <= 131_072).unwrap_or(false) {
            msg_error(&c, "INVALID", "senderContent invalide");
            return;
        }
    }
    let reply_to = data.get("replyToId");
    if let Some(r) = reply_to {
        if !r.is_null() && !val_is_uuid(r) {
            msg_error(&c, "INVALID", "replyToId invalide");
            return;
        }
    }

    // Pour un MP, le destinataire est DÉRIVÉ de la conversation, jamais l'inverse.
    let first = |a: &str, b: &str| -> String {
        let (x, y) = (data.get(a), data.get(b));
        [x, y].into_iter().flatten().find(|v| truthy(Some(v))).map(|v| js_string(Some(v))).unwrap_or_default()
    };
    let mut conversation_id = first("conversationId", "channelId");
    let mut recipient_id: Option<String> = None;
    match data.get("recipientId") {
        Some(r) if !r.is_null() => {
            if !val_is_uuid(r) || r.as_str() == Some(uid.as_str()) {
                msg_error(&c, "INVALID", "Destinataire invalide");
                return;
            }
            let rid = r.as_str().unwrap().to_string();
            let expected = dm_id_for(&uid, &rid);
            if !conversation_id.is_empty() && conversation_id != expected {
                msg_error(&c, "FORBIDDEN", "Conversation et destinataire incohérents.");
                return;
            }
            conversation_id = expected;
            recipient_id = Some(rid);
        }
        _ => {
            if conversation_id.starts_with("dm_") {
                recipient_id = dm_peer(&json!(conversation_id), &uid);
            }
        }
    }

    // Blocage + confidentialité (MP uniquement)
    if let Some(rid) = &recipient_id {
        if crate::nodes::is_dm_blocked(&app, &uid, rid).await {
            msg_error(&c, "BLOCKED", "Vous ne pouvez pas envoyer de message à cet utilisateur.");
            return;
        }
        if !can_direct_message(&app, &uid, rid).await {
            msg_error(&c, "DM_NOT_ALLOWED", "Cet utilisateur n'accepte pas les messages privés de votre part.");
            return;
        }
    }

    // Contrôle d'accès à la conversation (fail-closed)
    if !has_conversation_access(&app, &uid, &json!(conversation_id)).await {
        msg_error(&c, "FORBIDDEN", "Vous ne participez pas à cette conversation.");
        return;
    }

    // ÉTAPE 1 : identifiant généré côté gateway, payload construit immédiatement
    let message_id = Uuid::new_v4().to_string();
    let is_dm_conv = conversation_id.starts_with("dm_");
    let is_group = recipient_id.is_none() && !is_dm_conv;
    let e2ee = data.get("e2eeType").cloned();
    let mut m = Map::new();
    m.insert("id".into(), json!(message_id));
    m.insert("conversationId".into(), json!(conversation_id));
    if is_group {
        m.insert("groupId".into(), json!(conversation_id));
    }
    m.insert("senderId".into(), json!(uid));
    m.insert("content".into(), json!(content));
    if let Some(sc) = sender_content {
        m.insert("senderContent".into(), sc.clone());
    }
    if let Some(e) = &e2ee {
        m.insert("e2eeType".into(), e.clone());
    }
    if let Some(r) = &recipient_id {
        m.insert("recipientId".into(), json!(r));
    }
    if let Some(r) = reply_to {
        m.insert("replyToId".into(), r.clone());
    }
    m.insert("createdAt".into(), json!(crate::iso::to_string(&chrono::Utc::now())));
    m.insert("isEdited".into(), json!(false));
    m.insert("reactions".into(), json!([]));
    m.insert(
        "sender".into(),
        json!({ "id": uid, "username": c.username(), "displayName": c.display_name(), "avatarUrl": c.avatar() }),
    );
    let message_for_client = Value::Object(m);

    // ÉTAPE 2 : rejoindre la room et diffuser AVANT l'écriture en base
    let conv_room = format!("conversation:{conversation_id}");
    let _ = c.socket.join(conv_room.clone());
    let _ = app.io().to(conv_room.clone()).emit("message:new", &message_for_client).await;

    if let Some(rid) = &recipient_id {
        let io = app.io();
        let conv_ids: std::collections::HashSet<String> = io.within(conv_room.clone()).sockets().iter().map(|s| s.id.to_string()).collect();
        let recipient_socks: Vec<String> = io.within(format!("user:{rid}")).sockets().iter().map(|s| s.id.to_string()).collect();
        // Filet de sécurité DM : user:B reçoit le message s'il n'est PAS déjà dans la room de la conversation.
        let already = recipient_socks.iter().any(|s| conv_ids.contains(s));
        if !already {
            let _ = io.to(format!("user:{rid}")).emit("message:new", &message_for_client).await;
            let _ = io
                .to(format!("user:{rid}"))
                .emit(
                    "CONVERSATION_CREATE",
                    &json!({ "id": conversation_id, "type": "dm", "recipientId": uid, "recipientName": c.display_name(), "recipientAvatar": c.avatar() }),
                )
                .await;
            // Destinataire hors ligne → notification push (rien du contenu chiffré ne sort)
            if recipient_socks.is_empty() {
                let body = if e2ee.as_ref().map(|e| !truthy(Some(e))).unwrap_or(true) && !content.is_empty() && !content.starts_with("ecdh:") {
                    preview(&content)
                } else {
                    "Nouveau message".to_string()
                };
                let (a, payload) = (app.clone(), json!({ "userId": rid, "title": c.display_name(), "body": body, "url": format!("/channels/me/{uid}"), "type": "message", "conversationKey": uid }));
                tokio::spawn(async move { a.svc.users_send_push(payload).await });
            }
        }
        // Filet de sécurité EXPÉDITEUR : les autres appareils qui ne sont pas déjà dans la room
        let sender_socks: Vec<String> = io.within(format!("user:{uid}")).sockets().iter().map(|s| s.id.to_string()).collect();
        for sid in &sender_socks {
            if *sid != c.socket.id.to_string() && !conv_ids.contains(sid) {
                let _ = io.to(sid.clone()).emit("message:new", &message_for_client).await;
            }
        }
        // L'expéditeur voit apparaître la conversation dans SA liste de MP sans rafraîchir
        if !sender_socks.is_empty() {
            let (a, rid, uid2, cid) = (app.clone(), rid.clone(), uid.clone(), conversation_id.clone());
            tokio::spawn(async move {
                if let Ok(ru) = a.svc.users_get_user(&rid).await {
                    let name = ru.get("displayName").filter(|v| truthy(Some(v))).or_else(|| ru.get("username")).filter(|v| truthy(Some(v))).map(|v| js_string(Some(v))).unwrap_or_default();
                    let avatar = ru.get("avatarUrl").filter(|v| truthy(Some(v))).cloned().unwrap_or(Value::Null);
                    let _ = a.io().to(format!("user:{uid2}")).emit("CONVERSATION_CREATE", &json!({ "id": cid, "type": "dm", "recipientId": rid, "recipientName": name, "recipientAvatar": avatar })).await;
                }
            });
        }
    }

    // Groupe : push pour chaque participant hors ligne
    if is_group {
        let (a, cid, uid2, sender_name) = (app.clone(), conversation_id.clone(), uid.clone(), c.display_name());
        let body = if e2ee.as_ref().map(|e| !truthy(Some(e))).unwrap_or(true) && !content.is_empty() && !content.starts_with("ecdh:") {
            preview(&content)
        } else {
            "Nouveau message".to_string()
        };
        tokio::spawn(async move {
            let Ok(result) = a.svc.messages_get_participants(&cid).await else { return };
            let list = result.get("participants").and_then(|p| p.as_array()).or_else(|| result.as_array());
            for p in list.into_iter().flatten() {
                let pid = js_string(p.get("userId"));
                if pid == uid2 {
                    continue;
                }
                if a.io().within(format!("user:{pid}")).sockets().is_empty() {
                    a.svc
                        .users_send_push(json!({ "userId": pid, "title": sender_name, "body": body, "url": format!("/channels/me/{cid}"), "type": "message", "conversationKey": cid }))
                        .await;
                }
            }
        });
    }

    // ÉTAPE 3 : confirmation immédiate à l'expéditeur (`clientNonce` renvoyé tel quel, jamais diffusé)
    let nonce = data.get("clientNonce").and_then(|n| n.as_str()).filter(|n| NONCE_RE.is_match(n));
    let mut sent = Map::new();
    sent.insert("success".into(), json!(true));
    sent.insert("message".into(), message_for_client.clone());
    if let Some(n) = nonce {
        sent.insert("clientNonce".into(), json!(n));
    }
    let _ = c.socket.emit("message:sent", &Value::Object(sent));

    // ÉTAPE 4 : écriture en base en arrière-plan
    let c2 = c.clone();
    let (data2, recipient2) = (data.clone(), recipient_id.clone());
    tokio::spawn(async move {
        let app = c2.app.clone();
        let mut body = Map::new();
        body.insert("id".into(), json!(message_id));
        body.insert("conversationId".into(), json!(conversation_id));
        body.insert("content".into(), json!(content));
        body.insert("senderId".into(), json!(c2.user_id));
        if let Some(sc) = data2.get("senderContent") {
            body.insert("senderContent".into(), sc.clone());
        }
        if let Some(e) = data2.get("e2eeType") {
            body.insert("e2eeType".into(), e.clone());
        }
        if let Some(r) = data2.get("replyToId") {
            body.insert("replyToId".into(), r.clone());
        }
        match app.svc.messages_create_message(Value::Object(body)).await {
            Ok(message) => after_message_saved(&c2, &data2, &conversation_id, &message_id, &content, recipient2.as_deref(), &message).await,
            Err(e) => {
                error!("Échec écriture DB du message {message_id}: {}", e.message);
                // Pas de `err.message` au client : il contenait le corps brut de la réponse du microservice.
                let _ = c2.socket.emit("message:failed", &json!({ "messageId": message_id, "error": "Échec de la sauvegarde — veuillez réessayer" }));
            }
        }
    });
}

async fn after_message_saved(c: &Arc<SockCtx>, data: &Value, conversation_id: &str, message_id: &str, content: &str, recipient: Option<&str>, message: &Value) {
    let app = &c.app;
    // Suppression différée : relancée maintenant que le message est en base.
    let pending = c.pending_deletions.lock().remove(message_id);
    if let Some(delete_user) = pending {
        let (a, mid) = (app.clone(), message_id.to_string());
        tokio::spawn(async move {
            let _ = a.svc.messages_delete_message(&mid, &delete_user).await;
        });
    }
    // Archive DM si quota atteint
    if let Some(ev) = message.get("archiveEvent").filter(|v| truthy(Some(v))) {
        c.to_room(&format!("conversation:{conversation_id}"), "DM_ARCHIVE_PUSH", ev.clone()).await;
    }
    let sender_name = c.display_name();
    // Ping hors ligne : stocké en DB ET Redis pour persistance
    if let Some(rid) = recipient {
        if let Ok(false) = app.redis.is_user_online(rid).await {
            let _ = app.redis.add_pending_ping(rid, conversation_id, &sender_name).await;
            let _ = app.svc.messages_save_notification(rid, conversation_id, &sender_name, None, None, None).await;
        }
    }
    // Mentions (@username → mentionedUserIds), limitées aux participants et plafonnées
    let mut requested: Vec<String> = vec![];
    if let Some(list) = data.get("mentionedUserIds").and_then(|m| m.as_array()) {
        for id in list.iter().filter(|v| val_is_uuid(v)).filter_map(|v| v.as_str()) {
            if id != c.user_id && !requested.iter().any(|r| r == id) {
                requested.push(id.to_string());
            }
        }
        requested.truncate(MAX_MENTIONS);
    }
    let mut mentioned: Vec<String> = vec![];
    if !requested.is_empty() {
        if let Some(rid) = recipient {
            mentioned = requested.into_iter().filter(|id| id == rid).collect();
        } else {
            let result = app.svc.messages_get_participants(conversation_id).await.ok();
            let allowed: std::collections::HashSet<String> = result
                .as_ref()
                .and_then(|r| r.get("participants").and_then(|p| p.as_array()).or_else(|| r.as_array()))
                .map(|a| a.iter().map(|p| js_string(p.get("userId"))).collect())
                .unwrap_or_default();
            mentioned = requested.into_iter().filter(|id| allowed.contains(id)).collect();
        }
    }
    let e2ee_set = truthy(data.get("e2eeType"));
    for mid in mentioned {
        let prev = if e2ee_set { String::new() } else { substring80(content) };
        let payload = json!({
            "conversationId": conversation_id, "senderId": c.user_id, "senderName": sender_name, "senderAvatar": c.avatar(),
            "preview": prev, "notificationType": "mention",
        });
        match app.redis.is_user_online(&mid).await {
            Ok(true) => c.to_room(&format!("user:{mid}"), "MENTION_NOTIFY", payload).await,
            Ok(false) => {
                let _ = app.redis.add_pending_ping(&mid, conversation_id, &sender_name).await;
                let _ = app.svc.messages_save_notification(&mid, conversation_id, &sender_name, Some(&c.user_id), Some("mention"), None).await;
                let body = if prev.is_empty() { "Nouvelle mention".to_string() } else { prev };
                app.svc
                    .users_send_push(json!({ "userId": mid, "title": format!("{sender_name} vous a mentionné"), "body": body, "url": "/channels/me", "type": "mention", "conversationKey": conversation_id }))
                    .await;
            }
            Err(_) => {}
        }
    }
}

async fn message_edit(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let mid = data.get("messageId").cloned().unwrap_or(Value::Null);
    let emit_err = |code: Value| {
        let _ = c.socket.emit("message:edit-error", &json!({ "messageId": mid, "error": code }));
    };
    let r: Result<(), String> = async {
        if !app.ws_limits.check_message_rate(Some(&app.redis.raw()), &c.user_id).await {
            emit_err(json!("RATE_LIMITED"));
            return Ok(());
        }
        let v = validate_message_content(field(&data, "content"), &Value::Null, field(&data, "e2eeType")).map_err(|e| e.to_string())?;
        let sender_content = data.get("senderContent").and_then(|s| s.as_str());
        let e2ee = data.get("e2eeType").and_then(|e| e.as_f64()).map(|n| n as i64);
        let updated = app.svc.messages_update_message(&js_string(data.get("messageId")), &v.content, &c.user_id, sender_content, e2ee).await.map_err(|e| e.message)?;
        if updated.is_null() || !truthy(Some(&updated)) {
            emit_err(json!("Message non trouvé ou non autorisé"));
            return Ok(());
        }
        let conv = updated.get("conversationId").cloned().unwrap_or(Value::Null);
        let pick = |k: &str, fallback: Option<&Value>| -> Value { updated.get(k).filter(|v| !v.is_null()).cloned().or_else(|| fallback.cloned()).unwrap_or(Value::Null) };
        let mut body = Map::new();
        body.insert("messageId".into(), updated.get("id").cloned().unwrap_or(Value::Null));
        body.insert("conversationId".into(), conv.clone());
        body.insert("senderId".into(), pick("senderId", Some(&json!(c.user_id))));
        body.insert("content".into(), updated.get("content").cloned().unwrap_or(Value::Null));
        if let v @ (Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Object(_) | Value::Array(_)) = pick("senderContent", data.get("senderContent")) {
            body.insert("senderContent".into(), v);
        }
        if let v @ (Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Object(_) | Value::Array(_)) = pick("e2eeType", data.get("e2eeType")) {
            body.insert("e2eeType".into(), v);
        }
        if let Some(u) = updated.get("updatedAt") {
            body.insert("updatedAt".into(), u.clone());
        }
        body.insert("isEdited".into(), json!(true));
        let _ = app.io().to(format!("conversation:{}", js_string(Some(&conv)))).emit("message:edited", &Value::Object(body)).await;
        Ok(())
    }
    .await;
    if let Err(m) = r {
        error!("Erreur édition message: {m}");
        let _ = c.socket.emit("message:edit-error", &json!({ "messageId": mid, "error": m }));
    }
}

async fn message_delete(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let conv = data.get("conversationId").filter(|v| truthy(Some(v)));
    // La room venait du client : on ne doit pas faire disparaître un message chez des tiers.
    if let Some(cv) = conv {
        if !has_conversation_access(&app, &c.user_id, cv).await {
            let _ = c.socket.emit("message:error", &json!({ "error": "FORBIDDEN" }));
            return;
        }
    }
    let room = conv.map(|cv| format!("conversation:{}", js_string(Some(cv)))).unwrap_or_else(|| format!("user:{}", c.user_id));
    let mid = js_string(data.get("messageId"));
    if let Err(e) = app.svc.messages_delete_message(&mid, &c.user_id).await {
        if e.status == Some(404) {
            // Message pas encore en base (écriture en cours) — différer.
            c.pending_deletions.lock().insert(mid.clone(), c.user_id.clone());
            info!("Suppression différée (message pas encore en base) {mid}");
        } else {
            warn!("Suppression échouée, nouvel essai planifié {mid}: {}", e.message);
            let (a, m, u) = (app.clone(), mid.clone(), c.user_id.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if let Err(e) = a.svc.messages_delete_message(&m, &u).await {
                    error!("Nouvel essai de suppression échoué {m}: {}", e.message);
                }
            });
        }
    }
    // Toujours émettre de façon optimiste — le client a déjà retiré le message localement.
    let body = json!({ "messageId": data.get("messageId"), "conversationId": data.get("conversationId") });
    let _ = app.io().to(room).emit("message:deleted", &body).await;
    let _ = c.socket.emit("message:deleted", &body);
}

async fn conversation_join(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let conversation_id = data.get("conversationId").filter(|v| truthy(Some(v)));
    let recipient_id = data.get("recipientId").filter(|v| truthy(Some(v)));
    let err = |m: &str| {
        let _ = c.socket.emit("conversation:join:error", &json!({ "error": m }));
    };
    let room_id: Option<String> = match (conversation_id, recipient_id) {
        (None, Some(r)) => {
            // Chemin DM sûr : le room ID est dérivé de userId + recipientId
            if !val_is_uuid(r) {
                err("Destinataire invalide");
                return;
            }
            Some(dm_id_for(&c.user_id, r.as_str().unwrap()))
        }
        (Some(cid), _) => {
            let s = cid.as_str().unwrap_or("");
            if s.starts_with("dm_") {
                if dm_peer(cid, &c.user_id).is_none() {
                    err("Accès non autorisé");
                    return;
                }
                Some(s.to_string())
            } else if !val_is_id(cid) {
                err("Accès non autorisé");
                return;
            } else {
                // Conversation UUID — vérifier via le service messages
                if !app.svc.messages_is_participant(s, &c.user_id).await {
                    err("Accès non autorisé");
                    return;
                }
                Some(s.to_string())
            }
        }
        _ => None,
    };
    let Some(room_id) = room_id else { return };
    let _ = c.socket.join(format!("conversation:{room_id}"));
    let _ = c.socket.emit("conversation:joined", &json!({ "conversationId": room_id }));
    // Informer l'utilisateur d'un appel de groupe actif en cours
    if !room_id.starts_with("dm_") {
        if let Ok(Some(raw)) = app.redis.get(&format!("call:active:group:{room_id}")).await {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                let _ = c.socket.emit("CALL_ACTIVE", &v);
            }
        }
    }
}

// ── Récupération d'historique E2EE entre les deux participants d'un MP ──────

const E2EE_HISTORY_TTL: u64 = 120;

async fn e2ee_history_request(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = &c.app;
    let conv = field(&data, "conversationId");
    let Some(peer) = dm_peer(conv, &c.user_id) else { return };
    if field(&data, "recipientId").as_str() != Some(peer.as_str()) {
        return;
    }
    if crate::nodes::is_dm_blocked(app, &c.user_id, &peer).await {
        return;
    }
    let online = app.redis.is_user_online(&peer).await.unwrap_or(false);
    if !online {
        let _ = c.socket.emit("e2ee:history-error", &json!({ "reason": "recipient_offline", "conversationId": conv }));
        return;
    }
    let cid = js_string(Some(conv));
    let _ = app.redis.set(&format!("e2eehist:{cid}:{}:{peer}", c.user_id), "1", Some(E2EE_HISTORY_TTL)).await;
    info!("[E2EE] History request from {} to {peer} for {cid}", c.user_id);
    let _ = app.io().to(format!("user:{peer}")).emit("e2ee:history-request", &json!({ "requesterId": c.user_id, "conversationId": conv })).await;
}

async fn e2ee_history_response(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = &c.app;
    let conv = field(&data, "conversationId");
    let Some(peer) = dm_peer(conv, &c.user_id) else { return };
    let Some(messages) = field(&data, "messages").as_array() else { return };
    if field(&data, "requesterId").as_str() != Some(peer.as_str()) {
        return;
    }
    // La demande doit exister et n'est honorée qu'une fois.
    let cid = js_string(Some(conv));
    let key = format!("e2eehist:{cid}:{peer}:{}", c.user_id);
    if !matches!(app.redis.get(&key).await, Ok(Some(_))) {
        warn!("[E2EE] Réponse d'historique non sollicitée de {} vers {peer} — ignorée", c.user_id);
        return;
    }
    let _ = app.redis.del(&key).await;
    // 500 messages au plus par réponse
    let msgs: Vec<Value> = messages
        .iter()
        .take(500)
        .map(|m| {
            let id = m.get("id").and_then(|v| v.as_str());
            let content = m.get("content").and_then(|v| v.as_str()).map(|s| String::from_utf16_lossy(&s.encode_utf16().take(131_072).collect::<Vec<_>>())).unwrap_or_default();
            let sender = match m.get("senderId").and_then(|v| v.as_str()) {
                Some(s) if s == c.user_id || s == peer => s.to_string(),
                _ => c.user_id.clone(),
            };
            (id.map(str::to_string), json!({ "id": id, "content": content, "senderId": sender, "createdAt": m.get("createdAt").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null) }))
        })
        .filter(|(id, _)| id.is_some())
        .map(|(_, v)| v)
        .collect();
    info!("[E2EE] History response from {} to {peer}: {} messages", c.user_id, msgs.len());
    let _ = app.io().to(format!("user:{peer}")).emit("e2ee:history-response", &json!({ "responderId": c.user_id, "conversationId": conv, "messages": msgs })).await;
}

// ── Archivage P2P ───────────────────────────────────────────────────────────

async fn dm_archive_request(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: HResult = async {
        let conversation_id = field(&data, "conversationId");
        let message_id = field(&data, "messageId");
        let limit = {
            let n = crate::perms::js_number(field(&data, "limit"));
            let n = if n.is_finite() && n != 0.0 { n } else { 50.0 };
            n.clamp(1.0, 200.0)
        };
        // Sans contrôle, n'importe quel compte diffusait une demande dans la room d'une conversation tierce.
        if !has_conversation_access(&app, &c.user_id, conversation_id).await {
            return Err("FORBIDDEN".into());
        }
        if !message_id.is_null() && !val_is_id(message_id) {
            return Err("INVALID_ID".into());
        }
        let request_id = Uuid::new_v4().to_string();
        // Seule une réponse à CETTE demande, pour CETTE conversation, sera relayée — et uniquement à son auteur.
        let _ = app.redis.set(&format!("dmarchreq:{request_id}"), &json!({ "requesterId": c.user_id, "conversationId": conversation_id }).to_string(), Some(60)).await;

        // 1. Cache Redis
        if truthy(Some(message_id)) {
            let cached = app.svc.messages_get_cached_archived_message(message_id.as_str().unwrap_or(""), c.token.as_deref()).await?;
            if cached.get("source").and_then(|s| s.as_str()) == Some("cache") && truthy(cached.get("message")) {
                c.emit_event(
                    "DM_ARCHIVE_RESPONSE",
                    json!({ "conversationId": conversation_id, "messages": [cached["message"]], "fromPeerId": "server_cache", "requestId": request_id }),
                );
                return Ok(());
            }
        }
        // 2. Pas en cache → demander aux pairs en ligne de cette conversation
        c.to_room_others(
            &format!("conversation:{}", js_string(Some(conversation_id))),
            "DM_ARCHIVE_PEER_REQUEST",
            json!({
                "requestId": request_id, "conversationId": conversation_id, "messageId": data.get("messageId"),
                "beforeDate": data.get("beforeDate"), "limit": limit, "requesterId": c.user_id,
            }),
        )
        .await;

        // Délai : si aucun pair n'a répondu en 10 s, notifier le client
        let (c2, rid, cv) = (c.clone(), request_id.clone(), conversation_id.clone());
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            c2.pending_archive.lock().remove(&rid);
            if matches!(c2.app.redis.get(&format!("dmarch:{rid}")).await, Ok(Some(_))) {
                return; // un pair a déjà fourni les messages
            }
            c2.emit_event(
                "DM_ARCHIVE_RESPONSE",
                json!({ "conversationId": cv, "messages": [], "fromPeerId": "timeout", "requestId": rid, "error": "Aucun peer en ligne avec ce message" }),
            );
        });
        c.pending_archive.lock().insert(request_id, handle.abort_handle());
        info!("🔍 Demande archive DM: {} cherche msg dans {}", c.user_id, js_string(Some(conversation_id)));
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("DM_ARCHIVE_ERROR", &m);
    }
}

async fn dm_archive_peer_response(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let request_id = field(&data, "requestId");
    // La réponse doit correspondre à une demande en attente : demandeur et conversation viennent de cette demande.
    if !val_is_uuid(request_id) {
        return;
    }
    let rid = request_id.as_str().unwrap().to_string();
    let Ok(Some(raw)) = app.redis.get(&format!("dmarchreq:{rid}")).await else { return };
    let Ok(pending) = serde_json::from_str::<Value>(&raw) else { return };
    let requester = js_string(pending.get("requesterId"));
    let conversation_id = pending.get("conversationId").cloned().unwrap_or(Value::Null);
    if requester == c.user_id || !has_conversation_access(&app, &c.user_id, &conversation_id).await {
        warn!("DM_ARCHIVE_PEER_RESPONSE rejeté: {} n'est pas participant de {}", c.user_id, js_string(Some(&conversation_id)));
        return;
    }
    // Le pair qui répond n'est pas une source de vérité : le senderId est forcé sur son identité authentifiée.
    let sanitized: Vec<Value> = field(&data, "messages")
        .as_array()
        .map(|a| {
            a.iter()
                .take(200)
                .filter_map(|m| {
                    let id = m.get("id").and_then(|v| v.as_str())?;
                    let content = m.get("content").and_then(|v| v.as_str()).map(|s| String::from_utf16_lossy(&s.encode_utf16().take(131_072).collect::<Vec<_>>())).unwrap_or_default();
                    Some(json!({ "id": id, "conversationId": conversation_id, "senderId": c.user_id, "content": content, "createdAt": m.get("createdAt").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null) }))
                })
                .collect()
        })
        .unwrap_or_default();
    if !sanitized.is_empty() {
        if let Err(e) = app.svc.messages_cache_archived_messages(Value::Array(sanitized.clone())).await {
            warn!("Erreur cache messages archivés: {}", e.message);
        }
    }
    // Demande servie : le repli « timeout » de l'autre socket (éventuellement une autre instance) le lira.
    let _ = app.redis.set(&format!("dmarch:{rid}"), "1", Some(30)).await;
    let n = sanitized.len();
    let ev = "DM_ARCHIVE_RESPONSE";
    let _ = app
        .io()
        .to(format!("user:{requester}"))
        .emit(ev, &event(ev, json!({ "conversationId": conversation_id, "messages": sanitized, "fromPeerId": c.user_id, "requestId": rid })))
        .await;
    info!("📨 Peer {} a fourni {n} msg archivés pour {requester}", c.user_id);
}

#[allow(dead_code)]
fn _keep(_: &str) -> bool {
    is_id("") || is_uuid("") || s_of(&Value::Null).is_none()
}
