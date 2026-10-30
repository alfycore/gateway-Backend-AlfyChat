//! Handlers divers : rejoindre un salon, présence, profil, groupes de discussion, vocal de serveur, déconnexion.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use super::calls::node_owns_channel;
use super::helpers::*;
use super::messages::HErr;
use super::{ch_room, on, Ack, SockCtx};
use crate::http::routes_misc::{js_string, truthy};
use crate::perms::{CONNECT, MANAGE_CHANNELS, MOVE_MEMBERS, MUTE_MEMBERS, READ};
use crate::redis_client::PresencePatch;
use crate::state::VoiceParticipant;
use crate::validation::{field, validate_group_input, validate_profile};

fn respond(ack: &mut Ack, v: Value) {
    ack.send(&v);
}

pub fn register(c: &Arc<SockCtx>) {
    on(c, "CHANNEL_JOIN", channel_join);
    on(c, "CHANNEL_LEAVE", |c, data, _| async move {
        let cid = field(&data, "channelId");
        if !val_is_id(cid) {
            return;
        }
        let cid = cid.as_str().unwrap();
        if let Some(sid) = field(&data, "serverId").as_str().filter(|s| crate::http::routes_misc::is_id(s)) {
            let _ = c.socket.leave(ch_room(sid, cid));
            return;
        }
        let suffix = format!(":{cid}");
        for room in c.socket.rooms() {
            if room.starts_with("ch:") && room.ends_with(&suffix) {
                let _ = c.socket.leave(room.to_string());
            }
        }
    });
    on(c, "PRESENCE_UPDATE", presence_update);
    on(c, "PROFILE_UPDATE", profile_update);
    on(c, "CHANGE_USERNAME", change_username);
    on(c, "GROUP_CREATE", group_create);
    on(c, "GROUP_UPDATE", group_update);
    on(c, "GROUP_LEAVE", group_leave);
    on(c, "GROUP_DELETE", group_delete);
    on(c, "VOICE_JOIN", voice_join);
    on(c, "VOICE_LEAVE", |c, _data, _| async move {
        leave_voice_channel(&c.app, &c.user_id, &c.socket.id.to_string()).await;
    });
    on(c, "VOICE_STATE_UPDATE", voice_state_update);
    on(c, "VOICE_SPEAKING", voice_speaking);
    on(c, "VOICE_CHANNEL_STATUS", voice_channel_status);
    on(c, "VOICE_MODERATE", voice_moderate);
    for (ev, key) in [("VOICE_OFFER", "offer"), ("VOICE_ANSWER", "answer"), ("VOICE_ICE_CANDIDATE", "candidate")] {
        on(c, ev, move |c, data, _| async move {
            // L'émetteur doit lui-même être dans le salon : sinon n'importe quelle socket injecte de la signalisation.
            let channel_id = js_string(data.get("channelId"));
            let target_socket = {
                let v = c.app.conns.voice.lock();
                let Some(parts) = v.channels.get(&channel_id) else { return };
                if !parts.contains_key(&c.user_id) {
                    return;
                }
                let Some(t) = parts.get(&js_string(data.get("targetUserId"))) else { return };
                t.socket_id.clone()
            };
            let body = json!({ "channelId": data.get("channelId"), "fromUserId": c.user_id, key: data.get(key) });
            let _ = c.io().to(target_socket).emit(ev, &body).await;
        });
    }
}

async fn channel_join(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = &c.app;
    let (cid, sid) = (field(&data, "channelId"), field(&data, "serverId"));
    if !val_is_id(cid) || !val_is_id(sid) {
        return;
    }
    let (channel_id, server_id) = (cid.as_str().unwrap(), sid.as_str().unwrap());
    // Pour un serveur avec node connecté, la membership est gérée localement par le node.
    let is_member = if app.has_node(server_id) {
        match crate::nodes::forward_to_node(app, server_id, "MEMBER_CHECK", &json!({ "userId": c.user_id }), 15_000).await {
            Ok(r) => r.get("isMember") == Some(&Value::Bool(true)),
            Err(e) => {
                warn!("CHANNEL_JOIN permission check error: {e}");
                return;
            }
        }
    } else {
        match app.svc.servers_is_member(server_id, &c.user_id).await {
            Ok(m) => m,
            Err(e) => {
                warn!("CHANNEL_JOIN permission check error: {}", e.message);
                return;
            }
        }
    };
    if !is_member {
        let _ = c.socket.emit("error", &json!({ "message": "Accès refusé — vous n'êtes pas membre de ce serveur" }));
        return;
    }
    // Le salon doit appartenir à CE serveur…
    if !node_owns_channel(&c, server_id, channel_id).await {
        let _ = c.socket.emit("error", &json!({ "message": "Salon introuvable dans ce serveur" }));
        return;
    }
    // …et être visible pour ce membre (salon privé).
    if !check_channel_permission(app, &c.user_id, server_id, channel_id, READ).await {
        let _ = c.socket.emit("error", &json!({ "message": "Accès refusé à ce salon" }));
        return;
    }
    let _ = c.socket.join(ch_room(server_id, channel_id));
    info!("{} rejoint {}", c.user_id, ch_room(server_id, channel_id));
}

// ── Présence ────────────────────────────────────────────────────────────────

fn clip(v: &Value, n: usize) -> Option<String> {
    if !truthy(Some(v)) {
        return None;
    }
    let t = js_string(Some(v));
    let t = crate::validation::js_trim(&t);
    let cut = String::from_utf16_lossy(&t.encode_utf16().take(n).collect::<Vec<_>>());
    Some(cut).filter(|s| !s.is_empty())
}

async fn presence_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let status = field(&data, "status").as_str().filter(|s| ["online", "idle", "dnd", "invisible"].contains(s));
        let Some(status) = status else { return Ok(()) };
        let emoji = clip(field(&data, "emoji"), 2);
        let text = if truthy(data.get("text")) { clip(field(&data, "text"), 100) } else if truthy(data.get("customStatus")) { clip(field(&data, "customStatus"), 100) } else { None };
        let (emoji_v, text_v) = (emoji.clone().map(|e| json!(e)), text.clone().map(|t| json!(t)));

        // `auto: true` → transition automatique : le choix explicite (chosenStatus) et la DB ne sont pas touchés.
        if data.get("auto") == Some(&Value::Bool(true)) {
            let patch = PresencePatch {
                status: Some(status.to_string()),
                emoji: Some(emoji.clone()),
                text: Some(text.clone()),
                last_activity: Some(crate::redis_client::now_ms()),
                auto_idle: Some(status == "idle"),
                ..Default::default()
            };
            app.redis.set_presence(&c.user_id, patch).await.map_err(|e| HErr(e.to_string()))?;
            let friends = app.svc.friends_get_friends(&c.user_id).await;
            super::presence::broadcast_presence_update(&app, &c.user_id, status, &friends, text_v.as_ref(), emoji_v.as_ref()).await;
            return Ok(());
        }

        // Choix explicite de l'utilisateur → met à jour le statut choisi + DB.
        let patch = PresencePatch {
            status: Some(status.to_string()),
            chosen_status: Some(status.to_string()),
            emoji: Some(emoji.clone()),
            text: Some(text.clone()),
            last_activity: Some(crate::redis_client::now_ms()),
            auto_idle: Some(false),
        };
        app.redis.set_presence(&c.user_id, patch).await.map_err(|e| HErr(e.to_string()))?;
        // Écriture en base : on n'attend pas
        let (a, uid, st, tx, em) = (app.clone(), c.user_id.clone(), status.to_string(), text.clone(), emoji.clone());
        tokio::spawn(async move {
            if let Err(e) = a.svc.users_update_status(&uid, &st, Some(tx.as_deref()), Some(em.as_deref())).await {
                warn!("updateStatus DB failed for {uid}: {}", e.message);
            }
        });
        let friends = app.svc.friends_get_friends(&c.user_id).await;
        super::presence::broadcast_presence_update(&app, &c.user_id, status, &friends, text_v.as_ref(), emoji_v.as_ref()).await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("PRESENCE_ERROR", &m);
    }
}

// ── Profil ──────────────────────────────────────────────────────────────────

fn set_local_user(c: &SockCtx, patch: &Map<String, Value>) {
    if let Some(cl) = c.app.conns.clients.lock().get_mut(&c.socket.id.to_string()) {
        let mut u = cl.user.as_object().cloned().unwrap_or_default();
        for (k, v) in patch {
            u.insert(k.clone(), v.clone());
        }
        cl.user = Value::Object(u);
    }
}

async fn notify_friends_and_servers(c: &Arc<SockCtx>, payload: Value, warn_friends: &str, warn_servers: &str) {
    let friends = c.app.svc.friends_get_friends(&c.user_id).await;
    if friends.is_array() {
        for f in friends.as_array().unwrap() {
            let fid = ["friendId", "id"].iter().find_map(|k| f.get(*k).filter(|v| truthy(Some(v))).map(|v| js_string(Some(v)))).unwrap_or_default();
            c.to_room(&format!("user:{fid}"), "PROFILE_UPDATE", payload.clone()).await;
        }
    } else {
        warn!("{warn_friends}");
    }
    for room in c.socket.rooms() {
        if room.starts_with("server:") {
            c.to_room(&room, "PROFILE_UPDATE", payload.clone()).await;
        }
    }
    let _ = warn_servers;
}

async fn profile_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let r: Result<(), HErr> = async {
        let clean = validate_profile(&data)?;
        let result = c.app.svc.users_update_profile(&c.user_id, Value::Object(clean.clone())).await?;
        let updated = result.get("data").filter(|v| truthy(Some(v))).cloned().unwrap_or_else(|| {
            let mut m = Map::new();
            m.insert("userId".into(), json!(c.user_id));
            for (k, v) in &clean {
                m.insert(k.clone(), v.clone());
            }
            Value::Object(m)
        });
        set_local_user(&c, &clean);
        c.emit_event("PROFILE_UPDATE", updated);
        let mut p = Map::new();
        p.insert("userId".into(), json!(c.user_id));
        for (k, v) in &clean {
            p.insert(k.clone(), v.clone());
        }
        notify_friends_and_servers(&c, Value::Object(p), "Erreur notification profil amis", "Erreur notification profil serveurs").await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("PROFILE_UPDATE_ERROR", &m);
    }
}

/// Changement de nom d'utilisateur : le nouveau nom est diffusé comme un PROFILE_UPDATE aux amis et serveurs.
async fn change_username(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let r: Result<(), HErr> = async {
        let (nu, pw) = (field(&data, "newUsername"), field(&data, "password"));
        if !truthy(Some(nu)) || !truthy(Some(pw)) {
            let _ = c.socket.emit("CHANGE_USERNAME_ERROR", &json!({ "error": "Données manquantes" }));
            return Ok(());
        }
        let new_username = js_string(Some(nu));
        let result = c.app.svc.users_change_username(&c.user_id, &new_username, &js_string(Some(pw)), c.token.as_deref()).await?;
        if !truthy(result.get("success")) {
            let e = result.get("error").filter(|v| truthy(Some(v))).cloned().unwrap_or(json!("Erreur lors du changement"));
            let _ = c.socket.emit("CHANGE_USERNAME_ERROR", &json!({ "error": e }));
            return Ok(());
        }
        let mut patch = Map::new();
        patch.insert("username".into(), json!(new_username));
        set_local_user(&c, &patch);
        let _ = c.socket.emit("CHANGE_USERNAME_SUCCESS", &json!({ "username": new_username }));
        notify_friends_and_servers(&c, json!({ "userId": c.user_id, "username": new_username }), "Erreur notif username amis", "Erreur notif username serveurs").await;
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("CHANGE_USERNAME_ERROR", &m);
    }
}

// ── Groupes de discussion ───────────────────────────────────────────────────

async fn group_create(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let clean = validate_group_input(&data)?;
        let requested: Vec<String> = clean
            .get("participantIds")
            .or_else(|| data.get("participantIds"))
            .and_then(|p| p.as_array())
            .map(|a| a.iter().map(|x| js_string(Some(x))).collect())
            .unwrap_or_default();
        let is_open = clean.get("isOpen") != Some(&Value::Bool(false));
        let mut all = vec![c.user_id.clone()];
        all.extend(requested.iter().filter(|id| **id != c.user_id).cloned());

        let mut rest = Map::new();
        rest.insert("type".into(), json!("group"));
        if let Some(n) = clean.get("name") {
            rest.insert("name".into(), n.clone());
        }
        if let Some(a) = clean.get("avatarUrl") {
            rest.insert("avatarUrl".into(), a.clone());
        }
        rest.insert("isOpen".into(), json!(is_open));
        let group = app.svc.messages_create_conversation(rest, json!(all), &c.user_id).await?;
        let group_id = js_string(group.get("id"));
        let _ = c.socket.join(format!("conversation:{group_id}"));

        // Notifier et faire rejoindre chaque participant RÉELLEMENT ajouté.
        let created: Vec<String> = if let Some(ids) = group.get("participantIds").and_then(|p| p.as_array()) {
            ids.iter().map(|x| js_string(Some(x))).collect()
        } else if let Some(ps) = group.get("participants").and_then(|p| p.as_array()) {
            ps.iter().filter_map(|p| ["userId", "id"].iter().find_map(|k| p.get(*k).filter(|v| truthy(Some(v))).map(|v| js_string(Some(v))))).collect()
        } else {
            vec![]
        };
        for pid in created.iter().filter(|id| **id != c.user_id && requested.contains(id)) {
            c.to_room(&format!("user:{pid}"), "GROUP_CREATE", group.clone()).await;
            // Faire rejoindre les participants connectés à la room
            let _ = app.io().within(format!("user:{pid}")).join(format!("conversation:{group_id}")).await;
        }
        c.emit_event("GROUP_CREATE", group.clone());
        info!("Groupe créé: {group_id} par {} avec {} participants", c.user_id, all.len());
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("GROUP_CREATE_ERROR", &m);
    }
}

async fn group_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let group_id = js_string(data.get("groupId"));
        let clean = validate_group_input(&data)?;
        let (name, avatar, is_open) = (clean.get("name").cloned(), clean.get("avatarUrl").cloned(), clean.get("isOpen").cloned());
        let add: Vec<String> = clean.get("addParticipants").and_then(|a| a.as_array()).map(|a| a.iter().map(|x| js_string(Some(x))).collect()).unwrap_or_default();
        let remove: Vec<String> = clean.get("removeParticipants").and_then(|a| a.as_array()).map(|a| a.iter().map(|x| js_string(Some(x))).collect()).unwrap_or_default();

        if name.is_some() || avatar.is_some() || is_open.is_some() {
            let body = crate::svc::obj(vec![("name", name.clone()), ("avatarUrl", avatar.clone()), ("isOpen", is_open.clone())]);
            app.svc.messages_update_conversation(&group_id, body, c.token.as_deref()).await?;
        }
        for pid in &add {
            app.svc.messages_add_participant(&group_id, pid, c.token.as_deref()).await?;
            invalidate_conversation_access(&app, &group_id, Some(pid)).await;
            c.to_room(&format!("user:{pid}"), "GROUP_MEMBER_ADD", json!({ "groupId": group_id, "userId": pid, "addedBy": c.user_id })).await;
            let _ = app.io().within(format!("user:{pid}")).join(format!("conversation:{group_id}")).await;
        }
        for pid in &remove {
            app.svc.messages_remove_participant(&group_id, pid, c.token.as_deref()).await?;
            invalidate_conversation_access(&app, &group_id, Some(pid)).await;
            c.to_room(&format!("user:{pid}"), "GROUP_MEMBER_REMOVE", json!({ "groupId": group_id, "userId": pid, "removedBy": c.user_id })).await;
            let _ = app.io().within(format!("user:{pid}")).leave(format!("conversation:{group_id}")).await;
        }
        let p = crate::svc::obj(vec![
            ("groupId", Some(json!(group_id))), ("name", name), ("avatarUrl", avatar), ("isOpen", is_open),
            ("addParticipants", clean.get("addParticipants").cloned()), ("removeParticipants", clean.get("removeParticipants").cloned()),
            ("updatedBy", Some(json!(c.user_id))),
        ]);
        c.to_room(&format!("conversation:{group_id}"), "GROUP_UPDATE", p).await;
        info!("Groupe mis à jour: {group_id} par {}", c.user_id);
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("GROUP_UPDATE_ERROR", &m);
    }
}

async fn group_leave(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let group_id = js_string(data.get("groupId"));
        // Le service gère le transfert de propriété
        let result = app.svc.messages_leave_conversation(&group_id, &c.user_id, c.token.as_deref()).await?;
        invalidate_conversation_access(&app, &group_id, Some(&c.user_id)).await;
        let _ = c.socket.leave(format!("conversation:{group_id}"));

        let mut payload = Map::new();
        payload.insert("groupId".into(), json!(group_id));
        payload.insert("userId".into(), json!(c.user_id));
        if let Some(o) = result.as_object() {
            for (k, v) in o {
                payload.insert(k.clone(), v.clone());
            }
        }
        c.emit_event("GROUP_LEAVE", Value::Object(payload));
        if !truthy(result.get("deleted")) {
            c.to_room(
                &format!("conversation:{group_id}"),
                "GROUP_UPDATE",
                crate::svc::obj(vec![
                    ("groupId", Some(json!(group_id))), ("removeParticipants", Some(json!([c.user_id]))),
                    ("newOwnerId", result.get("newOwnerId").cloned()), ("leftBy", Some(json!(c.user_id))),
                ]),
            )
            .await;
        } else {
            c.to_room(&format!("conversation:{group_id}"), "GROUP_DELETE", json!({ "groupId": group_id })).await;
        }
        info!("Utilisateur {} a quitté le groupe {group_id}", c.user_id);
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("GROUP_LEAVE_ERROR", &m);
    }
}

async fn group_delete(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let r: Result<(), HErr> = async {
        let group_id = js_string(data.get("groupId"));
        // Supprimer D'ABORD (le service refuse si l'appelant n'est pas propriétaire), notifier ensuite.
        app.svc.messages_delete_conversation(&group_id, c.token.as_deref()).await?;
        c.to_room(&format!("conversation:{group_id}"), "GROUP_DELETE", json!({ "groupId": group_id, "deletedBy": c.user_id })).await;
        invalidate_conversation_access(&app, &group_id, None).await;
        info!("Groupe supprimé: {group_id} par {}", c.user_id);
        Ok(())
    }
    .await;
    if let Err(HErr(m)) = r {
        c.emit_error("GROUP_DELETE_ERROR", &m);
    }
}

// ── Vocal de serveur ────────────────────────────────────────────────────────

async fn voice_join(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
    if !val_is_id(sid) || !val_is_id(cid) {
        return;
    }
    let (server_id, channel_id) = (sid.as_str().unwrap().to_string(), cid.as_str().unwrap().to_string());

    // L'utilisateur doit être membre du serveur
    match app.svc.servers_is_member(&server_id, &c.user_id).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = c.socket.emit("error", &json!({ "message": "Accès refusé — vous n'êtes pas membre de ce serveur" }));
            return;
        }
        Err(e) => {
            warn!("VOICE_JOIN permission check error: {}", e.message);
            return;
        }
    }

    // Le salon appartient BIEN à ce serveur et il est vocal (les serveurs auto-hébergés : au moins appartenir au node).
    if app.has_node(&server_id) {
        if !node_owns_channel(&c, &server_id, &channel_id).await {
            let _ = c.socket.emit("error", &json!({ "message": "Salon introuvable dans ce serveur" }));
            return;
        }
    } else {
        match app.svc.servers_get_channels(&server_id, None).await {
            Ok(chs) => {
                let target = chs.as_array().and_then(|a| a.iter().find(|ch| ["id", "channelId"].iter().find_map(|k| ch.get(*k).filter(|v| !v.is_null())).and_then(|v| v.as_str()) == Some(channel_id.as_str())));
                let Some(target) = target else {
                    let _ = c.socket.emit("error", &json!({ "message": "Salon introuvable dans ce serveur" }));
                    return;
                };
                let t = target.get("type").and_then(|t| t.as_str());
                if t != Some("voice") && t != Some("stage") {
                    let _ = c.socket.emit("error", &json!({ "message": "Ce salon n'est pas un salon vocal" }));
                    return;
                }
            }
            Err(e) => {
                warn!("VOICE_JOIN channel check error: {}", e.message);
                return;
            }
        }
    }

    // Droit de se connecter au salon (surcharges incluses)
    if !check_channel_permission(&app, &c.user_id, &server_id, &channel_id, CONNECT).await {
        let _ = c.socket.emit("VOICE_ERROR", &json!({ "type": "VOICE_ERROR", "payload": { "channelId": channel_id, "error": "PERMISSION_DENIED" } }));
        return;
    }
    // Limite d'utilisateurs : MOVE_MEMBERS passe outre, comme sur Discord
    let meta = get_channel_meta(&app, &server_id, &channel_id).await;
    if let Some(limit) = meta.as_ref().map(|m| m.user_limit).filter(|l| *l > 0) {
        let (n, has_me) = {
            let v = app.conns.voice.lock();
            let ch = v.channels.get(&channel_id);
            (ch.map(|m| m.len()), ch.map(|m| m.contains_key(&c.user_id)).unwrap_or(false))
        };
        if let Some(n) = n {
            if !has_me && n as i64 >= limit && !check_server_permission(&app, &c.user_id, &server_id, MOVE_MEMBERS).await {
                let _ = c.socket.emit("VOICE_ERROR", &json!({ "type": "VOICE_ERROR", "payload": { "channelId": channel_id, "error": "CHANNEL_FULL", "userLimit": limit } }));
                return;
            }
        }
    }

    // Quitter d'abord tout salon vocal existant (y compris depuis un autre onglet)
    let existing = app.conns.voice.lock().user_channel.get(&c.user_id).cloned();
    if let Some(existing) = existing.filter(|e| *e != channel_id) {
        remove_voice_participant(&app, &c.user_id, &existing).await;
    }

    let avatar = c.user_str("avatarUrl").or_else(|| c.user_str("avatar_url")).map(str::to_string);
    let participant = {
        let mut v = app.conns.voice.lock();
        let parts = v.channels.entry(channel_id.clone()).or_default();
        let previous = parts.get(&c.user_id).cloned();
        let p = VoiceParticipant {
            socket_id: c.socket.id.to_string(),
            user_id: c.user_id.clone(),
            username: c.username(),
            display_name: Some(c.display_name()),
            avatar_url: avatar.clone(),
            muted: data.get("muted") == Some(&Value::Bool(true)),
            deafened: data.get("deafened") == Some(&Value::Bool(true)),
            server_id: server_id.clone(),
            video: data.get("video") == Some(&Value::Bool(true)),
            streaming: false,
            server_muted: previous.as_ref().map(|p| p.server_muted).unwrap_or(false),
            server_deafened: previous.as_ref().map(|p| p.server_deafened).unwrap_or(false),
            joined_at: previous.and_then(|p| p.joined_at).or(Some(crate::redis_client::now_ms())),
        };
        parts.insert(c.user_id.clone(), p.clone());
        v.user_channel.insert(c.user_id.clone(), channel_id.clone());
        p
    };

    // Salle de signalisation vocale
    let _ = c.socket.join(format!("voice:{channel_id}"));
    // Tout le serveur sait que l'utilisateur est en vocal
    broadcast_voice_state(&app, &server_id, &channel_id).await;
    // Les participants existants créent la connexion WebRTC vers le nouvel arrivant
    let _ = c.socket.to(format!("voice:{channel_id}")).emit("VOICE_USER_JOINED", &json!({ "channelId": channel_id, "userId": c.user_id, "username": c.username(), "avatarUrl": participant.avatar_url })).await;
    info!("{} joined voice channel {channel_id}", c.username());
}

async fn voice_state_update(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let (server_id, channel_id) = {
        let mut v = app.conns.voice.lock();
        let Some(ch) = v.user_channel.get(&c.user_id).cloned() else { return };
        let Some(p) = v.channels.get_mut(&ch).and_then(|m| m.get_mut(&c.user_id)) else { return };
        if p.socket_id != c.socket.id.to_string() {
            return;
        }
        let b = |k: &str| data.get(k).and_then(|v| v.as_bool());
        if let Some(x) = b("muted") {
            p.muted = x;
        }
        if let Some(x) = b("deafened") {
            p.deafened = x;
        }
        if let Some(x) = b("video") {
            p.video = x;
        }
        if let Some(x) = b("streaming") {
            p.streaming = x;
        }
        (p.server_id.clone(), ch)
    };
    broadcast_voice_state(&app, &server_id, &channel_id).await;
}

/// Anneau vert « parle » : relayé à tout le serveur, sans état ; le débit est borné (120 ms).
async fn voice_speaking(c: Arc<SockCtx>, data: Value, _ack: Ack) {
    let app = c.app.clone();
    let (server_id, channel_id) = {
        let v = app.conns.voice.lock();
        let Some(ch) = v.user_channel.get(&c.user_id).cloned() else { return };
        let Some(p) = v.channels.get(&ch).and_then(|m| m.get(&c.user_id)) else { return };
        if p.socket_id != c.socket.id.to_string() {
            return;
        }
        (p.server_id.clone(), ch)
    };
    let speaking = data.get("speaking") == Some(&Value::Bool(true));
    if speaking {
        let now = crate::redis_client::now_ms();
        let mut last = c.last_speaking.lock();
        if now - *last < 120 {
            return;
        }
        *last = now;
    }
    let _ = c.socket.to(format!("server:{server_id}")).emit("VOICE_SPEAKING", &json!({ "serverId": server_id, "channelId": channel_id, "userId": c.user_id, "speaking": speaking })).await;
}

/// « Définir un statut de salon » — texte libre affiché sous le salon vocal.
async fn voice_channel_status(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let (sid, cid) = (field(&data, "serverId"), field(&data, "channelId"));
    if !val_is_id(sid) || !val_is_id(cid) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let (server_id, channel_id) = (sid.as_str().unwrap().to_string(), cid.as_str().unwrap().to_string());
    let first_server = {
        let v = app.conns.voice.lock();
        match v.channels.get(&channel_id) {
            None => None,
            Some(m) if m.is_empty() => None,
            Some(m) => m.values().next().map(|p| p.server_id.clone()),
        }
    };
    // Éphémère : un salon vide n'a pas de statut.
    let Some(first_server) = first_server else { return respond(&mut ack, json!({ "error": "CHANNEL_EMPTY" })) };
    if first_server != server_id {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let in_channel = app.conns.voice.lock().user_channel.get(&c.user_id).map(|ch| *ch == channel_id).unwrap_or(false);
    if !in_channel && !check_server_permission(&app, &c.user_id, &server_id, MANAGE_CHANNELS).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    let status = field(&data, "status").as_str().map(|s| {
        let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
        String::from_utf16_lossy(&collapsed.encode_utf16().take(100).collect::<Vec<_>>())
    }).unwrap_or_default();
    {
        let mut v = app.conns.voice.lock();
        if status.is_empty() {
            v.status.remove(&channel_id);
        } else {
            v.status.insert(channel_id.clone(), status.clone());
        }
    }
    broadcast_voice_state(&app, &server_id, &channel_id).await;
    respond(&mut ack, json!({ "success": true, "status": status }));
}

/// Modération vocale : rendre muet / sourd, déconnecter, déplacer.
async fn voice_moderate(c: Arc<SockCtx>, data: Value, mut ack: Ack) {
    let app = c.app.clone();
    let (sid, target, action) = (field(&data, "serverId"), field(&data, "targetUserId"), field(&data, "action"));
    let actions = ["mute", "unmute", "deafen", "undeafen", "disconnect", "move"];
    if !val_is_id(sid) || !val_is_uuid(target) || !action.as_str().map(|a| actions.contains(&a)).unwrap_or(false) {
        return respond(&mut ack, json!({ "error": "INVALID_PAYLOAD" }));
    }
    let (server_id, target_id, action) = (sid.as_str().unwrap().to_string(), target.as_str().unwrap().to_string(), action.as_str().unwrap().to_string());
    let channel_id = {
        let v = app.conns.voice.lock();
        let ch = v.user_channel.get(&target_id).cloned();
        match ch.filter(|ch| v.channels.get(ch).and_then(|m| m.get(&target_id)).map(|p| p.server_id == server_id).unwrap_or(false)) {
            Some(ch) => ch,
            None => {
                drop(v);
                return respond(&mut ack, json!({ "error": "NOT_IN_VOICE" }));
            }
        }
    };
    let needed = if action == "disconnect" || action == "move" { MOVE_MEMBERS } else { MUTE_MEMBERS };
    if !check_server_permission(&app, &c.user_id, &server_id, needed).await {
        return respond(&mut ack, json!({ "error": "PERMISSION_DENIED" }));
    }
    if target_id != c.user_id && !can_act_on_member(&app, &c.user_id, &target_id, &server_id).await {
        return respond(&mut ack, json!({ "error": "TARGET_OUTRANKS_YOU" }));
    }
    let force = |extra_channel: &Value| json!({ "type": "VOICE_FORCE", "payload": { "serverId": server_id, "action": action, "channelId": extra_channel, "by": c.user_id } });
    if action == "move" {
        let to = field(&data, "channelId");
        let meta = if val_is_id(to) { get_channel_meta(&app, &server_id, to.as_str().unwrap()).await } else { None };
        let ok = meta.map(|m| m.kind == "voice" || m.kind == "stage").unwrap_or(false);
        if !ok {
            return respond(&mut ack, json!({ "error": "INVALID_CHANNEL" }));
        }
        let _ = app.io().to(format!("user:{target_id}")).emit("VOICE_FORCE", &force(to)).await;
        return respond(&mut ack, json!({ "success": true }));
    }
    if action == "disconnect" {
        let _ = app.io().to(format!("user:{target_id}")).emit("VOICE_FORCE", &force(&json!(channel_id))).await;
        remove_voice_participant(&app, &target_id, &channel_id).await;
        return respond(&mut ack, json!({ "success": true }));
    }
    {
        let mut v = app.conns.voice.lock();
        if let Some(p) = v.channels.get_mut(&channel_id).and_then(|m| m.get_mut(&target_id)) {
            match action.as_str() {
                "mute" => p.server_muted = true,
                "unmute" => p.server_muted = false,
                "deafen" => p.server_deafened = true,
                "undeafen" => p.server_deafened = false,
                _ => {}
            }
        }
    }
    let _ = app.io().to(format!("user:{target_id}")).emit("VOICE_FORCE", &force(&json!(channel_id))).await;
    broadcast_voice_state(&app, &server_id, &channel_id).await;
    respond(&mut ack, json!({ "success": true }));
}

// ── Déconnexion ─────────────────────────────────────────────────────────────

/// Termine un appel dont plus aucune socket ne fait partie (base + salle SFU).
async fn end_call_if_empty(c: &SockCtx, call_id: &str) {
    let n = c.io().within(format!("call:{call_id}")).fetch_sockets().await.map(|s| s.len()).unwrap_or(0);
    if n > 0 {
        return;
    }
    let _ = c.app.svc.calls_end(call_id, &c.user_id).await;
    let _ = c.app.svc.sfu_destroy_room(call_id).await;
}

pub async fn on_disconnect(c: Arc<SockCtx>, reason: &str) {
    let app = c.app.clone();
    info!("Déconnexion: {} ({}) - Raison: {reason}", c.username(), c.user_id);

    // Fermer l'onglet n'envoie jamais CALL_LEAVE : sans nettoyage, l'appel restait « en cours » en base.
    // Délai de grâce : une reconnexion (CALL_REJOIN) ne coupe pas l'appel.
    for room in c.socket.rooms() {
        if let Some(call_id) = room.strip_prefix("call:") {
            let (c2, id) = (c.clone(), call_id.to_string());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(15)).await;
                end_call_if_empty(&c2, &id).await;
            });
        }
    }

    // Nettoyer l'état vocal
    leave_voice_channel(&app, &c.user_id, &c.socket.id.to_string()).await;

    // Pas de minuterie orpheline
    for (_, h) in c.pending_archive.lock().drain() {
        h.abort();
    }
    app.conns.clients.lock().remove(&c.socket.id.to_string());

    let r: Result<(), String> = async {
        // Hors ligne seulement s'il ne reste aucun socket actif
        app.redis.set_user_offline(&c.user_id, &c.socket.id.to_string()).await.map_err(|e| e.to_string())?;
        app.redis.delete_session(&c.user_id, &c.session_id).await.map_err(|e| e.to_string())?;
        let still = app.redis.is_user_online(&c.user_id).await.map_err(|e| e.to_string())?;
        if !still {
            // La clé de présence (TTL 24 h) est conservée pour la restauration à la reconnexion
            if let Ok(Some(_)) = app.redis.get_presence(&c.user_id).await {
                let _ = app.redis.set_presence(&c.user_id, PresencePatch::default()).await;
            }
            let friends = app.svc.friends_get_friends(&c.user_id).await;
            super::presence::broadcast_presence_update(&app, &c.user_id, "offline", &friends, None, None).await;
            // last_seen + is_online=FALSE : on n'attend pas
            let (a, uid) = (app.clone(), c.user_id.clone());
            tokio::spawn(async move {
                if let Err(e) = a.svc.users_update_last_seen(&uid).await {
                    warn!("updateLastSeen failed for {uid}: {}", e.message);
                }
            });
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        error!("Erreur lors de la déconnexion de {}: {e}", c.user_id);
    }
}
