//! Présence : diffusion des changements de statut et détection d'inactivité (auto-idle).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::helpers::is_presence_hidden;
use crate::http::routes_misc::is_id;
use crate::redis_client::PresencePatch;
use crate::state::{event, AppState};

/// Diffuse un changement de statut aux amis, aux contacts de MP et aux membres des serveurs en commun.
pub async fn broadcast_presence_update(app: &Arc<AppState>, user_id: &str, status: &str, friends: &Value, text: Option<&Value>, emoji: Option<&Value>) {
    // Les amis voient 'offline' en mode invisible ou quand « afficher mon statut en ligne » est désactivé.
    let hidden = status != "offline" && is_presence_hidden(app, user_id).await;
    let visible = if status == "invisible" || hidden { "offline" } else { status };
    let nz = |v: Option<&Value>| v.cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null);
    let payload = event(
        "PRESENCE_UPDATE",
        json!({
            "userId": user_id,
            "status": visible,
            "customStatus": if hidden { Value::Null } else { nz(text) },
            "text": if hidden { Value::Null } else { nz(text) },
            "emoji": if hidden { Value::Null } else { nz(emoji) },
        }),
    );

    let mut recipients: Vec<String> = vec![];
    let mut push = |id: String, recipients: &mut Vec<String>| {
        if !id.is_empty() && !recipients.contains(&id) {
            recipients.push(id);
        }
    };
    if let Some(list) = friends.as_array() {
        for f in list {
            let fid = f.get("friendId").filter(|v| !v.is_null()).or_else(|| f.get("id")).and_then(|v| v.as_str());
            if let Some(fid) = fid {
                push(fid.to_string(), &mut recipients);
            }
        }
    }
    // Sans amitié, la liste des MP d'un utilisateur ne recevait jamais ses mises à jour de présence.
    if let Ok(convs) = app.svc.messages_get_conversations(user_id, None).await {
        if let Some(list) = convs.as_array() {
            for conv in list {
                if conv.get("type").and_then(|v| v.as_str()) == Some("dm") {
                    if let Some(r) = conv.get("recipientId").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                        push(r.to_string(), &mut recipients);
                    }
                }
            }
        }
    }
    // Membres des serveurs en commun. Socket.IO (JS) livre une seule fois par socket même s'il appartient à
    // plusieurs rooms visées ; socketioxide non : on émet d'abord vers les serveurs (chacun en excluant les
    // précédents), puis vers les rooms utilisateur en excluant tous les serveurs.
    let user_rooms: Vec<String> = recipients.iter().map(|f| format!("user:{f}")).collect();
    let mut server_rooms: Vec<String> = vec![];
    if let Ok(Some(cached)) = app.redis.get_user_rooms(user_id).await {
        for sid in cached.server_ids.iter().filter(|s| is_id(s)) {
            server_rooms.push(format!("server:{sid}"));
        }
    }
    emit_union(app, &server_rooms, &user_rooms, "PRESENCE_UPDATE", &payload).await;
}

/// Émet à l'union de rooms, une seule fois par socket.
pub async fn emit_union(app: &Arc<AppState>, group_a: &[String], group_b: &[String], ev: &str, payload: &Value) {
    let io = app.io();
    for (i, room) in group_a.iter().enumerate() {
        let _ = io.to(room.clone()).except(group_a[..i].to_vec()).emit(ev, payload).await;
    }
    if !group_b.is_empty() {
        let _ = io.to(group_b.to_vec()).except(group_a.to_vec()).emit(ev, payload).await;
    }
}

/// Passe en « absent » les utilisateurs inactifs depuis 5 minutes (vérifié chaque minute).
pub fn spawn_auto_idle(app: &Arc<AppState>) {
    const IDLE_TIMEOUT_MS: i64 = 5 * 60 * 1000;
    let app = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let users: std::collections::HashSet<String> = app.conns.clients.lock().values().map(|c| c.user_id.clone()).filter(|u| !u.is_empty()).collect();
            for uid in users {
                let Ok(Some(p)) = app.redis.get_presence(&uid).await else { continue };
                let last = p.get("lastActivity").and_then(|v| v.as_i64()).unwrap_or(0);
                if p.get("chosenStatus").and_then(|v| v.as_str()) == Some("online")
                    && p.get("status").and_then(|v| v.as_str()) == Some("online")
                    && crate::redis_client::now_ms() - last > IDLE_TIMEOUT_MS
                {
                    let patch = PresencePatch { status: Some("idle".into()), auto_idle: Some(true), ..Default::default() };
                    if app.redis.set_presence(&uid, patch).await.is_err() {
                        continue;
                    }
                    let friends = app.svc.friends_get_friends(&uid).await;
                    broadcast_presence_update(&app, &uid, "idle", &friends, p.get("text"), p.get("emoji")).await;
                }
            }
        }
    });
}
