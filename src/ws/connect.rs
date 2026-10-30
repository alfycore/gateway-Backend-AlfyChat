//! Connexion des clients : authentification (JWT + modération), initialisation de la session
//! (rooms, présence, appels et notifications en attente) puis pose des handlers.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Value};
use socketioxide::extract::{Data, SocketRef, State, TryData};
use socketioxide::socket::DisconnectReason;
use tokio::sync::watch;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::helpers::{fr_date, val_is_id};
use super::{ch_room, SockCtx};
use crate::http::routes_misc::{is_id, is_uuid, js_string};
use crate::ratelimit::SocketLimiter;
use crate::redis_client::{now_ms, PresencePatch};
use crate::state::{event, AppState, ConnectedClient, Moderation, A};

/// Identité validée par le middleware, relue par le handler de connexion.
#[derive(Clone)]
pub struct AuthInfo {
    pub user_id: String,
    pub session_id: String,
    pub user: Value,
    pub token: Option<String>,
    pub moderation: Moderation,
}

fn token_of(auth: &Value, socket: &SocketRef<A>) -> Option<String> {
    let from_auth = auth.get("token").filter(|t| crate::http::routes_misc::truthy(Some(t))).map(|t| js_string(Some(t)));
    from_auth.or_else(|| {
        socket.req_parts().headers.get("authorization").and_then(|v| v.to_str().ok()).map(|a| a.replacen("Bearer ", "", 1)).filter(|t| !t.is_empty())
    })
}

/// Middleware d'authentification de l'espace de noms `/`.
pub async fn auth_middleware(socket: SocketRef<A>, TryData(auth): TryData<Value>, State(app): State<Arc<AppState>>) -> Result<(), String> {
    let auth = auth.unwrap_or(Value::Null);
    let Some(token) = token_of(&auth, &socket) else { return Err("Token d'authentification requis".into()) };

    let claims = crate::security::verify_jwt(&token).map_err(|_| "Token invalide".to_string())?;
    let uid = claims.get("userId").and_then(|u| u.as_str()).filter(|u| is_uuid(u));
    let bad_type = claims.get("type").filter(|t| crate::http::routes_misc::truthy(Some(t))).map(|t| t.as_str() != Some("access")).unwrap_or(false);
    let Some(user_id) = uid.filter(|_| !bad_type) else { return Err("Token invalide".into()) };

    // Utilisateur et statut de modération. Fail-closed : si le statut de modération ne peut pas être lu,
    // la connexion est refusée — sinon une panne du service users rouvrirait le temps réel aux comptes bannis.
    let (user, moderation) = tokio::join!(app.svc.users_get_user(user_id), app.svc.users_get_moderation_status(user_id));
    let user = user.map_err(|e| {
        error!("Erreur d'authentification WebSocket: {}", e.message);
        "Token invalide".to_string()
    })?;
    if !crate::http::routes_misc::truthy(Some(&user)) {
        return Err("Utilisateur non trouvé".into());
    }
    let Ok(moderation) = moderation else {
        return Err("Vérification du compte impossible pour le moment. Réessayez dans quelques instants.".into());
    };
    let m = Moderation::from_value(&moderation);
    if m.banned {
        let until = match &m.banned_until {
            Some(u) => format!(" jusqu'au {}", fr_date(u)),
            None => " définitivement".to_string(),
        };
        warn!("Connexion WS refusée — compte banni: {user_id}");
        return Err(format!("Ce compte est banni{until}. Motif : {}", m.ban_reason.as_deref().unwrap_or("non précisé")));
    }

    socket.extensions.insert(AuthInfo { user_id: user_id.to_string(), session_id: Uuid::new_v4().to_string(), user, token: Some(token), moderation: m });
    Ok(())
}

/// Handler de connexion de l'espace de noms `/`.
pub async fn on_connect(socket: SocketRef<A>, State(app): State<Arc<AppState>>) {
    let Some(auth) = socket.extensions.get::<AuthInfo>() else {
        let _ = socket.disconnect();
        return;
    };
    let (user_id, session_id, user) = (auth.user_id.clone(), auth.session_id.clone(), auth.user.clone());
    let sid = socket.id.to_string();
    let username = user.get("username").and_then(|u| u.as_str()).unwrap_or("").to_string();
    let display = ["displayName", "username"].iter().find_map(|k| user.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty())).unwrap_or("").to_string();

    // Les handlers sont posés AVANT l'initialisation (rien n'est perdu) ; ils attendent `ready`.
    let (ready_tx, ready_rx) = watch::channel(false);
    let ctx = Arc::new(SockCtx {
        app: app.clone(),
        socket: socket.clone(),
        user_id: user_id.clone(),
        session_id: session_id.clone(),
        user: user.clone(),
        token: auth.token.clone(),
        limiter: SocketLimiter::new(),
        ready: ready_rx,
        pending_deletions: Mutex::new(HashMap::new()),
        pending_archive: Mutex::new(HashMap::new()),
        call_members: Mutex::new(HashMap::new()),
        last_speaking: Mutex::new(0),
    });
    super::messages::register(&ctx);
    super::calls::register(&ctx);
    super::servers::register(&ctx);
    super::misc::register(&ctx);
    {
        let c = ctx.clone();
        socket.on_disconnect(move |_s: SocketRef<A>, reason: DisconnectReason| {
            let c = c.clone();
            async move { super::misc::on_disconnect(c, &reason.to_string()).await }
        });
    }

    info!("Connexion: {username} ({user_id})");
    app.conns.clients.lock().insert(
        sid.clone(),
        ConnectedClient { socket_id: sid.clone(), user_id: user_id.clone(), session_id: session_id.clone(), connected_at: chrono::Utc::now(), user: user.clone() },
    );
    if let Err(e) = app.redis.set_user_online(&user_id, &sid).await {
        error!("setUserOnline: {e}");
    }
    let _ = app.redis.set_session(&user_id, &session_id, &json!({ "socketId": sid, "connectedAt": crate::iso::to_string(&chrono::Utc::now()) }), 86400).await;

    // Rooms personnelles
    let _ = socket.join(format!("user:{user_id}"));

    // Les trois jonctions (MP, groupes, serveurs) sont indépendantes : elles partent en parallèle.
    let (friend_list, _, _) = tokio::join!(join_dm_rooms(&ctx), join_group_rooms(&ctx, &username), join_server_rooms(&ctx, &username));

    // READY (données initiales volontairement vides)
    ctx.emit_event("READY", json!({ "user": user, "sessionId": session_id, "servers": [], "friends": [], "conversations": [] }));

    // Un appel en attente (arrivée tardive < 60 s)
    if let Ok(Some(raw)) = app.redis.get(&format!("pending_call:user:{user_id}")).await {
        if let Ok(call) = serde_json::from_str::<Value>(&raw) {
            let _ = socket.emit("CALL_INCOMING", &call);
            info!("Appel en attente re-émis à l'utilisateur tardif {user_id}");
        }
    }

    // Présence restaurée depuis Redis (survit 24 h) ou, à défaut, depuis la base
    let restored = app.redis.get_presence(&user_id).await.ok().flatten();
    let chosen = restored
        .as_ref()
        .and_then(|p| p.get("chosenStatus").and_then(|s| s.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
        .unwrap_or_else(|| match user.get("status").and_then(|s| s.as_str()) {
            Some(s) if !s.is_empty() && s != "offline" => s.to_string(),
            _ => "online".to_string(),
        });
    let restored_emoji = restored.as_ref().and_then(|p| p.get("emoji")).filter(|v| !v.is_null()).cloned();
    let restored_text = restored
        .as_ref()
        .and_then(|p| p.get("text"))
        .filter(|v| !v.is_null())
        .cloned()
        .or_else(|| user.get("customStatus").filter(|v| crate::http::routes_misc::truthy(Some(v))).cloned());
    let _ = app
        .redis
        .set_presence(
            &user_id,
            PresencePatch {
                status: Some(chosen.clone()),
                chosen_status: Some(chosen.clone()),
                emoji: Some(restored_emoji.as_ref().and_then(|e| e.as_str()).map(str::to_string)),
                text: Some(restored_text.as_ref().and_then(|e| e.as_str()).map(str::to_string)),
                last_activity: Some(now_ms()),
                ..Default::default()
            },
        )
        .await;
    ctx.emit_event("PRESENCE_RESTORED", json!({ "status": chosen, "emoji": restored_emoji, "text": restored_text }));
    super::presence::broadcast_presence_update(&app, &user_id, &chosen, &friend_list, restored_text.as_ref(), restored_emoji.as_ref()).await;

    // Pings en attente (messages reçus hors ligne) — en arrière-plan
    {
        let c = ctx.clone();
        tokio::spawn(async move { send_pending_pings(&c).await });
    }

    let _ = ready_tx.send(true);
}

/// Notifications persistantes (base) fusionnées avec les pings Redis (compat.).
async fn send_pending_pings(c: &Arc<SockCtx>) {
    let app = &c.app;
    let db = app.svc.messages_get_notifications(c.token.as_deref()).await.ok().and_then(|v| v.as_object().cloned()).unwrap_or_default();
    let Ok(redis_pings) = app.redis.get_pending_pings(&c.user_id).await else { return };
    let mut merged: serde_json::Map<String, Value> = redis_pings.iter().map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or(Value::Null))).collect();
    for (conv, notif) in db {
        match merged.get(&conv).cloned() {
            None => {
                merged.insert(conv, notif);
            }
            Some(existing) => {
                let count = existing.get("count").and_then(|c| c.as_i64()).unwrap_or(0).max(notif.get("count").and_then(|c| c.as_i64()).unwrap_or(0));
                let pick_s = |k: &str| notif.get(k).filter(|v| crate::http::routes_misc::truthy(Some(v))).or_else(|| existing.get(k)).cloned();
                let mut m = serde_json::Map::new();
                m.insert("count".into(), json!(count));
                if let Some(s) = pick_s("senderName") {
                    m.insert("senderName".into(), s);
                }
                // Le type « mention » est prioritaire sur « message »
                let ty = if notif.get("type").and_then(|t| t.as_str()) == Some("mention") { notif.get("type").cloned() } else { existing.get("type").filter(|v| !v.is_null()).cloned().or_else(|| notif.get("type").cloned()) };
                if let Some(t) = ty {
                    m.insert("type".into(), t);
                }
                if let Some(ch) = pick_s("channelName") {
                    m.insert("channelName".into(), ch);
                }
                merged.insert(conv, Value::Object(m));
            }
        }
    }
    if !merged.is_empty() {
        c.emit_event("PENDING_PINGS", Value::Object(merged));
        // Nettoyer Redis (la base est purgée via PATCH /notifications/read côté client)
        let _ = app.redis.clear_pending_pings(&c.user_id).await;
    }
}

async fn join_dm_rooms(c: &Arc<SockCtx>) -> Value {
    let friends = c.app.svc.friends_get_friends(&c.user_id).await;
    if let Some(list) = friends.as_array() {
        for f in list {
            if let Some(fid) = f.get("id").and_then(|i| i.as_str()) {
                let _ = c.socket.join(format!("conversation:{}", super::helpers::dm_id_for(&c.user_id, fid)));
            }
        }
        return friends;
    }
    json!([])
}

async fn join_group_rooms(c: &Arc<SockCtx>, username: &str) {
    match c.app.svc.messages_get_conversations(&c.user_id, None).await {
        Ok(convs) => {
            let mut n = 0;
            for conv in convs.as_array().into_iter().flatten() {
                let id = ["id", "conversationId"].iter().find_map(|k| conv.get(*k).filter(|v| crate::http::routes_misc::truthy(Some(v)))).map(|v| js_string(Some(v)));
                if let Some(id) = id.filter(|i| !i.starts_with("dm_")) {
                    let _ = c.socket.join(format!("conversation:{id}"));
                    n += 1;
                }
            }
            if n > 0 {
                info!("{username} auto-joined {n} group conversation rooms");
            }
        }
        Err(e) => warn!("Erreur join des rooms de groupe: {}", e.message),
    }
}

async fn join_server_rooms(c: &Arc<SockCtx>, username: &str) {
    let app = &c.app;
    // Chemin rapide : restaurer depuis le cache Redis (évite NOT_A_CHANNEL_MEMBER au redémarrage)
    if let Ok(Some(cached)) = app.redis.get_user_rooms(&c.user_id).await {
        for sid in cached.server_ids.iter().filter(|s| is_id(s)) {
            let _ = c.socket.join(format!("server:{sid}"));
        }
        // Format courant : "<serverId>:<channelId>" (les anciennes entrées sont ignorées)
        for key in &cached.channel_ids {
            let mut it = key.split(':');
            if let (Some(sid), Some(cid)) = (it.next(), it.next()) {
                if is_id(sid) && is_id(cid) {
                    let _ = c.socket.join(ch_room(sid, cid));
                }
            }
        }
        info!("{username} restored {} servers + {} channels from Redis cache", cached.server_ids.len(), cached.channel_ids.len());
    }

    // Chemin lent : rafraîchir depuis les microservices (met à jour le cache)
    let Ok(servers) = app.svc.servers_get_user_servers(&c.user_id, c.token.as_deref()).await else { return };
    let Some(list) = servers.as_array() else { return };
    let results = futures::future::join_all(list.iter().map(|srv| {
        let c = c.clone();
        let srv = srv.clone();
        async move {
            let sid = ["id", "server_id"].iter().find_map(|k| srv.get(*k).filter(|v| crate::http::routes_misc::truthy(Some(v)))).map(|v| js_string(Some(v)))?;
            if !is_id(&sid) {
                return None;
            }
            let _ = c.socket.join(format!("server:{sid}"));
            // Notifier le node (sans attendre)
            {
                let (a, s2, body) = (c.app.clone(), sid.clone(), json!({ "userId": c.user_id, "username": c.username(), "displayName": c.display_name(), "avatarUrl": c.avatar() }));
                tokio::spawn(async move {
                    let _ = crate::nodes::forward_to_node(&a, &s2, "MEMBER_JOIN", &body, 15_000).await;
                });
            }
            // Salons visibles par ce membre (attendus pour éviter la course au démarrage)
            let channels: Vec<Value> = match crate::nodes::forward_to_node(&c.app, &sid, "CHANNEL_LIST", &json!({ "userId": c.user_id }), 15_000).await {
                Ok(r) => r.get("channels").and_then(|c| c.as_array()).cloned().unwrap_or_default(),
                Err(_) => c.app.svc.servers_get_channels(&sid, Some(&c.user_id)).await.ok().and_then(|v| v.as_array().cloned()).unwrap_or_default(),
            };
            let mut cids = vec![];
            for ch in channels {
                let Some(id) = ch.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)) else { continue };
                let _ = c.socket.join(ch_room(&sid, id));
                cids.push(format!("{sid}:{id}"));
            }
            Some((sid, cids))
        }
    }))
    .await;
    let (mut all_servers, mut all_channels) = (vec![], vec![]);
    for (sid, cids) in results.into_iter().flatten() {
        all_servers.push(sid);
        all_channels.extend(cids);
    }
    // Persisté pour la prochaine reconnexion
    let _ = app.redis.save_user_rooms(&c.user_id, &all_servers, &all_channels).await;
    info!("{username} auto-joined {} server rooms, {} channel rooms", all_servers.len(), all_channels.len());
}

/// Utilisé par les routes HTTP internes.
#[allow(dead_code)]
pub fn _unused(_: &Data<Value>) -> bool {
    val_is_id(&Value::Null) || event("", Value::Null).is_null()
}
