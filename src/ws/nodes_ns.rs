//! Espace de noms `/server-nodes` : les server-nodes auto-hébergés s'y connectent (nodeToken, pas JWT utilisateur),
//! y reçoivent des événements à traiter (MSG_FORWARD…) et y diffusent leurs changements (NODE_BROADCAST).

use std::sync::Arc;

use rand::RngCore;
use serde_json::{json, Map, Value};
use socketioxide::extract::{Data, SocketRef, State, TryData};
use tracing::{error, info, warn};

use super::calls::node_owns_channel_app;
use super::ch_room;
use crate::http::routes_misc::{is_id, is_uuid, js_string, truthy};
use crate::state::{event, AppState, ConnectedNode, A};

/// Identité validée d'un node (ou d'une demande d'enregistrement).
#[derive(Clone)]
pub struct NodeAuth {
    pub register_mode: bool,
    pub register_owner_id: Option<String>,
    pub server_id: Option<String>,
    pub endpoint: Option<String>,
    pub name: Option<String>,
}

/// Événements d'un node relayés tels quels (hors cas traités explicitement).
const NODE_PASSTHROUGH_EVENTS: [&str; 1] = ["CHANNEL_PERMS_UPDATE"];

pub async fn auth_middleware(socket: SocketRef<A>, TryData(auth): TryData<Value>, State(app): State<Arc<AppState>>) -> Result<(), String> {
    let auth = auth.unwrap_or(Value::Null);
    let g = |k: &str| auth.get(k).cloned().unwrap_or(Value::Null);

    // ── Mode enregistrement ─────────────────────────────────────────────
    // Ce mode CRÉE un serveur en base : le node doit présenter le JWT de l'utilisateur qui l'installe.
    if g("register") == Value::Bool(true) {
        let Some(token) = g("token").as_str().filter(|t| !t.is_empty()).map(str::to_string) else {
            return Err("Enregistrement refusé — connectez-vous dans le client AlfyChat pour obtenir un jeton d'installation".into());
        };
        let owner = crate::security::verify_jwt(&token)
            .ok()
            .and_then(|c| ["userId", "id"].iter().find_map(|k| c.get(*k).filter(|v| truthy(Some(v))).and_then(|v| v.as_str()).map(str::to_string)))
            .filter(|o| is_uuid(o));
        let Some(owner) = owner else { return Err("Jeton d'installation invalide ou expiré".into()) };
        // Un compte banni ne doit pas pouvoir créer de serveur (fail-closed).
        match app.svc.users_get_moderation_status(&owner).await {
            Err(_) => return Err("Vérification du compte impossible pour le moment".into()),
            Ok(m) if crate::state::Moderation::from_value(&m).banned => return Err("Ce compte est banni".into()),
            Ok(_) => {}
        }
        if !app.ws_limits.check_node_register_rate(&owner) {
            return Err("Trop d'enregistrements de serveurs — patientez quelques minutes".into());
        }
        socket.extensions.insert(NodeAuth {
            register_mode: true,
            register_owner_id: Some(owner),
            server_id: None,
            endpoint: None,
            name: auth.get("name").and_then(|n| n.as_str()).map(str::to_string),
        });
        return Ok(());
    }

    // ── Mode connexion normal : valide le token ─────────────────────────
    let (node_token, server_id) = (g("nodeToken"), g("serverId"));
    if !truthy(Some(&node_token)) || !truthy(Some(&server_id)) {
        return Err("nodeToken et serverId requis".into());
    }
    let (Some(node_token), Some(server_id)) = (node_token.as_str(), server_id.as_str().filter(|s| is_id(s))) else {
        return Err("nodeToken et serverId requis".into());
    };
    let result = match app.svc.servers_validate_node_token(node_token).await {
        Ok(r) => r,
        Err(e) => {
            error!("Erreur authentification server-node: {}", e.message);
            return Err("Authentification server-node échouée".into());
        }
    };
    if result.get("serverId").and_then(|s| s.as_str()) != Some(server_id) {
        return Err("Token de node invalide — serverId ne correspond pas".into());
    }
    // L'endpoint HTTP est déclaré par le node : validé ICI, une fois, avant d'être mémorisé (SSRF + exfiltration de secret).
    let raw_endpoint = g("endpoint");
    let mut endpoint = None;
    if !raw_endpoint.is_null() && raw_endpoint != "" {
        let validated = match raw_endpoint.as_str() {
            Some(e) => crate::security::validate_node_endpoint(e).await,
            None => None,
        };
        match validated {
            Some(v) => endpoint = Some(v),
            None => {
                warn!("Endpoint de node refusé pour {server_id}: {}", js_string(Some(&raw_endpoint)).chars().take(120).collect::<String>());
                return Err("Endpoint invalide — une origine HTTPS publique est requise (ni IP privée, ni chemin)".into());
            }
        }
    }
    socket.extensions.insert(NodeAuth { register_mode: false, register_owner_id: None, server_id: Some(server_id.to_string()), endpoint, name: None });
    Ok(())
}

fn setup_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 14];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char).collect()
}

pub async fn on_connect(socket: SocketRef<A>, State(app): State<Arc<AppState>>) {
    let Some(auth) = socket.extensions.get::<NodeAuth>() else {
        let _ = socket.disconnect();
        return;
    };

    // ── Mode auto-enregistrement ─────────────────────────────────────────
    if auth.register_mode {
        let owner = auth.register_owner_id.clone().unwrap_or_default();
        match app.svc.servers_register_node(auth.name.as_deref(), Some(&owner)).await {
            Ok(result) if truthy(result.get("serverId")) => {
                info!("✅ Serveur auto-enregistré: {} ({}) par {owner}", js_string(result.get("serverName")), js_string(result.get("serverId")));
                let _ = socket.emit(
                    "REGISTERED",
                    &json!({ "serverId": result["serverId"], "nodeToken": result.get("nodeToken"), "serverName": result.get("serverName"), "inviteCode": result.get("inviteCode") }),
                );
            }
            Ok(_) => {
                let _ = socket.emit("REGISTER_ERROR", &json!({ "message": "Échec de la création du serveur" }));
            }
            Err(e) => {
                error!("Erreur lors de l'auto-enregistrement du server-node: {}", e.message);
                let _ = socket.emit("REGISTER_ERROR", &json!({ "message": "Erreur interne du gateway" }));
            }
        }
        let _ = socket.disconnect();
        return;
    }

    let server_id = auth.server_id.clone().unwrap_or_default();
    // Endpoint déjà validé par le middleware ; ne JAMAIS relire handshake.auth.endpoint ici.
    let endpoint = auth.endpoint.clone();
    info!("🟢 Server-node connecté: serverId={server_id} endpoint={}", endpoint.as_deref().unwrap_or("n/a"));

    let sid = socket.id.to_string();
    app.conns.nodes.lock().insert(
        server_id.clone(),
        ConnectedNode { socket: socket.clone(), socket_id: sid.clone(), server_id: server_id.clone(), endpoint, connected_at: chrono::Utc::now() },
    );

    // Code admin à usage unique (14 caractères d'un alphabet de 32 ≈ 70 bits), valable 15 minutes.
    let code = setup_code();
    let _ = app.redis.set(&format!("setup_code:{server_id}"), &code, Some(900)).await;
    let _ = socket.emit("SETUP_CODE", &json!({ "code": code, "serverId": server_id, "expiresIn": 900 }));

    // Secret propre à ce serveur, remis sur ce canal authentifié : le node n'a plus besoin du INTERNAL_SECRET maître.
    let _ = socket.emit("NODE_SECRET", &json!({ "secret": crate::security::derive_node_secret(&server_id) }));
    info!("🔑 Code admin généré pour serverId={server_id}");

    // Les membres connectés savent que le serveur est de nouveau en ligne
    let ev = "SERVER_NODE_ONLINE";
    let _ = app.io().to(format!("server:{server_id}")).emit(ev, &event(ev, json!({ "serverId": server_id }))).await;

    {
        let (app, server_id) = (app.clone(), server_id.clone());
        socket.on("NODE_BROADCAST", move |_s: SocketRef<A>, Data::<Value>(data)| {
            let (app, server_id) = (app.clone(), server_id.clone());
            async move { node_broadcast(&app, &server_id, &data).await }
        });
    }
    // Ancien format (compat) : même contrôle d'appartenance du salon que NODE_BROADCAST
    {
        let (app, server_id) = (app.clone(), server_id.clone());
        socket.on("MSG_BROADCAST", move |_s: SocketRef<A>, Data::<Value>(data)| {
            let (app, server_id) = (app.clone(), server_id.clone());
            async move {
                let cid = data.get("channelId");
                if !cid.map(super::helpers::val_is_id).unwrap_or(false) || !node_owns_channel_app(&app, &server_id, cid.unwrap().as_str().unwrap()).await {
                    warn!("MSG_BROADCAST rejeté: salon {} hors du serveur {server_id}", js_string(cid));
                    return;
                }
                let ev = "SERVER_MESSAGE_NEW";
                let room = ch_room(&server_id, cid.unwrap().as_str().unwrap());
                let _ = app.io().to(room).emit(ev, &event(ev, data.get("message").cloned().unwrap_or(Value::Null))).await;
            }
        });
    }
    socket.on("NODE_STATUS", |_s: SocketRef<A>, Data::<Value>(d)| async move {
        info!("📊 Node status: {} — {} membres — {}", js_string(d.get("name")), js_string(d.get("memberCount")), js_string(d.get("status")));
    });

    {
        let (app, server_id, sid) = (app.clone(), server_id.clone(), sid.clone());
        socket.on_disconnect(move |_s: SocketRef<A>| {
            let (app, server_id, sid) = (app.clone(), server_id.clone(), sid.clone());
            async move {
                // Ne supprimer que si c'est bien CE socket qui est enregistré (reconnexion rapide)
                let was_current = {
                    let mut g = app.conns.nodes.lock();
                    if g.get(&server_id).map(|n| n.socket_id == sid).unwrap_or(false) {
                        g.remove(&server_id);
                        true
                    } else {
                        false
                    }
                };
                if was_current {
                    info!("🔴 Server-node déconnecté: serverId={server_id}");
                    let ev = "SERVER_NODE_OFFLINE";
                    let _ = app.io().to(format!("server:{server_id}")).emit(ev, &event(ev, json!({ "serverId": server_id }))).await;
                } else {
                    info!("🔄 Ancien socket du server-node déconnecté (remplacé): serverId={server_id}");
                }
            }
        });
    }
}

/// `{ ...payload, serverId }`
fn with_server(payload: &Value, server_id: &str) -> Value {
    let mut m = payload.as_object().cloned().unwrap_or_default();
    m.insert("serverId".into(), json!(server_id));
    Value::Object(m)
}

/// `{ ...inner, serverId }` où `inner` est un sous-objet du payload (`channel`, `role`, `member`).
fn spread_inner(payload: &Value, key: &str, server_id: &str) -> Value {
    with_server(payload.get(key).unwrap_or(&Value::Null), server_id)
}

async fn node_broadcast(app: &Arc<AppState>, server_id: &str, data: &Value) {
    let Some(event_name) = data.get("event").and_then(|e| e.as_str()) else { return };
    let Some(payload) = data.get("data").filter(|p| p.is_object()) else { return };
    let channel = payload.get("channelId");
    if channel.map(|c| !super::helpers::val_is_id(c)).unwrap_or(false) {
        return;
    }
    // Le serverId du payload doit être celui du node connecté
    if let Some(p_sid) = payload.get("serverId").filter(|v| truthy(Some(v))) {
        if p_sid.as_str() != Some(server_id) {
            warn!("NODE_BROADCAST rejeté: node {server_id} tente de broadcast vers serveur {}", js_string(Some(p_sid)));
            return;
        }
    }
    // …et le salon visé lui appartient aussi (sinon un node pouvait diffuser dans le salon d'un autre serveur)
    if let Some(cid) = channel.filter(|v| truthy(Some(v))).and_then(|c| c.as_str()) {
        if !node_owns_channel_app(app, server_id, cid).await {
            warn!("NODE_BROADCAST rejeté: salon {cid} n'appartient pas au serveur {server_id}");
            return;
        }
    }
    let channel_id = channel.and_then(|c| c.as_str()).filter(|c| !c.is_empty());
    let srv_room = format!("server:{server_id}");
    let io = app.io();
    let emit_srv = |ev: &'static str, p: Value| {
        let (io, room) = (io.clone(), srv_room.clone());
        async move {
            let _ = io.to(room).emit(ev, &event(ev, p)).await;
        }
    };
    let emit_chan = |ev: &'static str, p: Value, cid: &str| {
        let (io, room) = (io.clone(), ch_room(server_id, cid));
        async move {
            let _ = io.to(room).emit(ev, &event(ev, p)).await;
        }
    };

    match event_name {
        // ── Messages ──
        "MSG_BROADCAST" => {
            if let Some(cid) = channel_id {
                emit_chan("SERVER_MESSAGE_NEW", payload.get("message").cloned().unwrap_or(Value::Null), cid).await
            }
        }
        "MSG_EDIT" => {
            if let Some(cid) = channel_id {
                emit_chan("SERVER_MESSAGE_EDITED", with_server(payload, server_id), cid).await
            }
        }
        "MSG_DELETE" => {
            if let Some(cid) = channel_id {
                emit_chan("SERVER_MESSAGE_DELETED", with_server(payload, server_id), cid).await
            }
        }
        // ── Salons ──
        "CHANNEL_CREATE" => emit_srv("CHANNEL_CREATE", spread_inner(payload, "channel", server_id)).await,
        "CHANNEL_UPDATE" => emit_srv("CHANNEL_UPDATE", spread_inner(payload, "channel", server_id)).await,
        "CHANNEL_DELETE" => emit_srv("CHANNEL_DELETE", json!({ "channelId": payload.get("channelId"), "serverId": server_id })).await,
        // ── Rôles ──
        "ROLE_CREATE" => emit_srv("ROLE_CREATE", spread_inner(payload, "role", server_id)).await,
        "ROLE_UPDATE" => emit_srv("ROLE_UPDATE", spread_inner(payload, "role", server_id)).await,
        "ROLE_DELETE" => emit_srv("ROLE_DELETE", json!({ "roleId": payload.get("roleId"), "serverId": server_id })).await,
        // ── Membres ──
        "MEMBER_JOIN" => emit_srv("MEMBER_JOIN", spread_inner(payload, "member", server_id)).await,
        "MEMBER_UPDATE" => emit_srv("MEMBER_UPDATE", spread_inner(payload, "member", server_id)).await,
        "MEMBER_KICK" => emit_srv("MEMBER_LEAVE", json!({ "serverId": server_id, "userId": payload.get("userId"), "kicked": true })).await,
        "MEMBER_BAN" => emit_srv("MEMBER_LEAVE", json!({ "serverId": server_id, "userId": payload.get("userId"), "banned": true })).await,
        // ── Infos du serveur ──
        "SERVER_UPDATE" => {
            let mut m = Map::new();
            m.insert("id".into(), json!(server_id));
            for (k, v) in payload.as_object().into_iter().flatten() {
                m.insert(k.clone(), v.clone());
            }
            emit_srv("SERVER_UPDATE", Value::Object(m)).await
        }
        // ── Frappe ──
        "TYPING_START" => {
            if let Some(cid) = channel_id {
                emit_chan("SERVER_TYPING_START", with_server(payload, server_id), cid).await
            }
        }
        "TYPING_STOP" => {
            if let Some(cid) = channel_id {
                emit_chan("SERVER_TYPING_STOP", with_server(payload, server_id), cid).await
            }
        }
        // ── Liste blanche : un relais « tel quel » permettrait à un node malveillant de forger des événements plateforme ──
        other => {
            if !NODE_PASSTHROUGH_EVENTS.contains(&other) {
                warn!("NODE_BROADCAST rejeté: événement non autorisé \"{}\" depuis {server_id}", other.chars().take(64).collect::<String>());
                return;
            }
            let room = match channel_id {
                Some(cid) => ch_room(server_id, cid),
                None => srv_room.clone(),
            };
            let _ = io.to(room).emit(other, &event(other, with_server(payload, server_id))).await;
        }
    }
}
