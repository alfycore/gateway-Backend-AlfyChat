//! Routes HTTP : amorçage, amis, serveurs, médias, répartiteur de charge, santé et statistiques
//! (équivalents de `http/{bootstrap,friends,servers,media,lb,internal,health,stats}.routes.ts`
//! et des hooks `claim-admin` / webhook entrant d'`index.ts`).

use std::sync::Arc;
use std::time::Duration;

use axum::http::Method;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use super::proxy::{
    proxy_multipart_to_service, proxy_request, proxy_to_media, proxy_to_node, proxy_to_node_multipart, safe_json,
};
use super::{empty, err_json, handler, json, send, set_header, Req, Resp, Router};
use crate::lb::registry::ServiceMetrics;
use crate::nodes::{forward_to_node, invalidate_block_cache};
use crate::redis_client::now_ms;
use crate::security::{
    encode_uri_component, is_safe_file_segment, rewrite_node_path, safe_secret_equal, set_safe_file_headers,
};
use crate::state::{event, AppState};

static UUID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap());
static ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,128}$").unwrap());
static LOCAL_HOST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?").unwrap());
static WEBHOOK_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9]{16,128}$").unwrap());

pub fn is_id(v: &str) -> bool {
    ID_RE.is_match(v)
}

pub fn is_uuid(v: &str) -> bool {
    UUID_RE.is_match(v)
}

pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        _ => true,
    }
}

// ═══════════════════════════ Amorçage ═══════════════════════════

/// Appelle un service avec l'identité de l'appelant. `None` sur tout échec : une brique manquante
/// ne doit pas faire tomber l'amorçage.
async fn part(req: &Req, base_url: &str, path: impl AsRef<str>) -> Option<Value> {
    let path = path.as_ref();
    if base_url.is_empty() {
        return None;
    }
    let mut rb = req.app.http.get(format!("{base_url}{path}")).header("Content-Type", "application/json").timeout(Duration::from_secs(8));
    if let Some(a) = req.authorization() {
        rb = rb.header("authorization", a);
    }
    let r = rb.send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<Value>().await.ok()
}

/// Déballe les réponses encore enveloppées dans `{ success, data }`.
fn unwrap(v: Option<Value>) -> Value {
    match v {
        Some(Value::Object(m)) if m.contains_key("data") => m.get("data").cloned().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

/// Recopie le profil du destinataire à la racine de chaque conversation privée.
fn with_recipient_profiles(conversations: Value) -> Vec<Value> {
    let Value::Array(list) = conversations else { return vec![] };
    list.into_iter()
        .map(|conv| {
            let (is_dm, recipient) = (
                conv.get("type").and_then(|v| v.as_str()) == Some("dm"),
                conv.get("recipientId").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string),
            );
            let (true, Some(recipient)) = (is_dm, recipient) else { return conv };
            let profile = conv
                .get("participants")
                .and_then(|p| p.as_array())
                .and_then(|a| a.iter().find(|p| p.get("userId").and_then(|u| u.as_str()) == Some(recipient.as_str())).cloned());
            let Some(profile) = profile else { return conv };
            let s = |k: &str| profile.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string);
            let name = s("displayName")
                .or_else(|| s("username"))
                .or_else(|| conv.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
                .unwrap_or_else(|| recipient.clone());
            let mut m = conv.as_object().cloned().unwrap_or_default();
            m.insert("recipientName".into(), json!(name));
            m.insert("recipientAvatar".into(), profile.get("avatarUrl").cloned().unwrap_or(Value::Null));
            m.insert("recipientUsername".into(), profile.get("username").cloned().unwrap_or(Value::Null));
            m.insert("recipientOnline".into(), json!(profile.get("isOnline") == Some(&Value::Bool(true))));
            Value::Object(m)
        })
        .collect()
}

fn register_bootstrap(r: &mut Router) {
    r.get(
        "/api/bootstrap/me",
        handler(|req: Req| async move {
            let Some(user_id) = req.user_id() else { return err_json(401, "Authentification requise") };
            let (a, cfg) = (req.app.clone(), req.app.cfg);
            let users = a.service_url("users", &cfg.users_url);
            let messages = a.service_url("messages", &cfg.messages_url);
            let friends = a.service_url("friends", &cfg.friends_url);
            let servers = a.service_url("servers", &cfg.servers_url);
            let started = std::time::Instant::now();
            let (user, srv, convs, fr, freq, blocked, notifs, notif_settings, prefs) = tokio::join!(
                part(&req, &users, format!("/users/{user_id}")),
                part(&req, &servers, format!("/servers?userId={}", encode_uri_component(&user_id))),
                part(&req, &messages, "/conversations"),
                part(&req, &friends, "/friends"),
                part(&req, &friends, "/friends/requests"),
                part(&req, &friends, "/friends/blocked"),
                part(&req, &messages, "/notifications"),
                part(&req, &messages, "/messages/notifications/settings"),
                part(&req, &users, format!("/users/{user_id}/preferences")),
            );
            let conversations = with_recipient_profiles(unwrap(convs));
            info!("bootstrap/me {user_id} — {} conversations en {} ms", conversations.len(), started.elapsed().as_millis());
            let or = |v: Value, d: Value| if v.is_null() { d } else { v };
            json(
                200,
                &json!({
                    "user": unwrap(user),
                    "servers": or(unwrap(srv), json!([])),
                    "conversations": conversations,
                    "friends": or(unwrap(fr), json!([])),
                    "friendRequests": or(unwrap(freq), json!({ "received": [], "sent": [] })),
                    "blocked": or(unwrap(blocked), json!([])),
                    "notifications": or(unwrap(notifs), json!({})),
                    "notificationSettings": or(unwrap(notif_settings), json!({})),
                    "preferences": or(unwrap(prefs), json!({})),
                    "fetchedAt": now_ms(),
                }),
            )
        }),
    );

    r.get(
        "/api/bootstrap/dm/:recipientId",
        handler(|req: Req| async move {
            let Some(user_id) = req.user_id() else { return err_json(401, "Authentification requise") };
            let recipient_id = req.param("recipientId").to_string();
            if !UUID_RE.is_match(&recipient_id) {
                return err_json(400, "recipientId invalide");
            }
            let limit = req
                .query("limit")
                .unwrap_or_else(|| "50".into())
                .trim()
                .split(|c: char| !c.is_ascii_digit() && c != '-' && c != '+')
                .next()
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|n| *n != 0)
                .unwrap_or(50)
                .clamp(1, 100);
            let (a, cfg) = (req.app.clone(), req.app.cfg);
            let users = a.service_url("users", &cfg.users_url);
            let messages = a.service_url("messages", &cfg.messages_url);
            let friends = a.service_url("friends", &cfg.friends_url);
            let started = std::time::Instant::now();
            let (recipient, block, keys, msgs) = tokio::join!(
                part(&req, &users, format!("/users/{recipient_id}")),
                part(&req, &friends, format!("/friends/block-status/{recipient_id}")),
                // Consomme une one-time prekey côté serveur : uniquement pour une conversation réellement ouverte.
                part(&req, &users, format!("/users/keys/{recipient_id}")),
                part(&req, &messages, format!("/messages?recipientId={}&limit={limit}", encode_uri_component(&recipient_id))),
            );
            info!("bootstrap/dm {user_id} → {recipient_id} en {} ms", started.elapsed().as_millis());
            let or = |v: Value, d: Value| if v.is_null() { d } else { v };
            json(
                200,
                &json!({
                    "recipient": unwrap(recipient),
                    "blockStatus": or(unwrap(block), json!({ "iBlockedThem": false, "theyBlockedMe": false })),
                    "keyBundle": unwrap(keys),
                    "messages": or(unwrap(msgs), json!([])),
                    "fetchedAt": now_ms(),
                }),
            )
        }),
    );
}

// ═══════════════════════════ Répartiteur de charge ═══════════════════════════

fn body_str<'a>(req: &'a Req, k: &str) -> Option<&'a str> {
    req.body.get(k).and_then(|v| v.as_str())
}

fn register_internal(r: &mut Router) {
    // Désactivé : l'auto-enregistrement des services n'est plus autorisé.
    r.post(
        "/api/internal/service/register",
        handler(|req: Req| async move {
            let id = body_str(&req, "id").filter(|s| !s.is_empty()).unwrap_or("unknown").to_string();
            warn!("ServiceRegistry: tentative d'auto-enregistrement refusée pour \"{id}\" — admin-only");
            err_json(403, "Auto-enregistrement désactivé — un administrateur doit ajouter ce service via /api/admin/services")
        }),
    );

    r.post(
        "/api/internal/service/heartbeat",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let id_v = req.body.get("id");
            let id_s = js_string(id_v);
            let secret = req.body.get("secret");
            if !truthy(secret) || !validate_service_secret(&app, &id_s, &js_string(secret)) {
                return err_json(401, "Secret invalide");
            }
            if !truthy(id_v) || !truthy(req.body.get("metrics")) {
                return err_json(400, "id et metrics requis");
            }
            if app.banned_service_ids.lock().contains(&id_s) {
                return err_json(403, "Instance bannie — supprimée par un administrateur");
            }
            let metrics = ServiceMetrics::from_value(req.body.get("metrics").unwrap_or(&Value::Null));
            if !app.lb.heartbeat(&id_s, metrics) {
                // Instance inconnue : arrive au redémarrage du gateway ; 404 pour que le service se ré-enregistre.
                return err_json(404, "Instance inconnue, veuillez vous enregistrer d'abord");
            }
            json(200, &json!({ "success": true }))
        }),
    );

    r.post(
        "/api/internal/service/deregister",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let secret = req.body.get("secret");
            if !truthy(secret) || !safe_secret_equal(Some(&js_string(secret)), Some(&app.cfg.internal_secret)) {
                return err_json(401, "Secret invalide");
            }
            let id = req.body.get("id");
            if !truthy(id) {
                return err_json(400, "id requis");
            }
            let id = js_string(id);
            let removed = app.lb.remove(&id);
            if removed {
                let a = app.clone();
                tokio::spawn(async move { a.monitoring.remove_service_instance(&id).await });
            }
            json(200, &json!({ "success": removed }))
        }),
    );

    r.get(
        "/api/internal/service/list",
        handler(|req: Req| async move {
            let app = req.app.clone();
            if !safe_secret_equal(req.header("x-internal-secret"), Some(&app.cfg.internal_secret)) {
                return err_json(401, "Secret invalide");
            }
            let instances: Vec<Value> = app.lb.get_all().iter().map(entry_with_score).collect();
            let healthy = instances.iter().filter(|i| i.get("healthy") == Some(&Value::Bool(true))).count();
            json(200, &json!({ "count": instances.len(), "healthy": healthy, "instances": instances }))
        }),
    );
}

/// `String(value)` de JavaScript pour une valeur JSON de saisie.
pub fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.as_f64().map(crate::json::js_number).unwrap_or_else(|| n.to_string()),
        Some(other) => crate::json::stringify(other),
    }
}

pub fn entry_with_score(e: &crate::lb::registry::ServiceEntry) -> Value {
    let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.insert("score".into(), json!(crate::lb::registry::compute_score(e)));
    }
    v
}

/// Valide la clé (`sk_…`) ou le secret interne d'un service.
pub fn validate_service_secret(app: &Arc<AppState>, id: &str, secret: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    if secret.starts_with("sk_") {
        return app.lb.validate_key(secret).as_deref() == Some(id);
    }
    safe_secret_equal(Some(secret), Some(&app.cfg.internal_secret))
}

fn register_lb(r: &mut Router) {
    r.post(
        "/api/lb/register",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let key = req.header("x-service-key").map(str::to_string);
            let internal = req.header("x-internal-secret").map(str::to_string);
            let endpoint = match req.body.get("endpoint") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return err_json(400, "endpoint requis"),
            };
            let domain = body_str(&req, "domain").filter(|s| !s.is_empty()).map(str::to_string);
            fn reg<'a>(endpoint: &'a str, domain: Option<&'a str>, gw: &'a str) -> crate::lb::registry::Registration<'a> {
                crate::lb::registry::Registration { endpoint, domain, gateway_id: Some(gw) }
            }

            let entry = if !key.as_deref().map(|k| k.starts_with("sk_")).unwrap_or(false) {
                // Repli : INTERNAL_SECRET + serviceId dans le corps (SERVICE_KEY absent)
                if !safe_secret_equal(internal.as_deref(), Some(&app.cfg.internal_secret)) {
                    return err_json(401, "X-Service-Key requis (format sk_...) ou X-Internal-Secret valide");
                }
                let sid = match req.body.get("serviceId") {
                    Some(Value::String(s)) if !s.is_empty() => s.clone(),
                    _ => return err_json(400, "serviceId requis dans le body quand SERVICE_KEY absent"),
                };
                match app.lb.register_by_id(&sid, reg(&endpoint, domain.as_deref(), &app.gateway_id)) {
                    Some(e) => e,
                    None => return err_json(403, "Service introuvable ou désactivé — vérifiez SERVICE_ID dans votre .env"),
                }
            } else {
                match app.lb.register_with_key(key.as_deref().unwrap_or(""), reg(&endpoint, domain.as_deref(), &app.gateway_id)) {
                    Some(e) => e,
                    None => return err_json(403, "Clé invalide ou service désactivé — vérifiez SERVICE_KEY dans votre .env"),
                }
            };

            {
                let (a, id, ep) = (app.clone(), entry.id.clone(), endpoint.clone());
                tokio::spawn(async move { a.monitoring.update_service_endpoint(&id, &ep).await });
            }
            app.gateways.touch(&app.gateway_id);
            info!("LB: \"{}\" ({}) connecté via [{}]", entry.id, entry.service_type, app.gateway_id);
            json(
                200,
                &json!({
                    "success": true,
                    "serviceId": entry.id,
                    "serviceType": entry.service_type,
                    "gatewayId": app.gateway_id,
                    "heartbeatIntervalMs": 30_000,
                }),
            )
        }),
    );

    r.post(
        "/api/lb/heartbeat",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let Some(service_id) = lb_service_id(&req) else { return err_json(403, "Clé invalide ou serviceId manquant") };
            let metrics = req.body.get("metrics");
            if !matches!(metrics, Some(Value::Object(_)) | Some(Value::Array(_))) {
                return err_json(400, "metrics requis");
            }
            if !app.lb.heartbeat(&service_id, ServiceMetrics::from_value(metrics.unwrap())) {
                return err_json(404, "Service introuvable — ré-enregistrez-vous via /api/lb/register");
            }
            app.gateways.touch(&app.gateway_id);
            json(200, &json!({ "success": true }))
        }),
    );

    r.post(
        "/api/lb/deregister",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let Some(service_id) = lb_service_id(&req) else { return err_json(403, "Clé invalide ou serviceId manquant") };
            if app.lb.mark_offline(&service_id) {
                info!("LB: \"{service_id}\" déconnecté gracieusement");
            }
            json(200, &json!({ "success": true }))
        }),
    );
}

/// Identité d'un service : clé `X-Service-Key`, sinon secret interne + `serviceId` dans le corps.
fn lb_service_id(req: &Req) -> Option<String> {
    let app = &req.app;
    if let Some(key) = req.header("x-service-key").filter(|k| !k.is_empty()) {
        return app.lb.validate_key(key);
    }
    if safe_secret_equal(req.header("x-internal-secret"), Some(&app.cfg.internal_secret)) {
        return req.body.get("serviceId").and_then(|v| v.as_str()).map(str::to_string);
    }
    None
}

// ═══════════════════════════ Statistiques et santé ═══════════════════════════

fn register_stats_health(r: &mut Router) {
    r.get(
        "/api/stats",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let cached = app.stats_cache.lock().as_ref().filter(|(_, t)| t.elapsed() < Duration::from_secs(60)).map(|(d, _)| d.clone());
            let mut resp = match cached {
                Some(d) => json(200, &d),
                None => {
                    let cfg = app.cfg;
                    let get = |url: String| {
                        let (http, secret) = (app.http.clone(), cfg.internal_secret.clone());
                        async move {
                            let r = http.get(url).header("x-internal-secret", secret).header("Content-Type", "application/json").send().await.ok()?;
                            if !r.status().is_success() {
                                return None;
                            }
                            r.json::<Value>().await.ok()
                        }
                    };
                    let (users, servers) = tokio::join!(
                        get(format!("{}/internal/stats", app.service_url("users", &cfg.users_url))),
                        get(format!("{}/servers/internal/stats", app.service_url("servers", &cfg.servers_url))),
                    );
                    let pick = |v: &Option<Value>, k: &str| v.as_ref().and_then(|v| v.get(k)).filter(|x| !x.is_null()).cloned();
                    let connected = app.clients_len();
                    let data = json!({
                        "totalUsers": pick(&users, "totalUsers").unwrap_or(Value::Null),
                        "onlineUsers": pick(&users, "onlineUsers").unwrap_or(json!(connected)),
                        "totalServers": pick(&servers, "totalServers").unwrap_or(Value::Null),
                        "totalMembers": pick(&servers, "totalMembers").unwrap_or(Value::Null),
                        "connectedWS": connected,
                        "generatedAt": crate::iso::to_string(&chrono::Utc::now()),
                    });
                    *app.stats_cache.lock() = Some((data.clone(), std::time::Instant::now()));
                    json(200, &data)
                }
            };
            set_header(&mut resp, "cache-control", "public, max-age=60, stale-while-revalidate=120");
            resp
        }),
    );

    r.get(
        "/health",
        handler(|req: Req| async move {
            let app = req.app.clone();
            json(
                200,
                &json!({
                    "status": "ok",
                    "service": "gateway",
                    "uptime": app.started.elapsed().as_secs_f64(),
                    "connections": app.clients_len(),
                    "timestamp": crate::iso::to_string(&chrono::Utc::now()),
                }),
            )
        }),
    );

    r.get(
        "/stats",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let rooms = app.io().rooms().await.map(|r| r.len()).unwrap_or(0);
            json(200, &json!({ "connections": app.clients_len(), "rooms": rooms }))
        }),
    );

    // Diagnostic du socket mobile
    r.get(
        "/api/socket/status",
        handler(|req: Req| async move {
            let token = req.header("authorization").map(|a| a.replacen("Bearer ", "", 1)).filter(|t| !t.is_empty());
            let (mut valid, mut user_id) = (false, Value::Null);
            if let Some(t) = &token {
                if let Ok(claims) = crate::security::verify_jwt(t) {
                    valid = true;
                    user_id = claims.get("userId").cloned().unwrap_or(Value::Null);
                }
            }
            json(
                200,
                &json!({
                    "status": "ok",
                    "socketIO": true,
                    "transports": ["websocket", "polling"],
                    "tokenProvided": token.is_some(),
                    "tokenValid": valid,
                    "userId": user_id,
                    "timestamp": crate::iso::to_string(&chrono::Utc::now()),
                }),
            )
        }),
    );
}

// ═══════════════════════════ Amis ═══════════════════════════

async fn friends_fetch(req: &Req, method: Method, path: &str, body: Option<Value>, user_id: Option<&str>) -> Result<(u16, bytes::Bytes), reqwest::Error> {
    let app = &req.app;
    let base = app.service_url("friends", &app.cfg.friends_url);
    let mut rb = app.http.request(method, format!("{base}{path}")).header("Content-Type", "application/json");
    if let Some(a) = req.authorization() {
        rb = rb.header("authorization", a);
    }
    if let Some(u) = user_id {
        rb = rb.header("X-User-Id", u);
    }
    if let Some(b) = body {
        rb = rb.body(crate::json::stringify(&b));
    }
    let r = rb.send().await?;
    let status = r.status().as_u16();
    Ok((status, r.bytes().await?))
}

async fn emit_to(app: &Arc<AppState>, room: &str, ev: &str, payload: &Value) {
    let _ = app.io().to(room.to_string()).emit(ev, payload).await;
}

fn merge(data: Option<Value>, success: bool) -> Value {
    let mut m = Map::new();
    m.insert("success".into(), json!(success));
    if let Some(Value::Object(d)) = data {
        for (k, v) in d {
            m.insert(k, v);
        }
    }
    Value::Object(m)
}

fn register_friends(r: &mut Router) {
    r.post(
        "/api/friends/request",
        handler(|req: Req| async move {
            let from = req.user_id();
            match friends_fetch(&req, Method::POST, "/friends/request", Some(req.body.clone()), from.as_deref()).await {
                Ok((status, bytes)) => {
                    let Ok(data) = serde_json::from_slice::<Value>(&bytes) else { return err_json(502, "Service indisponible") };
                    let resp = json(status, &data);
                    if (200..300).contains(&status) {
                        if let Some(to) = data.get("toUserId").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                            let payload = json!({ "id": data.get("id").cloned().unwrap_or(Value::Null), "fromUserId": from, "toUserId": to });
                            emit_to(&req.app, &format!("user:{to}"), "FRIEND_REQUEST", &event("FRIEND_REQUEST", payload)).await;
                        }
                    }
                    resp
                }
                Err(e) => {
                    error!("Erreur envoi demande ami: {e}");
                    err_json(502, "Service indisponible")
                }
            }
        }),
    );

    r.post(
        "/api/friends/requests/:requestId/accept",
        handler(|req: Req| async move {
            let acceptor = req.user_id();
            let id = req.param("requestId").to_string();
            let mut body = req.body.as_object().cloned().unwrap_or_default();
            body.insert("userId".into(), json!(acceptor));
            match friends_fetch(&req, Method::POST, &format!("/friends/requests/{id}/accept"), Some(Value::Object(body)), acceptor.as_deref()).await {
                Ok((status, bytes)) => {
                    let Ok(data) = serde_json::from_slice::<Value>(&bytes) else { return err_json(502, "Service indisponible") };
                    if (200..300).contains(&status) {
                        let pick = |a: &str, b: &str| {
                            [a, b].iter().find_map(|k| data.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
                        };
                        for uid in [pick("user_id", "userId"), pick("friend_id", "friendId")].into_iter().flatten() {
                            emit_to(&req.app, &format!("user:{uid}"), "FRIEND_ACCEPT", &event("FRIEND_ACCEPT", data.clone())).await;
                        }
                    }
                    json(status, &data)
                }
                Err(e) => {
                    error!("Erreur accept ami: {e}");
                    err_json(502, "Service indisponible")
                }
            }
        }),
    );

    // Listes : GET /api/friends, /requests, /blocked
    for (route, path, kind) in [("/api/friends", "/friends/", 0), ("/api/friends/requests", "/friends/requests", 1), ("/api/friends/blocked", "/friends/blocked", 2)] {
        r.get(
            route,
            handler(move |req: Req| async move {
                let Some(uid) = req.user_id() else { return err_json(401, "Non authentifié") };
                match friends_fetch(&req, Method::GET, path, None, Some(&uid)).await {
                    Ok((status, bytes)) => {
                        let data = safe_json(&bytes);
                        let ok = (200..300).contains(&status);
                        let body = match (kind, ok) {
                            (1, true) => match data {
                                Some(Value::Array(a)) => json!({ "received": a, "sent": [] }),
                                Some(d) if !d.is_null() => d,
                                _ => json!({ "received": [], "sent": [] }),
                            },
                            (_, true) => data.unwrap_or_else(|| json!([])),
                            (_, false) => data.unwrap_or_else(|| json!({ "error": "Erreur service" })),
                        };
                        json(status, &body)
                    }
                    Err(e) => {
                        error!("Erreur friends: {e}");
                        if kind == 1 {
                            json(502, &json!({ "received": [], "sent": [] }))
                        } else {
                            err_json(502, "Service indisponible")
                        }
                    }
                }
            }),
        );
    }

    r.delete(
        "/api/friends/:friendId",
        handler(|req: Req| async move {
            let Some(uid) = req.user_id() else { return err_json(401, "Non authentifié") };
            let friend = req.param("friendId").to_string();
            match friends_fetch(&req, Method::DELETE, &format!("/friends/{friend}"), Some(json!({ "userId": uid })), Some(&uid)).await {
                Ok((status, bytes)) => {
                    let data = safe_json(&bytes);
                    let ok = (200..300).contains(&status);
                    if ok {
                        emit_to(&req.app, &format!("user:{uid}"), "FRIEND_REMOVE", &event("FRIEND_REMOVE", json!({ "friendId": friend }))).await;
                        emit_to(&req.app, &format!("user:{friend}"), "FRIEND_REMOVE", &event("FRIEND_REMOVE", json!({ "friendId": uid }))).await;
                    }
                    json(status, &merge(data, ok))
                }
                Err(e) => {
                    error!("Erreur removeFriend: {e}");
                    json(502, &json!({ "success": false, "error": "Service indisponible" }))
                }
            }
        }),
    );

    for (action, blocked) in [("block", true), ("unblock", false)] {
        r.post(
            &format!("/api/friends/:targetId/{action}"),
            handler(move |req: Req| async move {
                let Some(uid) = req.user_id() else { return err_json(401, "Non authentifié") };
                let target = req.param("targetId").to_string();
                let body = if blocked { json!({ "userId": uid, "blockedUserId": target }) } else { json!({ "userId": uid }) };
                match friends_fetch(&req, Method::POST, &format!("/friends/{target}/{action}"), Some(body), Some(&uid)).await {
                    Ok((status, bytes)) => {
                        let data = safe_json(&bytes);
                        let ok = (200..300).contains(&status);
                        if ok {
                            invalidate_block_cache(&req.app, &uid, &target);
                            let app = &req.app;
                            if blocked {
                                emit_to(app, &format!("user:{uid}"), "USER_BLOCKED", &json!({ "blockedId": target })).await;
                                emit_to(app, &format!("user:{target}"), "YOU_WERE_BLOCKED", &json!({ "byUserId": uid })).await;
                            } else {
                                emit_to(app, &format!("user:{uid}"), "USER_UNBLOCKED", &json!({ "unblockedId": target })).await;
                                emit_to(app, &format!("user:{target}"), "YOU_WERE_UNBLOCKED", &json!({ "byUserId": uid })).await;
                            }
                        }
                        json(status, &merge(data, ok))
                    }
                    Err(e) => {
                        error!("Erreur {action}User: {e}");
                        json(502, &json!({ "success": false, "error": "Service indisponible" }))
                    }
                }
            }),
        );
    }

    r.post(
        "/api/friends/requests/:requestId/decline",
        handler(|req: Req| async move {
            let Some(uid) = req.user_id() else { return err_json(401, "Non authentifié") };
            let id = req.param("requestId").to_string();
            match friends_fetch(&req, Method::POST, &format!("/friends/requests/{id}/decline"), Some(json!({ "userId": uid })), Some(&uid)).await {
                Ok((status, bytes)) => {
                    let data = safe_json(&bytes).or_else(|| Some(json!({})));
                    json(status, &merge(data, (200..300).contains(&status)))
                }
                Err(e) => {
                    error!("Erreur declineFriendRequest: {e}");
                    json(502, &json!({ "success": false, "error": "Service indisponible" }))
                }
            }
        }),
    );

    r.all("/api/friends/*", proxy_h("friends", |c| &c.friends_url, false, false));
    r.all("/api/friends", proxy_h("friends", |c| &c.friends_url, false, false));
}

/// Gestionnaire de proxy vers un microservice (`proxyRequest(getServiceUrl(...), …)`).
pub fn proxy_h(lb_type: &'static str, env_url: fn(&crate::config::Config) -> &String, with_type: bool, or_env: bool) -> super::Handler {
    handler(move |req: Req| async move {
        let cfg = req.app.cfg;
        let fallback = env_url(cfg).clone();
        let target = if or_env { req.app.service_url_or_env(lb_type, &fallback) } else { req.app.service_url(lb_type, &fallback) };
        proxy_request(req, target, Some(&fallback), if with_type { Some(lb_type) } else { None }).await
    })
}

// ═══════════════════════════ Hooks d'index.ts ═══════════════════════════

fn register_hooks(r: &mut Router) {
    // Après un claim-admin réussi : synchronise le server-node sans redémarrage.
    r.post(
        "/api/servers/:serverId/claim-admin",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let server_id = req.param("serverId").to_string();
            let user_id = req.user_id();
            if !is_id(&server_id) {
                return err_json(400, "serverId invalide");
            }
            let Some(user_id) = user_id else { return err_json(401, "Authentification requise") };
            let base = app.service_url("servers", &app.cfg.servers_url);
            let mut body = req.body.as_object().cloned().unwrap_or_default();
            body.insert("userId".into(), json!(user_id));
            body.insert("ownerId".into(), json!(user_id));
            let mut rb = app
                .http
                .post(format!("{base}/servers/{server_id}/claim-admin"))
                .header("Content-Type", "application/json")
                .header("X-User-Id", &user_id)
                .timeout(Duration::from_secs(15))
                .body(crate::json::stringify(&Value::Object(body)));
            if let Some(a) = req.authorization() {
                rb = rb.header("authorization", a);
            }
            match rb.send().await {
                Ok(r) => {
                    let (status, ok) = (r.status().as_u16(), r.status().is_success());
                    let bytes = r.bytes().await.unwrap_or_default();
                    let data = safe_json(&bytes).unwrap_or_else(|| json!({ "error": "Réponse vide" }));
                    if !ok {
                        return json(status, &data);
                    }
                    if app.has_node(&server_id) {
                        let (a, sid, uid) = (app.clone(), server_id.clone(), user_id.clone());
                        tokio::spawn(async move {
                            // Node hors ligne ou timeout → pris en compte au prochain démarrage du node.
                            if forward_to_node(&a, &sid, "SERVER_UPDATE", &json!({ "ownerId": uid }), 5_000).await.is_ok() {
                                emit_to(&a, &format!("server:{sid}"), "SERVER_UPDATE", &event("SERVER_UPDATE", json!({ "id": sid, "ownerId": uid }))).await;
                            }
                        });
                    }
                    json(200, &data)
                }
                Err(e) => {
                    error!("Erreur claim-admin gateway hook: {e}");
                    err_json(502, "Service indisponible")
                }
            }
        }),
    );

    // Webhook entrant : débit borné + diffusion en direct (5 messages / 2 s par webhook).
    r.post(
        "/api/servers/webhooks/:webhookId/:token",
        handler(|req: Req| async move {
            const BURST: usize = 5;
            const WINDOW_MS: i64 = 2_000;
            let app = req.app.clone();
            let (webhook_id, token) = (req.param("webhookId").to_string(), req.param("token").to_string());
            if !is_id(&webhook_id) || !WEBHOOK_TOKEN_RE.is_match(&token) {
                return json(401, &json!({ "error": "Webhook invalide", "code": "WEBHOOK_INVALID" }));
            }
            let now = now_ms();
            {
                let mut g = app.webhook_hits.lock();
                let hits: Vec<i64> = g.get(&webhook_id).cloned().unwrap_or_default().into_iter().filter(|t| now - t < WINDOW_MS).collect();
                if hits.len() >= BURST {
                    let retry_ms = WINDOW_MS - (now - hits[0]);
                    g.insert(webhook_id.clone(), hits);
                    let mut resp = json(429, &json!({ "error": "Trop de messages — ralentis", "code": "RATE_LIMITED", "retryAfterMs": retry_ms }));
                    set_header(&mut resp, "retry-after", &(((retry_ms as f64) / 1000.0).ceil() as i64).max(1).to_string());
                    return resp;
                }
                let mut hits = hits;
                hits.push(now);
                g.insert(webhook_id.clone(), hits);
                if g.len() > 10_000 {
                    g.clear(); // borne mémoire (fenêtres de 2 s)
                }
            }
            let base = app.service_url("servers", &app.cfg.servers_url);
            let body = if req.body.is_null() { json!({}) } else { req.body.clone() };
            let res = app
                .http
                .post(format!("{base}/servers/webhooks/{}/{}", encode_uri_component(&webhook_id), encode_uri_component(&token)))
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(10))
                .body(crate::json::stringify(&body))
                .send()
                .await;
            match res {
                Ok(r) => {
                    let (status, ok) = (r.status().as_u16(), r.status().is_success());
                    let bytes = r.bytes().await.unwrap_or_default();
                    let data = safe_json(&bytes).unwrap_or_else(|| json!({ "error": "Réponse vide" }));
                    if !ok {
                        return json(status, &data);
                    }
                    let sid = data.get("serverId").and_then(|v| v.as_str()).filter(|s| is_id(s));
                    let cid = data.get("channelId").and_then(|v| v.as_str()).filter(|s| is_id(s));
                    if let (Some(sid), Some(cid)) = (sid, cid) {
                        emit_to(&app, &crate::ws::ch_room(sid, cid), "SERVER_MESSAGE_NEW", &event("SERVER_MESSAGE_NEW", data.clone())).await;
                    }
                    json(201, &data)
                }
                Err(e) => {
                    error!("Erreur webhook entrant: {e}");
                    err_json(502, "Service indisponible")
                }
            }
        }),
    );
}

// ═══════════════════════════ Serveurs ═══════════════════════════

fn register_servers(r: &mut Router) {
    for p in ["/api/servers/join", "/api/servers/invite/*", "/api/servers/invites/*", "/api/servers/public/*", "/api/servers/discover/*", "/api/servers/badges/*", "/api/servers/admin/*"] {
        r.all(p, proxy_h("servers", |c| &c.servers_url, false, false));
    }

    // Liste des serveurs, enrichie avec les infos des nodes connectés
    r.get(
        "/api/servers",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let Some(user_id) = req.user_id() else { return err_json(401, "Authentification requise") };
            let base = app.service_url("servers", &app.cfg.servers_url);
            if base.is_empty() {
                return err_json(503, "Service indisponible — aucune instance active");
            }
            let mut rb = app
                .http
                .get(format!("{base}/servers?userId={}", encode_uri_component(&user_id)))
                .header("Content-Type", "application/json")
                .header("X-User-Id", &user_id);
            if let Some(a) = req.authorization() {
                rb = rb.header("authorization", a);
            }
            let res = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    error!("Erreur proxy GET /api/servers: {e}");
                    return err_json(502, "Service indisponible");
                }
            };
            let (status, ok) = (res.status().as_u16(), res.status().is_success());
            let bytes = res.bytes().await.unwrap_or_default();
            if !ok {
                return json(status, &safe_json(&bytes).unwrap_or_else(|| json!({ "error": "Service indisponible" })));
            }
            let Ok(servers) = serde_json::from_slice::<Value>(&bytes) else { return err_json(502, "Service indisponible") };
            let Value::Array(list) = servers else { return json(200, &servers) };

            let enriched = futures::future::join_all(list.into_iter().map(|mut server| {
                let app = app.clone();
                async move {
                    let id = server.get("id").and_then(|v| v.as_str()).map(str::to_string);
                    if let Some(id) = id {
                        if let Ok(info) = forward_to_node(&app, &id, "SERVER_INFO", &json!({}), 15_000).await {
                            // Les données du node ont la priorité
                            if let Value::Object(m) = &mut server {
                                for (src, dst) in [("iconUrl", "iconUrl"), ("bannerUrl", "bannerUrl"), ("name", "name"), ("description", "description")] {
                                    if truthy(info.get(src)) {
                                        m.insert(dst.into(), info[src].clone());
                                    }
                                }
                            }
                        }
                    }
                    server
                }
            }))
            .await;
            json(200, &Value::Array(enriched))
        }),
    );
    r.post("/api/servers", proxy_h("servers", |c| &c.servers_url, false, false));

    // Routes qui restent TOUJOURS vers le microservice
    for p in [
        "/api/servers/:serverId/join",
        "/api/servers/:serverId/leave",
        "/api/servers/:serverId/node-token",
        "/api/servers/:serverId/claim-admin",
        "/api/servers/:serverId/domain/*",
    ] {
        r.all(p, proxy_h("servers", |c| &c.servers_url, false, false));
    }

    // Upload de fichiers serveur (avant le catch-all /:serverId/*)
    r.post(
        "/api/servers/:serverId/files",
        handler(|req: Req| async move {
            let server_id = req.param("serverId").to_string();
            if !is_id(&server_id) {
                return err_json(400, "serverId invalide");
            }
            let node = req.app.node(&server_id);
            let query = req.original_url.split_once('?').map(|(_, q)| format!("?{}", q.split('?').next().unwrap_or(""))).unwrap_or_default();
            if let Some(ep) = node.and_then(|n| n.endpoint).filter(|e| !e.is_empty()) {
                return proxy_to_node_multipart(req, &ep, &format!("/files{query}"), &server_id).await;
            }
            // Fallback sans node : vers le servers microservice
            let base = req.app.service_url("servers", &req.app.cfg.servers_url);
            proxy_multipart_to_service(req, &base, &format!("/servers/{server_id}/files{query}")).await
        }),
    );

    // Lecture des fichiers uploadés
    r.get(
        "/api/servers/:serverId/files/:filename",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let (server_id, filename) = (req.param("serverId").to_string(), req.param("filename").to_string());
            if !is_id(&server_id) || !is_safe_file_segment(&filename) {
                return err_json(400, "Chemin invalide");
            }
            let origin = app.cfg.allowed_origins.first().cloned().unwrap_or_else(|| "http://localhost:4000".into());
            let (url, unavailable) = match app.node(&server_id).and_then(|n| n.endpoint).filter(|e| !e.is_empty()) {
                Some(ep) => (format!("{ep}/files/{}", encode_uri_component(&filename)), "Node indisponible"),
                None => (
                    format!(
                        "{}/servers/{}/files/{}",
                        app.service_url("servers", &app.cfg.servers_url),
                        encode_uri_component(&server_id),
                        encode_uri_component(&filename)
                    ),
                    "Service indisponible",
                ),
            };
            match app.http.get(url).timeout(Duration::from_secs(20)).send().await {
                Ok(r) => {
                    if !r.status().is_success() {
                        return json(r.status().as_u16(), &json!({ "error": "Fichier non trouvé" }));
                    }
                    let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
                    let bytes = r.bytes().await.unwrap_or_default();
                    let mut resp = send(200, "application/octet-stream", bytes.to_vec());
                    set_safe_file_headers(resp.headers_mut(), ct.as_deref());
                    set_header(&mut resp, "access-control-allow-origin", &origin);
                    set_header(&mut resp, "cross-origin-resource-policy", "cross-origin");
                    resp
                }
                Err(_) => err_json(502, unavailable),
            }
        }),
    );

    // Routes serveur-spécifiques : redirigées vers le server-node s'il est connecté
    r.all(
        "/api/servers/:serverId/*",
        handler(|req: Req| async move {
            let server_id = req.param("serverId").to_string();
            if let Some(ep) = req.app.node(&server_id).and_then(|n| n.endpoint).filter(|e| !e.is_empty()) {
                let node_path = rewrite_node_path(&req.original_url, &server_id);
                if req.header("content-type").unwrap_or("").contains("multipart/form-data") {
                    return proxy_to_node_multipart(req, &ep, &node_path, &server_id).await;
                }
                return proxy_to_node(req, &ep, &node_path, &server_id).await;
            }
            let base = req.app.service_url("servers", &req.app.cfg.servers_url);
            let fb = req.app.cfg.servers_url.clone();
            proxy_request(req, base, Some(&fb), None).await
        }),
    );

    // /api/servers/:serverId (sans sous-chemin) → /server sur le node
    r.all(
        "/api/servers/:serverId",
        handler(|req: Req| async move {
            let server_id = req.param("serverId").to_string();
            if let Some(ep) = req.app.node(&server_id).and_then(|n| n.endpoint).filter(|e| !e.is_empty()) {
                return proxy_to_node(req, &ep, "/server", &server_id).await;
            }
            let base = req.app.service_url("servers", &req.app.cfg.servers_url);
            let fb = req.app.cfg.servers_url.clone();
            proxy_request(req, base, Some(&fb), None).await
        }),
    );
    r.all("/api/servers", proxy_h("servers", |c| &c.servers_url, false, false));
}

// ═══════════════════════════ Médias ═══════════════════════════

/// Résout l'endpoint d'un service média en ignorant les instances localhost quand MEDIA_URL est distant.
fn resolve_media_endpoint(app: &Arc<AppState>, preferred: Option<&str>) -> String {
    let media_url = &app.cfg.media_url;
    let distant = !media_url.is_empty() && !LOCAL_HOST_RE.is_match(media_url);
    let all = app.lb.get_all();
    let instance = app
        .lb
        .select_best_by_location("media", preferred)
        .or_else(|| all.iter().find(|i| i.service_type == "media" && !i.is_local).cloned())
        .or_else(|| all.iter().find(|i| i.service_type == "media").cloned());
    if let Some(i) = &instance {
        if i.is_local && distant {
            warn!("MediaProxy: seule instance locale disponible ({}), fallback sur MEDIA_URL distant", i.endpoint);
            return media_url.clone();
        }
    }
    instance.map(|i| i.endpoint).unwrap_or_else(|| media_url.clone())
}

fn register_media(r: &mut Router) {
    // Téléchargement : GET /api/media/:location/:serviceId/:folder/:filename
    r.get(
        "/api/media/:location/:serviceId/:folder/:filename",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let origin = app.cfg.allowed_origins.first().cloned().unwrap_or_else(|| "http://localhost:4000".into());
            let mut resp = media_download(&req).await;
            set_header(&mut resp, "access-control-allow-origin", &origin);
            set_header(&mut resp, "cross-origin-resource-policy", "cross-origin");
            resp
        }),
    );

    for p in ["/api/media/upload/*", "/api/media/*"] {
        r.all(
            p,
            handler(|req: Req| async move {
                let preferred = req.header("x-media-location").map(str::to_string).or_else(|| req.query("location"));
                let target = resolve_media_endpoint(&req.app, preferred.as_deref());
                let api = crate::security::api_path(&req.original_url);
                let media_path = api.strip_prefix("/api").map(str::to_string).unwrap_or(api);
                proxy_to_media(req, &target, &media_path).await
            }),
        );
    }

    // Anciennes URLs /uploads/*
    r.get(
        "/uploads/*",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let origin = app.cfg.allowed_origins.first().cloned().unwrap_or_else(|| "http://localhost:4000".into());
            let media_url = app.cfg.media_url.clone();
            let mut resp = {
                let raw = app.lb.select_best("media");
                let target = match &raw {
                    Some(i) if i.is_local && !media_url.is_empty() && !LOCAL_HOST_RE.is_match(&media_url) => media_url.clone(),
                    Some(i) => i.endpoint.clone(),
                    None => media_url.clone(),
                };
                let rest = req.path().strip_prefix("/uploads/").unwrap_or("").to_string();
                let segments: Vec<String> = rest.split('/').map(super::decode).collect();
                // Les segments sont décodés par Express puis validés.
                if segments.is_empty() || segments.len() > 4 || !segments.iter().all(|s| is_safe_file_segment(s)) {
                    err_json(400, "Chemin invalide")
                } else {
                    let url = format!("{target}/uploads/{}", segments.iter().map(|s| encode_uri_component(s)).collect::<Vec<_>>().join("/"));
                    match app.http.get(url).send().await {
                        Ok(r) => {
                            if !r.status().is_success() {
                                json(r.status().as_u16(), &json!({ "error": "Fichier non trouvé" }))
                            } else {
                                let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
                                let cc = r.headers().get("cache-control").and_then(|v| v.to_str().ok()).map(str::to_string);
                                let bytes = r.bytes().await.unwrap_or_default();
                                let mut resp = send(200, "application/octet-stream", bytes.to_vec());
                                set_safe_file_headers(resp.headers_mut(), ct.as_deref());
                                if let Some(cc) = cc {
                                    set_header(&mut resp, "cache-control", &cc);
                                }
                                resp
                            }
                        }
                        Err(e) => {
                            error!("Erreur proxy uploads: {e}");
                            err_json(502, "Service média indisponible")
                        }
                    }
                }
            };
            set_header(&mut resp, "access-control-allow-origin", &origin);
            set_header(&mut resp, "cross-origin-resource-policy", "cross-origin");
            resp
        }),
    );
}

async fn media_download(req: &Req) -> Resp {
    let app = &req.app;
    let media_url = app.cfg.media_url.clone();
    let (location, service_id, folder, filename) = (req.param("location"), req.param("serviceId"), req.param("folder"), req.param("filename"));
    // Paramètres DÉCODÉS : `..%2F..` ne doit jamais atteindre un autre service.
    if !is_safe_file_segment(folder) || !is_safe_file_segment(filename) || !Regex::new(r"^[A-Za-z]{1,8}$").unwrap().is_match(location) {
        return err_json(400, "Chemin invalide");
    }
    let distant = !media_url.is_empty() && !LOCAL_HOST_RE.is_match(&media_url);
    let unreachable_local = |i: &crate::lb::registry::ServiceEntry| i.is_local && distant;

    // 1. L'instance par serviceId (même malsaine), mais uniquement du service MÉDIA.
    let mut instance = app.lb.get_by_id(service_id).filter(|i| i.service_type == "media");
    if let Some(i) = &instance {
        if unreachable_local(i) {
            warn!("MediaProxy: instance {service_id} a un endpoint local ({}), fallback sur endpoint distant", i.endpoint);
            instance = None;
        }
    }
    // 2. Sinon, n'importe quelle instance de la même région.
    if instance.is_none() {
        let all = app.lb.get_all();
        let regional = app
            .lb
            .select_best_by_location("media", Some(location))
            .or_else(|| {
                all.iter().find(|i| i.service_type == "media" && i.location.to_uppercase() == location.to_uppercase() && !unreachable_local(i)).cloned()
            })
            .or_else(|| all.iter().find(|i| i.service_type == "media" && !unreachable_local(i)).cloned());
        if let Some(rg) = regional {
            warn!("MediaProxy: instance {service_id} introuvable, fallback sur {}", rg.id);
            instance = Some(rg);
        }
    }
    let target = instance.as_ref().map(|i| i.endpoint.clone()).unwrap_or_else(|| media_url.clone());
    let media_path = format!("/uploads/{}/{}", encode_uri_component(folder), encode_uri_component(filename));

    let fetch = |endpoint: String| {
        let (http, path) = (app.http.clone(), media_path.clone());
        async move { http.get(format!("{endpoint}{path}")).send().await }
    };
    let result = async {
        let mut res = fetch(target.clone()).await?;
        // Une entrée périmée peut pointer vers une instance cassée : on retente via MEDIA_URL.
        if !res.status().is_success() && instance.is_some() && target != media_url {
            warn!("MediaProxy: {target}{media_path} → {}, nouvel essai via MEDIA_URL", res.status().as_u16());
            res = fetch(media_url.clone()).await?;
        }
        Ok::<_, reqwest::Error>(res)
    }
    .await;
    match result {
        Ok(res) => {
            if !res.status().is_success() {
                return json(res.status().as_u16(), &json!({ "error": "Fichier non trouvé" }));
            }
            let ct = res.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
            let cc = res.headers().get("cache-control").and_then(|v| v.to_str().ok()).map(str::to_string);
            let bytes = res.bytes().await.unwrap_or_default();
            let mut resp = send(200, "application/octet-stream", bytes.to_vec());
            set_safe_file_headers(resp.headers_mut(), ct.as_deref());
            if let Some(cc) = cc {
                set_header(&mut resp, "cache-control", &cc);
            }
            resp
        }
        Err(e) => {
            error!("Erreur download média: {e}");
            err_json(502, "Service média indisponible")
        }
    }
}

// ═══════════════════════════ Assemblage ═══════════════════════════

pub fn register_all_part1(r: &mut Router) {
    register_bootstrap(r);
    register_internal(r);
    register_lb(r);
}

pub fn register_stats(r: &mut Router) {
    // `/api/stats` précède les routes d'administration ; santé/stats WS viennent en dernier.
    let mut tmp = Router::default();
    register_stats_health(&mut tmp);
    for route in tmp.routes {
        if route.pattern == "/api/stats" {
            r.routes.push(route);
        }
    }
}

pub fn register_health(r: &mut Router) {
    let mut tmp = Router::default();
    register_stats_health(&mut tmp);
    for route in tmp.routes {
        if route.pattern != "/api/stats" {
            r.routes.push(route);
        }
    }
}

pub fn register_friends_routes(r: &mut Router) {
    register_friends(r);
}

pub fn register_hooks_routes(r: &mut Router) {
    register_hooks(r);
}

pub fn register_servers_routes(r: &mut Router) {
    register_servers(r);
}

pub fn register_media_routes(r: &mut Router) {
    register_media(r);
}

#[allow(dead_code)]
fn _unused(_: Resp) -> Resp {
    empty(200)
}
