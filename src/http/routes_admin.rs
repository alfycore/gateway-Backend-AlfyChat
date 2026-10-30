//! Routes d'administration (équivalent de `http/admin.routes.ts`).

use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use super::proxy::safe_json;
use super::routes_misc::{entry_with_score, js_string, proxy_h};
use super::{err_json, handler, json, Req, Resp, Router};
use crate::lb::registry::{generate_service_key, is_service_type, PreRegister, SERVICE_TYPES};
use crate::monitoring_db::IncidentPatch;
use crate::state::AppState;

static SERVICE_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[a-z0-9][a-z0-9._-]{0,63}$").unwrap());
static HTTP_URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^https?://.+").unwrap());

/// Vérifie que l'appelant est administrateur. `Err(réponse)` sinon.
pub async fn require_admin(req: &Req) -> Result<String, Resp> {
    let Some(user_id) = req.user_id() else { return Err(err_json(401, "Non authentifié")) };
    let base = req.app.service_url("users", &req.app.cfg.users_url);
    let mut rb = req.app.http.get(format!("{base}/users/{user_id}"));
    if let Some(a) = req.authorization() {
        rb = rb.header("authorization", a);
    }
    match rb.send().await {
        Ok(r) => {
            let bytes = r.bytes().await.unwrap_or_default();
            let data = safe_json(&bytes);
            if data.as_ref().and_then(|d| d.get("role")).and_then(|r| r.as_str()) != Some("admin") {
                return Err(err_json(403, "Accès refusé"));
            }
            Ok(user_id)
        }
        Err(_) => Err(err_json(502, "Service indisponible")),
    }
}

macro_rules! admin {
    ($req:ident) => {
        match require_admin(&$req).await {
            Ok(u) => u,
            Err(r) => return r,
        }
    };
}

fn server_error() -> Resp {
    err_json(500, "Erreur serveur")
}

fn id_param(req: &Req) -> String {
    req.param("id").to_string()
}

fn bool_or_undefined(v: Option<&Value>) -> Option<bool> {
    v.and_then(|v| v.as_bool())
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        _ => true,
    }
}

fn string_list(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(|v| v.as_array()).map(|a| a.iter().map(|x| js_string(Some(x))).collect())
}

pub fn register(r: &mut Router) {
    // ── IP bannies ────────────────────────────────────────────────────────
    r.get(
        "/api/admin/gateway/stats",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let banned = app.redis.get_banned_ips().await;
            let stats = app.redis.get_rate_limit_stats().await;
            match (banned, stats) {
                (Ok(b), Ok((total, active))) => json(
                    200,
                    &json!({
                        "bannedIPs": b,
                        "rateLimitStats": { "totalBlocked": total, "activeWindows": active },
                        "config": {
                            "window": app.cfg.rate_limit_window,
                            "anon": app.cfg.rate_limit_anon,
                            "user": app.cfg.rate_limit_user,
                            "admin": app.cfg.rate_limit_admin,
                        },
                    }),
                ),
                (Err(e), _) | (_, Err(e)) => {
                    error!("Erreur stats gateway: {e}");
                    server_error()
                }
            }
        }),
    );

    r.post(
        "/api/admin/gateway/ban-ip",
        handler(|req: Req| async move {
            let user_id = admin!(req);
            let ip = match req.body.get("ip") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                _ => return err_json(400, "IP requise"),
            };
            let reason = req.body.get("reason").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("Banni par un administrateur").to_string();
            match req.app.redis.ban_ip(ip.trim(), &reason, &user_id).await {
                Ok(()) => {
                    info!("IP bannie: {ip} par {user_id} — raison: {reason}");
                    json(200, &json!({ "success": true }))
                }
                Err(e) => {
                    error!("Erreur ban IP: {e}");
                    server_error()
                }
            }
        }),
    );

    r.delete(
        "/api/admin/gateway/ban-ip/:ip",
        handler(|req: Req| async move {
            let user_id = admin!(req);
            let ip = super::decode(req.param("ip"));
            match req.app.redis.unban_ip(&ip).await {
                Ok(()) => {
                    info!("IP débannie: {ip} par {user_id}");
                    json(200, &json!({ "success": true }))
                }
                Err(e) => {
                    error!("Erreur unban IP: {e}");
                    server_error()
                }
            }
        }),
    );

    r.delete(
        "/api/admin/gateway/rate-limit/:ip",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let ip = super::decode(req.param("ip"));
            match req.app.redis.del(&format!("rl_auth:{ip}")).await {
                Ok(()) => {
                    info!("Rate limit auth réinitialisé pour {ip} par admin");
                    json(200, &json!({ "success": true, "message": format!("Rate limit réinitialisé pour {ip}") }))
                }
                Err(e) => {
                    error!("Erreur reset rate limit: {e}");
                    server_error()
                }
            }
        }),
    );

    // ── Supervision ───────────────────────────────────────────────────────
    r.get(
        "/api/admin/monitoring",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let (services, history, peak) = tokio::join!(
                app.monitoring.get_latest_service_status(),
                app.monitoring.get_user_stats_history(24),
                app.monitoring.get_peak_users(24),
            );
            match (services, history, peak) {
                (Ok(s), Ok(h), Ok(p)) => json(
                    200,
                    &json!({
                        "services": s,
                        "connectedUsers": { "current": app.clients_len(), "peak24h": p, "history": h },
                        "checkedAt": crate::iso::to_string(&chrono::Utc::now()),
                    }),
                ),
                _ => server_error(),
            }
        }),
    );

    r.get(
        "/api/admin/monitoring/service/:name",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let name = req.param("name").to_string();
            // `Math.min(parseInt(String(req.query.hours) || '24'), 168)` : sans paramètre, NaN → erreur SQL → 500.
            let hours = req.query("hours").and_then(|h| h.trim().split(|c: char| !c.is_ascii_digit() && c != '-').next().and_then(|s| s.parse::<i64>().ok()));
            let Some(hours) = hours.map(|h| h.min(168)) else { return server_error() };
            match req.app.monitoring.get_service_history(&name, hours).await {
                Ok(history) => json(200, &json!({ "service": name, "hours": hours, "history": history })),
                Err(e) => {
                    error!("Erreur /api/admin/monitoring/service: {e}");
                    server_error()
                }
            }
        }),
    );

    r.get(
        "/api/admin/monitoring/users/chart",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let period = req.query("period").unwrap_or_default();
            if !["30min", "10min", "hour", "day", "month"].contains(&period.as_str()) {
                return err_json(400, "period must be 30min, 10min, hour, day or month");
            }
            match req.app.monitoring.get_user_stats_aggregated(&period).await {
                Ok(data) => json(200, &json!({ "period": period, "data": data })),
                Err(e) => {
                    error!("Erreur /api/admin/monitoring/users/chart: {e}");
                    server_error()
                }
            }
        }),
    );

    // Statut public
    r.get(
        "/api/status",
        handler(|req: Req| async move {
            let app = req.app.clone();
            let statuses = app.monitoring.get_latest_service_status().await;
            let incidents = app.monitoring.get_incidents(false).await;
            let statuses = match statuses {
                Ok(s) => s,
                Err(e) => {
                    error!("Erreur /api/status: {e}");
                    return server_error();
                }
            };
            let mut names: Vec<String> = vec![];
            for s in &statuses {
                if let Some(n) = s.get("service").and_then(|v| v.as_str()) {
                    if !names.iter().any(|x| x == n) {
                        names.push(n.to_string());
                    }
                }
            }
            let uptimes = futures::future::join_all(names.iter().map(|n| app.monitoring.get_service_uptime_daily(n, 90))).await;
            let mut uptime = serde_json::Map::new();
            for (n, u) in names.iter().zip(uptimes) {
                uptime.insert(n.clone(), Value::Array(u));
            }
            // Sous-ensemble public des instances (ni métriques ni endpoints internes)
            let instances: Vec<Value> = app
                .lb
                .get_all()
                .iter()
                .map(|i| {
                    json!({
                        "serviceType": i.service_type,
                        "domain": i.domain,
                        "location": i.location,
                        "healthy": i.healthy,
                        "lastHeartbeat": i.last_heartbeat.map(|d| crate::iso::to_string(&d)),
                        "score": crate::lb::registry::compute_score(i),
                    })
                })
                .collect();
            json(200, &json!({ "services": statuses, "incidents": incidents, "uptime": Value::Object(uptime), "instances": instances }))
        }),
    );

    // ── Incidents ─────────────────────────────────────────────────────────
    r.get(
        "/api/admin/status/incidents",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let include = req.query("includeResolved").as_deref() == Some("true");
            json(200, &json!({ "incidents": req.app.monitoring.get_incidents(include).await }))
        }),
    );

    r.post(
        "/api/admin/status/incidents",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let b = &req.body;
            let title = b.get("title").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let severity = b.get("severity").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let (Some(title), Some(severity)) = (title, severity) else { return err_json(400, "title et severity requis") };
            let created_by = req.user_id();
            let services = string_list(b.get("services"));
            let id = req
                .app
                .monitoring
                .create_incident(
                    title,
                    b.get("message").and_then(|v| v.as_str()),
                    severity,
                    services.as_deref(),
                    b.get("status").and_then(|v| v.as_str()),
                    created_by.as_deref(),
                )
                .await;
            match id {
                Some(id) => json(201, &json!({ "id": id })),
                None => err_json(500, "Erreur création incident"),
            }
        }),
    );

    r.patch(
        "/api/admin/status/incidents/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let Some(id) = parse_int(req.param("id")) else { return err_json(400, "ID invalide") };
            let b = &req.body;
            let patch = IncidentPatch {
                title: b.get("title").and_then(|v| v.as_str()).map(str::to_string),
                message: b.get("message").map(|v| v.as_str().map(str::to_string)),
                severity: b.get("severity").and_then(|v| v.as_str()).map(str::to_string),
                services: string_list(b.get("services")),
                status: b.get("status").and_then(|v| v.as_str()).map(str::to_string),
            };
            if req.app.monitoring.update_incident(id, patch).await {
                json(200, &json!({ "success": true }))
            } else {
                err_json(500, "Erreur mise à jour")
            }
        }),
    );

    r.delete(
        "/api/admin/status/incidents/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let Some(id) = parse_int(req.param("id")) else { return err_json(400, "ID invalide") };
            if req.app.monitoring.delete_incident(id).await {
                json(200, &json!({ "success": true }))
            } else {
                err_json(500, "Erreur suppression")
            }
        }),
    );

    // ── Registre des instances de service ─────────────────────────────────
    r.get(
        "/api/admin/services",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let instances: Vec<Value> = req.app.lb.get_all().iter().map(entry_with_score).collect();
            json(200, &json!({ "instances": instances, "types": SERVICE_TYPES }))
        }),
    );

    r.get(
        "/api/admin/services/degraded",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let degraded: Vec<Value> = req
                .app
                .lb
                .get_degraded()
                .iter()
                .map(|i| {
                    let mut m = serde_json::Map::new();
                    m.insert("id".into(), json!(i.id));
                    m.insert("serviceType".into(), json!(i.service_type));
                    m.insert("endpoint".into(), json!(i.endpoint));
                    m.insert("domain".into(), json!(i.domain));
                    if let Some(d) = &i.degraded_at {
                        m.insert("degradedAt".into(), json!(crate::iso::to_string(d)));
                    }
                    if let Some(r) = &i.degraded_reason {
                        m.insert("degradedReason".into(), json!(r));
                    }
                    Value::Object(m)
                })
                .collect();
            json(200, &json!({ "degraded": degraded }))
        }),
    );

    r.get(
        "/api/admin/services/:type",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let t = req.param("type").to_string();
            if !is_service_type(&t) {
                return err_json(400, "Type de service inconnu");
            }
            let instances: Vec<Value> = req.app.lb.get_instances(&t, true, true).iter().map(entry_with_score).collect();
            json(200, &json!({ "instances": instances }))
        }),
    );

    r.post(
        "/api/admin/services",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let b = &req.body;
            let str_of = |k: &str| match b.get(k) {
                None | Some(Value::Null) => String::new(),
                Some(v) => js_string(Some(v)).trim().to_string(),
            };
            let id = str_of("id");
            let endpoint = str_of("endpoint").trim_end_matches('/').to_string();
            let location = str_of("location").to_uppercase();
            let service_type = b.get("serviceType").and_then(|v| v.as_str()).map(str::to_string);

            if id.is_empty() || !SERVICE_ID_RE.is_match(&id) {
                return err_json(400, "Identifiant invalide (lettres, chiffres, . _ - ; 64 caractères max)");
            }
            let Some(service_type) = service_type.filter(|t| is_service_type(t)) else {
                return err_json(400, &format!("Type inconnu — attendus : {}", SERVICE_TYPES.join(", ")));
            };
            if location.is_empty() {
                return err_json(400, "Zone requise");
            }
            let host = match url::Url::parse(&endpoint) {
                Ok(u) if u.scheme() == "http" || u.scheme() == "https" => match (u.host_str(), u.port()) {
                    (Some(h), Some(p)) => format!("{h}:{p}"),
                    (Some(h), None) => h.to_string(),
                    _ => return err_json(400, "URL invalide — format attendu : https://messages.exemple.app"),
                },
                _ => return err_json(400, "URL invalide — format attendu : https://messages.exemple.app"),
            };
            if crate::config::IP_ENDPOINT_RE.is_match(&endpoint) {
                return err_json(400, "Adresse IP non autorisée — utilisez un nom de domaine");
            }
            // Ré-enregistrer un id existant écrasait l'instance et régénérait sa clé en silence.
            if app.lb.get_by_id(&id).is_some() {
                return err_json(409, &format!("Une instance « {id} » existe déjà"));
            }
            let domain = Some(str_of("domain")).filter(|d| !d.is_empty()).unwrap_or(host);

            let instance = app.lb.pre_register(PreRegister {
                id: &id,
                service_type: &service_type,
                location: &location,
                enabled: Some(true),
                key_hash: None,
                endpoint: Some(&endpoint),
                domain: Some(&domain),
            });
            let (raw_key, hash) = generate_service_key();
            app.lb.add_key_hash(&id, &hash);
            // L'UPDATE du hash doit suivre l'INSERT, sinon la clé pourrait ne jamais être persistée.
            app.monitoring.upsert_service_instance(&id, &service_type, &endpoint, &domain, &location).await;
            app.monitoring.store_service_key_hash(&id, &raw_key).await;
            app.allowed_service_ids.lock().insert(id.clone());
            app.banned_service_ids.lock().remove(&id);
            info!("Admin: service \"{id}\" ajouté avec une clé unique");
            json(201, &json!({ "success": true, "instance": instance, "serviceKey": raw_key }))
        }),
    );

    r.post(
        "/api/admin/services/:id/restore",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let id = id_param(&req);
            if !req.app.lb.restore_instance(&id) {
                return err_json(404, "Instance introuvable");
            }
            info!("Admin: instance \"{id}\" restaurée manuellement");
            json(200, &json!({ "success": true, "message": format!("Instance \"{id}\" remise en service") }))
        }),
    );

    r.patch(
        "/api/admin/services/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let id = id_param(&req);
            let Some(enabled) = bool_or_undefined(req.body.get("enabled")) else {
                return err_json(400, "Le champ \"enabled\" (boolean) est requis");
            };
            if !app.lb.set_enabled(&id, enabled) {
                return err_json(404, "Instance introuvable");
            }
            spawn_set_enabled(&app, &id, enabled);
            info!("Admin: instance \"{id}\" {}", if enabled { "activée" } else { "désactivée" });
            json(200, &json!({ "success": true, "enabled": enabled }))
        }),
    );

    r.put(
        "/api/admin/services/:id/endpoint",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let id = id_param(&req);
            let endpoint = req.body.get("endpoint").and_then(|v| v.as_str()).filter(|e| !e.is_empty() && HTTP_URL_RE.is_match(e));
            let Some(endpoint) = endpoint else { return err_json(400, "Un endpoint HTTP(S) valide est requis") };
            let ep = endpoint.trim().to_string();
            if !app.lb.update_endpoint(&id, &ep) {
                return err_json(404, "Instance introuvable");
            }
            let (a, i, e) = (app.clone(), id.clone(), ep.clone());
            tokio::spawn(async move { a.monitoring.update_service_endpoint(&i, &e).await });
            info!("Admin: endpoint de \"{id}\" mis à jour → {ep}");
            json(200, &json!({ "success": true, "endpoint": ep }))
        }),
    );

    r.delete(
        "/api/admin/services/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let id = id_param(&req);
            if !app.lb.remove(&id) {
                return err_json(404, "Instance introuvable");
            }
            app.banned_service_ids.lock().insert(id.clone());
            app.allowed_service_ids.lock().remove(&id);
            info!("ServiceRegistry: instance \"{id}\" supprimée et bannie par un admin");
            let (a, i) = (app.clone(), id.clone());
            tokio::spawn(async move { a.monitoring.remove_service_instance(&i).await });
            json(200, &json!({ "success": true }))
        }),
    );

    r.post(
        "/api/admin/services/:id/rotate-key",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let id = id_param(&req);
            if app.lb.get_by_id(&id).is_none() {
                return err_json(404, "Instance introuvable");
            }
            let (raw_key, hash) = generate_service_key();
            app.lb.add_key_hash(&id, &hash);
            let (a, i, k) = (app.clone(), id.clone(), raw_key.clone());
            tokio::spawn(async move { a.monitoring.store_service_key_hash(&i, &k).await });
            info!("Admin: clé régénérée pour le service \"{id}\"");
            json(200, &json!({ "success": true, "serviceKey": raw_key }))
        }),
    );

    // ── Rapport d'erreur d'un microservice ────────────────────────────────
    r.post(
        "/api/internal/service-error",
        handler(|req: Req| async move {
            let app = req.app.clone();
            if !crate::security::safe_secret_equal(req.header("x-internal-secret"), Some(&app.cfg.internal_secret)) {
                return err_json(401, "Non autorisé");
            }
            let b = &req.body;
            let service_id = b.get("serviceId").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let message = b.get("message").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let (Some(service_id), Some(message)) = (service_id, message) else { return err_json(400, "serviceId et message requis") };
            let error_type = b.get("errorType").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let stack = b.get("stack").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            let sev = b.get("severity").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("warning");
            let title = format!("[{service_id}] {}", error_type.unwrap_or("Erreur"));

            let full_message = format!("{message}{}", stack.map(|s| format!("\n\nStack:\n{s}")).unwrap_or_default());
            let services = vec![service_id.to_string()];
            app.monitoring.create_incident(&title, Some(&full_message), sev, Some(&services), Some("investigating"), Some("system")).await;

            let mail_body = [
                format!("Le service \"{service_id}\" a signalé une erreur {}.", sev.to_uppercase()),
                String::new(),
                format!("  Type    : {}", error_type.unwrap_or("Inconnu")),
                format!("  Message : {message}"),
                stack.map(|s| format!("\nStack:\n{s}")).unwrap_or_default(),
                String::new(),
                format!("  Heure   : {}", crate::iso::to_string(&chrono::Utc::now())),
                String::new(),
                "Un incident a été créé automatiquement dans le dashboard admin.".to_string(),
                String::new(),
                "— AlfyChat Gateway".to_string(),
            ]
            .join("\n");
            let to = app.cfg.admin_alert_emails.clone();
            let subject = format!("[AlfyChat] ⚠️ Erreur service : {service_id}");
            tokio::spawn(async move { crate::mailer::send_mail(&to, &subject, &mail_body).await });
            error!(service_id = service_id, "[service-error] incident créé : {message}");
            json(200, &json!({ "success": true }))
        }),
    );

    // ── Gateways (multi-gateway) ──────────────────────────────────────────
    r.get(
        "/api/admin/lb/gateways",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let gateways: Vec<Value> = app
                .gateways
                .get_all()
                .iter()
                .map(|g| {
                    let mut v = serde_json::to_value(g).unwrap_or(Value::Null);
                    if let Value::Object(m) = &mut v {
                        m.insert("isSelf".into(), json!(g.id == app.gateway_id));
                        m.insert("online".into(), json!(app.gateways.is_online(&g.id, 120_000)));
                    }
                    v
                })
                .collect();
            json(200, &json!({ "gateways": gateways }))
        }),
    );

    r.post(
        "/api/admin/lb/gateways",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let b = &req.body;
            let (id, name, url) = (b.get("id"), b.get("name"), b.get("url"));
            if !truthy(id) || !truthy(name) || !truthy(url) {
                return err_json(400, "id, name, url requis");
            }
            let (id, name, url) = (js_string(id), js_string(name), js_string(url));
            if !HTTP_URL_RE.is_match(&url) {
                return err_json(400, "url doit être un endpoint HTTP(S) valide");
            }
            let entry = app.gateways.register(&id, &name, &url, Some(true), false);
            let (a, i, n, u) = (app.clone(), id.clone(), name.clone(), url.clone());
            tokio::spawn(async move { a.monitoring.upsert_gateway(&i, &n, &u, true).await });
            info!("Admin: gateway \"{id}\" ajouté");
            json(201, &json!({ "success": true, "gateway": entry }))
        }),
    );

    r.patch(
        "/api/admin/lb/gateways/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let gid = id_param(&req);
            let b = &req.body;
            let name = b.get("name").map(|v| js_string(Some(v)));
            let url = b.get("url").map(|v| js_string(Some(v)));
            let enabled = b.get("enabled").map(|v| truthy(Some(v)));
            if name.is_some() || url.is_some() {
                app.gateways.update(&gid, name.as_deref(), url.as_deref());
            }
            if let Some(e) = enabled {
                app.gateways.set_enabled(&gid, e);
            }
            let (a, g) = (app.clone(), gid.clone());
            tokio::spawn(async move { a.monitoring.patch_gateway(&g, name.as_deref(), url.as_deref(), enabled).await });
            info!("Admin: gateway \"{gid}\" mis à jour");
            json(200, &json!({ "success": true }))
        }),
    );

    r.delete(
        "/api/admin/lb/gateways/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let gid = id_param(&req);
            if gid == app.gateway_id {
                return err_json(400, "Impossible de supprimer le gateway courant");
            }
            if !app.gateways.remove(&gid) {
                return err_json(404, "Gateway introuvable");
            }
            let a = app.clone();
            tokio::spawn(async move { a.monitoring.delete_gateway(&gid).await });
            json(200, &json!({ "success": true }))
        }),
    );

    // ── Services LB (nouveau système) ─────────────────────────────────────
    r.get(
        "/api/admin/lb/services",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let instances: Vec<Value> = req.app.lb.get_all().iter().map(entry_with_score).collect();
            json(200, &json!({ "instances": instances }))
        }),
    );

    r.post(
        "/api/admin/lb/services",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let b = &req.body;
            let (id, service_type, location) = (b.get("id"), b.get("serviceType"), b.get("location"));
            if !truthy(id) || !truthy(location) {
                return err_json(400, "id, serviceType, location requis");
            }
            let Some(st) = service_type.and_then(|v| v.as_str()).filter(|t| is_service_type(t)) else {
                return err_json(400, &format!("Type inconnu — attendus : {}", SERVICE_TYPES.join(", ")));
            };
            let id = js_string(id);
            let location = js_string(location).to_uppercase();
            if app.lb.get_by_id(&id).is_some() {
                return err_json(409, &format!("Un service avec l'id \"{id}\" existe déjà"));
            }
            let (raw_key, hash) = generate_service_key();
            app.lb.pre_register(PreRegister {
                id: &id,
                service_type: st,
                location: &location,
                enabled: Some(true),
                key_hash: Some(&hash),
                endpoint: None,
                domain: None,
            });
            app.monitoring.upsert_service_instance(&id, st, "", "", &location).await;
            app.monitoring.store_service_key_hash(&id, &raw_key).await;
            app.allowed_service_ids.lock().insert(id.clone());
            app.banned_service_ids.lock().remove(&id);
            info!("Admin: service LB \"{id}\" créé — clé générée");
            json(
                201,
                &json!({
                    "success": true,
                    "serviceKey": raw_key,
                    "hint": format!("Ajoutez SERVICE_KEY={raw_key} dans le .env du microservice \"{id}\""),
                }),
            )
        }),
    );

    r.post(
        "/api/admin/lb/services/:id/rotate-key",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let sid = id_param(&req);
            if app.lb.get_by_id(&sid).is_none() {
                return err_json(404, "Service introuvable");
            }
            let (raw_key, hash) = generate_service_key();
            app.lb.add_key_hash(&sid, &hash);
            let (a, s, k) = (app.clone(), sid.clone(), raw_key.clone());
            tokio::spawn(async move { a.monitoring.store_service_key_hash(&s, &k).await });
            info!("Admin: clé rotée pour service \"{sid}\"");
            json(200, &json!({ "success": true, "serviceKey": raw_key }))
        }),
    );

    r.delete(
        "/api/admin/lb/services/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let sid = id_param(&req);
            if !app.lb.remove(&sid) {
                return err_json(404, "Service introuvable");
            }
            app.banned_service_ids.lock().insert(sid.clone());
            app.allowed_service_ids.lock().remove(&sid);
            let (a, s) = (app.clone(), sid.clone());
            tokio::spawn(async move { a.monitoring.remove_service_instance(&s).await });
            info!("Admin: service LB \"{sid}\" supprimé");
            json(200, &json!({ "success": true }))
        }),
    );

    r.patch(
        "/api/admin/lb/services/:id",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let sid = id_param(&req);
            if let Some(enabled) = bool_or_undefined(req.body.get("enabled")) {
                app.lb.set_enabled(&sid, enabled);
                spawn_set_enabled(&app, &sid, enabled);
            }
            if let Some(ep) = req.body.get("endpoint").and_then(|v| v.as_str()).filter(|e| !e.is_empty()) {
                app.lb.update_endpoint(&sid, ep);
                let (a, s, e) = (app.clone(), sid.clone(), ep.to_string());
                tokio::spawn(async move { a.monitoring.update_service_endpoint(&s, &e).await });
            }
            json(200, &json!({ "success": true }))
        }),
    );

    r.post(
        "/api/admin/lb/services/:id/restore",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let sid = id_param(&req);
            if !req.app.lb.restore_instance(&sid) {
                return err_json(404, "Service introuvable");
            }
            json(200, &json!({ "success": true }))
        }),
    );

    // Recharge tous les hashes de clés depuis la DB, sans redémarrer.
    r.post(
        "/api/admin/lb/reload-keys",
        handler(|req: Req| async move {
            let _ = admin!(req);
            let app = req.app.clone();
            let mut count = 0;
            for row in app.monitoring.load_service_instances().await {
                if let Some(h) = row.service_key_hash.filter(|h| !h.is_empty()) {
                    app.lb.add_key_hash(&row.id, &h);
                    count += 1;
                }
            }
            info!("Admin: {count} clé(s) rechargée(s) depuis la DB");
            json(200, &json!({ "success": true, "reloaded": count }))
        }),
    );

    // Helpdesk → service users (avant le fourre-tout /api/admin)
    r.all("/api/helpdesk/*", proxy_h("users", |c| &c.users_url, false, false));
    r.all("/api/helpdesk", proxy_h("users", |c| &c.users_url, false, false));
    r.all("/api/admin/*", proxy_h("users", |c| &c.users_url, false, false));
    r.all("/api/admin", proxy_h("users", |c| &c.users_url, false, false));
}

fn spawn_set_enabled(app: &Arc<AppState>, id: &str, enabled: bool) {
    let (a, i) = (app.clone(), id.to_string());
    tokio::spawn(async move { a.monitoring.set_instance_enabled(&i, enabled).await });
    let mut banned = app.banned_service_ids.lock();
    if enabled {
        banned.remove(id);
    } else {
        banned.insert(id.to_string());
    }
}

/// `parseInt(s)` → `None` pour NaN.
fn parse_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<i64>().ok().map(|n| if neg { -n } else { n })
}

#[allow(dead_code)]
fn _warn() {
    warn!("");
}
