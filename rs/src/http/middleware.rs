//! Chaîne de middlewares d'`index.ts` (lignes 77–270), dans le même ordre.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method};
use futures::FutureExt;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tracing::{error, warn};

use super::{
    accepts_html, empty, err_json, html_file, json, set_header, Req, Resp, Router, ERROR_404_HTML, ERROR_500_HTML,
    WEBHOOK_PATH,
};
use crate::config::{self, AUTH_BRUTEFORCE_PATHS, AUTH_BRUTEFORCE_REGEX};
use crate::state::AppState;

static LOCALHOST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^http://localhost(:\d+)?$").unwrap());
static BAD_PATH_1: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)%2e|%2f|%5c|\\").unwrap());
static BAD_PATH_2: Lazy<Regex> = Lazy::new(|| Regex::new(r"(^|/)\.{1,2}(/|$)").unwrap());

pub const SUPPORTED_API_VERSIONS: [u64; 1] = [1];
pub const LATEST_API_VERSION: u32 = 1;
const JSON_LIMIT: usize = 2 * 1024 * 1024;

fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn put(base: &mut HeaderMap, name: &str, value: &str) {
    if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
        base.insert(n, hv(value));
    }
}

/// `vary(res, field)` : ajoute un champ sans doublon.
fn add_vary(base: &mut HeaderMap, field: &str) {
    let cur = base.get(header::VARY).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if cur.split(',').any(|f| f.trim().eq_ignore_ascii_case(field) || f.trim() == "*") {
        return;
    }
    let next = if cur.is_empty() { field.to_string() } else { format!("{cur}, {field}") };
    put(base, "vary", &next);
}

/// L'origine est-elle acceptée par la fonction `origin` du CORS ?
fn cors_origin_allowed(origin: Option<&str>) -> bool {
    let cfg = config::get();
    match origin {
        None => true,
        Some(o) => (!cfg.is_production && LOCALHOST_RE.is_match(o)) || cfg.allowed_origins.iter().any(|a| a == o),
    }
}

/// En-têtes de sécurité de helmet 7 (mêmes valeurs que `index.ts`).
fn helmet_headers(base: &mut HeaderMap) {
    let prod = config::get().is_production;
    if prod {
        put(
            base,
            "content-security-policy",
            "default-src 'self';script-src 'self';style-src 'self' 'unsafe-inline';img-src 'self' data: blob: https:;\
media-src 'self' blob: https:;connect-src 'self' https: wss:;frame-ancestors 'none';object-src 'none';\
base-uri 'self';form-action 'self';upgrade-insecure-requests;font-src 'self' https: data:;script-src-attr 'none'",
        );
    }
    put(base, "cross-origin-opener-policy", "same-origin");
    put(base, "cross-origin-resource-policy", "cross-origin");
    put(base, "origin-agent-cluster", "?1");
    put(base, "referrer-policy", "strict-origin-when-cross-origin");
    if prod {
        put(base, "strict-transport-security", "max-age=31536000; includeSubDomains; preload");
    }
    put(base, "x-content-type-options", "nosniff");
    put(base, "x-dns-prefetch-control", "off");
    put(base, "x-download-options", "noopen");
    put(base, "x-frame-options", "SAMEORIGIN");
    put(base, "x-permitted-cross-domain-policies", "none");
    put(base, "x-xss-protection", "0");
}

/// Applique le CORS du paquet `cors` (origine reflétée, `credentials: true`).
/// Retourne `true` si la réponse est un préflight déjà traité (204).
pub fn apply_cors(base: &mut HeaderMap, method: &Method, headers: &HeaderMap) -> bool {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !cors_origin_allowed(origin) {
        return false; // pas d'en-têtes CORS : la requête continue (l'origine sera refusée plus loin en prod)
    }
    if let Some(o) = origin {
        put(base, "access-control-allow-origin", o);
    }
    add_vary(base, "Origin");
    put(base, "access-control-allow-credentials", "true");
    if method == Method::OPTIONS {
        put(base, "access-control-allow-methods", "GET,HEAD,PUT,PATCH,POST,DELETE");
        if let Some(h) = headers.get("access-control-request-headers").and_then(|v| v.to_str().ok()) {
            put(base, "access-control-allow-headers", h);
            add_vary(base, "Access-Control-Request-Headers");
        }
        return true;
    }
    false
}

fn merge_base(resp: &mut Resp, base: &HeaderMap) {
    for (name, value) in base.iter() {
        if name == header::VARY {
            let existing = resp.headers().get(header::VARY).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let add = value.to_str().unwrap_or("");
            let merged = if existing.is_empty() {
                add.to_string()
            } else {
                let mut parts: Vec<String> = existing.split(',').map(|s| s.trim().to_string()).collect();
                for f in add.split(',').map(|s| s.trim()) {
                    if !parts.iter().any(|p| p.eq_ignore_ascii_case(f)) {
                        parts.push(f.to_string());
                    }
                }
                parts.join(", ")
            };
            set_header(resp, "vary", &merged);
        } else if !resp.headers().contains_key(name) {
            resp.headers_mut().insert(name.clone(), value.clone());
        }
    }
}

/// `req.fresh` d'Express : la réponse en cache du client est-elle toujours valable ?
fn is_fresh(req_headers: &HeaderMap, resp: &Resp) -> bool {
    let none_match = req_headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok());
    let modified_since = req_headers.get(header::IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok());
    if none_match.is_none() && modified_since.is_none() {
        return false;
    }
    if let Some(cc) = req_headers.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        if cc.split(',').any(|d| d.trim() == "no-cache") {
            return false;
        }
    }
    if let Some(nm) = none_match.filter(|n| *n != "*") {
        let Some(etag) = resp.headers().get(header::ETAG).and_then(|v| v.to_str().ok()) else { return false };
        let matched = nm.split(',').map(|t| t.trim()).any(|t| t == etag || t == format!("W/{etag}") || format!("W/{t}") == etag);
        if !matched {
            return false;
        }
    }
    if modified_since.is_some() {
        // Aucune réponse de ce gateway ne porte Last-Modified : toujours périmé.
        return false;
    }
    true
}

pub async fn handle(app: Arc<AppState>, router: Arc<Router>, remote: Option<IpAddr>, request: axum::extract::Request) -> Resp {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let headers = parts.headers;
    let original_url = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());

    let mut base = HeaderMap::new();
    let mut route_label: Option<String> = None;
    let mut anomaly_armed = false;

    let req = Req {
        app: app.clone(),
        method: method.clone(),
        original_url: original_url.clone(),
        url: original_url.clone(),
        headers: headers.clone(),
        remote,
        params: vec![],
        body: Value::Null,
        body_stream: parking_lot::Mutex::new(Some(body)),
        api_version: LATEST_API_VERSION,
    };

    let mut resp = pipeline(req, &router, &mut base, &mut route_label, &mut anomaly_armed).await;
    merge_base(&mut resp, &base);

    // Fraîcheur (304) : seulement GET/HEAD en 2xx portant un ETag.
    if (method == Method::GET || method == Method::HEAD) && resp.status().is_success() && is_fresh(&headers, &resp) {
        *resp.status_mut() = axum::http::StatusCode::NOT_MODIFIED;
        *resp.body_mut() = Body::empty();
        for h in [header::CONTENT_TYPE, header::CONTENT_LENGTH, header::TRANSFER_ENCODING] {
            resp.headers_mut().remove(h);
        }
    }

    if anomaly_armed {
        let path = original_url.split('?').next().unwrap_or("").to_string();
        // `req.path` pour l'exclusion (après réécriture de version).
        let path_for_skip = crate::security::api_path(&path);
        if path_for_skip != "/health" && path_for_skip != "/api/health" {
            let subject = crate::anomaly::jwt_subject(headers.get("authorization").and_then(|v| v.to_str().ok()))
                .unwrap_or_else(|| crate::anomaly::ip_subject(&headers, remote));
            let endpoint = format!("{} {}", method, route_label.clone().unwrap_or(path_for_skip));
            let is_4xx = resp.status().as_u16() >= 400 && resp.status().as_u16() < 500;
            let app2 = app.clone();
            tokio::spawn(async move { crate::anomaly::record_and_score(&app2, &subject, &endpoint, is_4xx).await });
        }
    }
    resp
}

/// Erreurs levées par le parseur JSON (équivalent des erreurs `http-errors` de body-parser).
struct ParseErr {
    status: u16,
    kind: &'static str,
}

fn parse_err_resp(e: &ParseErr) -> Resp {
    let message = match e.kind {
        "entity.parse.failed" => "JSON invalide",
        "entity.too.large" => "Corps de requête trop volumineux",
        _ => "Requête invalide",
    };
    let code = e.kind.to_uppercase().replace(['.', '-'], "_");
    json(e.status, &json!({ "error": message, "code": code }))
}

async fn read_json_body(req: &mut Req) -> Result<(), ParseErr> {
    // Corps par défaut : `{}`.
    req.body = json!({});
    let ct = req.header("content-type").unwrap_or("").to_string();
    let mime = ct.split(';').next().unwrap_or("").trim().to_lowercase();
    let has_body = req.headers.contains_key(header::TRANSFER_ENCODING)
        || req.header("content-length").map(|v| v.trim().parse::<f64>().is_ok()).unwrap_or(false);
    if !has_body || mime != "application/json" {
        return Ok(());
    }
    // Jeu de caractères : seuls les utf-* sont acceptés.
    for p in ct.split(';').skip(1) {
        if let Some((k, v)) = p.split_once('=') {
            if k.trim().eq_ignore_ascii_case("charset") {
                let cs = v.trim().trim_matches('"').to_lowercase();
                if !cs.starts_with("utf-") {
                    return Err(ParseErr { status: 415, kind: "charset.unsupported" });
                }
            }
        }
    }
    if let Some(enc) = req.header("content-encoding") {
        if !enc.trim().eq_ignore_ascii_case("identity") && !enc.trim().is_empty() {
            return Err(ParseErr { status: 415, kind: "encoding.unsupported" });
        }
    }
    let bytes = match req.read_raw(JSON_LIMIT).await {
        Ok(b) => b,
        Err(super::BodyError::TooLarge) => return Err(ParseErr { status: 413, kind: "entity.too.large" }),
        Err(super::BodyError::Aborted) => return Err(ParseErr { status: 400, kind: "request.aborted" }),
    };
    let text = String::from_utf8_lossy(&bytes);
    if text.is_empty() {
        return Ok(());
    }
    let first = text.trim_start().chars().next();
    if first != Some('{') && first != Some('[') {
        return Err(ParseErr { status: 400, kind: "entity.parse.failed" });
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => {
            req.body = v;
            Ok(())
        }
        Err(_) => Err(ParseErr { status: 400, kind: "entity.parse.failed" }),
    }
}

async fn pipeline(
    mut req: Req,
    router: &Router,
    base: &mut HeaderMap,
    route_label: &mut Option<String>,
    anomaly_armed: &mut bool,
) -> Resp {
    let cfg = config::get();
    let app = req.app.clone();

    // 1. Webhooks entrants : CORS ouvert à toute origine, AVANT le CORS global.
    let raw_path = req.original_url.split('?').next().unwrap_or("").to_string();
    let is_webhook = WEBHOOK_PATH.is_match(&raw_path);
    if is_webhook {
        put(base, "access-control-allow-origin", "*");
        put(base, "access-control-allow-methods", "POST, OPTIONS");
        put(base, "access-control-allow-headers", "Content-Type");
        put(base, "access-control-expose-headers", "Retry-After");
        put(base, "access-control-max-age", "600");
        if req.method == Method::OPTIONS {
            return empty(204);
        }
    }

    // 2. CORS (préflight terminé ici pour une origine acceptée).
    let origin = req.header("origin").map(str::to_string);
    let preflight_done = apply_cors(base, &req.method, &req.headers);
    if preflight_done {
        let mut r = empty(204);
        set_header(&mut r, "content-length", "0");
        return r;
    }

    // 3. Origine refusée en production.
    if let Some(o) = &origin {
        if cfg.is_production && !cfg.allowed_origins.iter().any(|a| a == o) && !LOCALHOST_RE.is_match(o) && !is_webhook {
            warn!("CORS: origine non autorisée — {o}");
            return err_json(403, "Origine non autorisée");
        }
    }

    // 4. helmet
    helmet_headers(base);

    // 5. Chemins ambigus
    if BAD_PATH_1.is_match(&raw_path) || BAD_PATH_2.is_match(&raw_path) {
        return err_json(400, "Chemin invalide");
    }

    // 6. Version d'API : /api/vN → /api
    {
        let u = req.url.clone();
        let b = u.as_bytes();
        if b.len() >= 6 && u[..6].eq_ignore_ascii_case("/api/v") {
            let mut i = 6;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i > 6 && (i == b.len() || b[i] == b'/') {
                let version: Option<u64> = u[6..i].parse().ok();
                match version.filter(|v| SUPPORTED_API_VERSIONS.contains(v)) {
                    None => {
                        put(base, "x-api-supported-versions", &SUPPORTED_API_VERSIONS.map(|v| v.to_string()).join(","));
                        let shown = u[6..i].trim_start_matches('0');
                        let shown = if shown.is_empty() { "0" } else { shown };
                        return json(
                            400,
                            &json!({
                                "error": format!("Version d'API non supportée: v{shown}"),
                                "supported": SUPPORTED_API_VERSIONS.iter().map(|v| format!("v{v}")).collect::<Vec<_>>(),
                            }),
                        );
                    }
                    Some(v) => {
                        req.api_version = v as u32;
                        req.url = format!("/api{}", &u[i..]);
                    }
                }
            }
        }
        put(base, "x-api-version", &format!("v{}", req.api_version));
    }

    // 7. IP bannie
    let ip = req.client_ip();
    if let Ok(true) = app.redis.is_ip_banned(&ip).await {
        warn!("IP bannie bloquée: {ip} — {} {}", req.method, req.path());
        return err_json(403, "Accès interdit");
    }

    // 8. Limitation de débit HTTP (anonyme / utilisateur / admin)
    {
        let mut limiter = &app.limiters.anon;
        let mut limit_max = cfg.rate_limit_anon;
        let mut key = ip.clone();
        if let Some(token) = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")) {
            if let Ok(claims) = crate::security::verify_jwt(token) {
                let uid = ["userId", "id"].iter().find_map(|k| claims.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()));
                let role = claims.get("role").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("user");
                if let Some(uid) = uid {
                    key = uid.to_string();
                    if role == "admin" || role == "moderator" {
                        limiter = &app.limiters.admin;
                        limit_max = cfg.rate_limit_admin;
                    } else {
                        limiter = &app.limiters.user;
                        limit_max = cfg.rate_limit_user;
                    }
                }
            }
        }
        match limiter.consume(&app.redis.raw(), &key).await {
            Ok(r) if r.allowed => {
                put(base, "x-ratelimit-limit", &limit_max.to_string());
                put(base, "x-ratelimit-remaining", &r.remaining.to_string());
            }
            other => {
                // Toute erreur du limiteur (Redis compris) vaut refus, comme l'original.
                let _ = app.redis.increment_rate_limit_blocked().await;
                warn!("Rate limit HTTP dépassé: {key}");
                let retry = match other {
                    Ok(r) if r.ms_before_next > 0 => (r.ms_before_next as f64 / 1000.0).ceil() as i64,
                    _ => 1,
                };
                put(base, "retry-after", &retry.to_string());
                return err_json(429, "Trop de requêtes, réessayez plus tard");
            }
        }
    }

    // 9. Corps JSON (sauf médias, webhooks de paiement et multipart vers les nodes)
    {
        let path = req.path().to_string();
        let ct = req.header("content-type").unwrap_or("").to_string();
        let skip = path.starts_with("/api/media")
            || path.to_lowercase().starts_with("/api/subscriptions/webhooks/")
            || (ct.contains("multipart/form-data") && path.starts_with("/api/servers/"));
        if !skip {
            if let Err(e) = read_json_body(&mut req).await {
                return parse_err_resp(&e);
            }
        }
    }

    // 10. Détection d'anomalies (enregistrée après la réponse)
    *anomaly_armed = true;

    // 11. Brute-force sur les endpoints d'authentification
    if req.method == Method::POST || req.method == Method::PATCH || req.method == Method::PUT {
        let p = req.path().to_lowercase();
        let p = p.trim_end_matches('/');
        let hit = AUTH_BRUTEFORCE_PATHS.iter().any(|bp| p == *bp || p.starts_with(&format!("{bp}/")))
            || AUTH_BRUTEFORCE_REGEX.iter().any(|re| re.is_match(p));
        if hit {
            match app.limiters.auth.consume(&app.redis.raw(), &ip).await {
                Ok(r) if r.allowed => {}
                other => {
                    let _ = app.redis.increment_rate_limit_blocked().await;
                    warn!("Brute-force bloqué sur {} depuis {ip}", req.path());
                    let retry = match other {
                        Ok(r) if r.ms_before_next > 0 => (r.ms_before_next as f64 / 1000.0).ceil() as i64,
                        _ => 60,
                    };
                    put(base, "retry-after", &retry.to_string());
                    return err_json(429, "Trop de tentatives. Réessayez dans quelques minutes.");
                }
            }
        }
    }

    // 12. Routes
    let path = req.path().to_string();
    if let Some((route, params)) = router.find(&req.method, &path) {
        *route_label = Some(route.pattern.clone());
        req.params = params;
        let h = route.handler.clone();
        let accepts = accepts_html(&req.headers);
        return match std::panic::AssertUnwindSafe(h(req)).catch_unwind().await {
            Ok(r) => r,
            Err(_) => {
                error!("panic dans un gestionnaire de route");
                internal_error(accepts)
            }
        };
    }

    // 404
    if accepts_html(&req.headers) {
        return html_file(404, ERROR_404_HTML);
    }
    json(404, &json!({ "error": "Route not found", "path": path }))
}

pub fn internal_error(html: bool) -> Resp {
    if html {
        html_file(500, ERROR_500_HTML)
    } else {
        json(500, &json!({ "error": "Internal server error" }))
    }
}
