//! Fonctions de proxy HTTP (équivalent de `http/proxy.ts`).

use std::time::Duration;

use axum::body::Body;
use axum::http::Method;
use serde_json::{json, Map, Value};
use tracing::{error, warn};

use super::{empty, err_json, json, send, set_header, BodyError, Req, Resp};
use crate::config;
use crate::security::{api_path, client_ip_headers, derive_node_secret, encode_uri_component, set_safe_file_headers};

/// Un node ou un service qui ne répond pas ne doit pas immobiliser la requête.
const NODE_TIMEOUT: Duration = Duration::from_millis(20_000);
const UPLOAD_TIMEOUT: Duration = Duration::from_millis(120_000);
/// Plafond de taille des corps bruts relayés (upload). Au-delà : 413.
const MAX_RAW_BODY: usize = 64 * 1024 * 1024;

fn is_read(m: &Method) -> bool {
    m == Method::GET || m == Method::HEAD
}

/// `safeJson` : `None` si le corps est vide ou n'est pas du JSON.
pub fn safe_json(bytes: &[u8]) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

/// Force `charset=utf-8` comme `res.send(string)`.
fn with_charset(ct: &str) -> String {
    let lower = ct.to_lowercase();
    if let Some(i) = lower.find("charset=") {
        let end = lower[i..].find(';').map(|e| i + e).unwrap_or(lower.len());
        format!("{}charset=utf-8{}", &ct[..i], &ct[end..])
    } else {
        format!("{ct}; charset=utf-8")
    }
}

fn first_origin() -> String {
    config::get().allowed_origins.first().cloned().unwrap_or_else(|| "http://localhost:4000".into())
}

fn body_error(err: BodyError, context: &str) -> Resp {
    match err {
        BodyError::TooLarge => err_json(413, "Fichier trop volumineux"),
        BodyError::Aborted => {
            // Le client est parti : rien à renvoyer.
            warn!("{context} (client interrompu)");
            empty(499)
        }
    }
}

fn is_media_type(ct: &str) -> bool {
    ct.starts_with("image/") || ct.starts_with("video/") || ct.starts_with("audio/") || ct.starts_with("application/octet-stream")
}

/// Proxy JSON vers un microservice, avec bascule sur les autres instances saines pour les méthodes idempotentes.
pub async fn proxy_request(req: Req, target_url: String, fallback_url: Option<&str>, service_type: Option<&str>) -> Resp {
    let app = req.app.clone();
    let cfg = config::get();
    let user_id = req.user_id();
    let service_path = api_path(&req.original_url).strip_prefix("/api").map(str::to_string).unwrap_or_else(|| api_path(&req.original_url));
    let skip_inject = service_path.to_lowercase().starts_with("/friends/request");

    // Le `userId` du corps est TOUJOURS celui du jeton ; `ownerId` n'est jamais transmis.
    let mut body_to_send: Option<Value> = if req.body.is_null() { None } else { Some(req.body.clone()) };
    if !is_read(&req.method) && !skip_inject {
        if let Some(Value::Object(m)) = &req.body.as_object().map(|_| req.body.clone()) {
            let mut rest: Map<String, Value> = m.clone();
            rest.remove("userId");
            rest.remove("ownerId");
            if let Some(u) = &user_id {
                rest.insert("userId".into(), json!(u));
            }
            body_to_send = Some(Value::Object(rest));
        }
    }

    if target_url.is_empty() {
        error!("[Proxy] Aucune instance LB disponible pour {}", service_type.unwrap_or(&req.original_url));
        return err_json(503, "Service indisponible — aucune instance active");
    }

    // Le basculement ne concerne que les méthodes idempotentes (rejouer un POST créait des doublons).
    let idempotent = matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS");
    let mut urls: Vec<String> = vec![target_url.clone()];
    if let (Some(st), true) = (service_type, idempotent) {
        let mut others: Vec<_> = app.lb.get_instances(st, false, false).into_iter().filter(|i| i.endpoint != target_url && !i.degraded).collect();
        others.sort_by(|a, b| {
            crate::lb::registry::compute_score(b).partial_cmp(&crate::lb::registry::compute_score(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        urls.extend(others.into_iter().map(|i| i.endpoint));
    }
    if !cfg.is_production && idempotent {
        if let Some(f) = fallback_url.filter(|f| !f.is_empty()) {
            if !urls.iter().any(|u| u == f) {
                urls.push(f.to_string());
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    urls.retain(|u| seen.insert(u.clone()));

    let client_ip = req.client_ip();
    let ua = req.header("user-agent").map(|s| s.chars().take(512).collect::<String>());
    let origin = req.header("origin").map(|s| s.chars().take(256).collect::<String>());
    let auth = req.authorization().map(str::to_string);

    let mut last_error: Option<String> = None;
    for base_url in urls {
        let url = format!("{base_url}{service_path}");
        let mut rb = app
            .http
            .request(req.method.clone(), &url)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(15));
        if let Some(a) = &auth {
            rb = rb.header("authorization", a);
        }
        if let Some(u) = &user_id {
            rb = rb.header("X-User-Id", u);
        }
        for (k, v) in client_ip_headers(&client_ip) {
            rb = rb.header(k, v);
        }
        if let Some(ua) = &ua {
            rb = rb.header("user-agent", ua);
        }
        if let Some(o) = &origin {
            rb = rb.header("x-client-origin", o);
        }
        if !is_read(&req.method) {
            if let Some(b) = &body_to_send {
                rb = rb.body(crate::json::stringify(b));
            }
        }
        let response = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[Proxy] Erreur réseau {base_url}: {e}, essai suivant…");
                last_error = Some(e.to_string());
                continue;
            }
        };
        let status = response.status();
        if status.as_u16() >= 500 {
            // 5XX → marquer dégradé si l'instance est dans le registre, essayer la suivante.
            let inst = app.lb.get_all().into_iter().find(|i| i.endpoint == base_url);
            match (inst, service_type) {
                (Some(inst), Some(_)) => {
                    app.lb.mark_degraded(&inst.id, &format!("HTTP {} sur proxyRequest", status.as_u16()));
                    warn!("[Proxy] Instance {} dégradée ({}), bascule vers suivant…", inst.id, status.as_u16());
                }
                _ => warn!("[Proxy] {base_url} → {}, essai suivant…", status.as_u16()),
            }
            last_error = Some(status.as_u16().to_string());
            continue;
        }

        let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!("[Proxy] Erreur réseau {base_url}: {e}, essai suivant…");
                last_error = Some(e.to_string());
                continue;
            }
        };
        let code = status.as_u16();
        if content_type.as_deref().map(|c| c.contains("application/json")).unwrap_or(false) {
            return json(code, &safe_json(&bytes).unwrap_or_else(|| json!({ "error": "Réponse vide" })));
        }
        if bytes.is_empty() {
            return json(code, &json!({ "success": status.is_success() }));
        }
        error!("Service {target_url} retourne du non-JSON: {}", String::from_utf8_lossy(&bytes).chars().take(300).collect::<String>());
        return json(code, &json!({ "error": "Service non disponible" }));
    }

    error!("[Proxy] Tous les endpoints épuisés : {}", last_error.unwrap_or_default());
    err_json(502, "Service indisponible")
}

/// Proxy vers un server-node auto-hébergé (JSON, avec passage binaire des médias).
pub async fn proxy_to_node(req: Req, node_endpoint: &str, node_path: &str, server_id: &str) -> Resp {
    let app = req.app.clone();
    let url = format!("{node_endpoint}{node_path}");
    let user_id = req.user_id();
    let mut body_to_send: Option<Value> = if req.body.is_null() { None } else { Some(req.body.clone()) };
    if let (Some(u), false) = (&user_id, is_read(&req.method)) {
        let mut m = req.body.as_object().cloned().unwrap_or_default();
        m.insert("userId".into(), json!(u));
        body_to_send = Some(Value::Object(m));
    }

    // Le node vérifie son propre secret local : le gateway prouve l'identité via un secret DÉRIVÉ pour ce serveur
    // précis. Le secret maître ne quitte jamais le gateway.
    let mut rb = app
        .http
        .request(req.method.clone(), &url)
        .header("Content-Type", "application/json")
        .header("x-internal-secret", derive_node_secret(server_id))
        .timeout(NODE_TIMEOUT);
    if let Some(u) = &user_id {
        rb = rb.header("X-User-Id", u);
    }
    if !is_read(&req.method) {
        if let Some(b) = &body_to_send {
            rb = rb.body(crate::json::stringify(b));
        }
    }
    let response = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Erreur proxy node: {e}");
            return err_json(502, "Server node indisponible");
        }
    };
    let code = response.status().as_u16();
    let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
    let cache_control = response.headers().get("cache-control").and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Erreur proxy node: {e}");
            return err_json(502, "Server node indisponible");
        }
    };
    match content_type.as_deref() {
        Some(ct) if ct.contains("application/json") => match serde_json::from_slice::<Value>(&bytes) {
            Ok(data) => json(code, &data),
            Err(e) => {
                error!("Erreur proxy node: {e}");
                err_json(502, "Server node indisponible")
            }
        },
        Some(ct)
            if ct.starts_with("image/")
                || ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct.starts_with("application/octet-stream")
                || ct.starts_with("application/pdf") =>
        {
            // Contenu fourni par un node tiers : jamais rendu tel quel (SVG, etc.).
            let mut r = send(code, ct, bytes.to_vec());
            set_safe_file_headers(r.headers_mut(), Some(ct));
            if let Some(cc) = cache_control {
                set_header(&mut r, "cache-control", &cc);
            }
            set_header(&mut r, "access-control-allow-origin", &first_origin());
            set_header(&mut r, "cross-origin-resource-policy", "cross-origin");
            r
        }
        _ => json(code, &json!({ "error": "Node non disponible" })),
    }
}

/// Proxy multipart/form-data vers un server-node (envoi de fichiers).
pub async fn proxy_to_node_multipart(mut req: Req, node_endpoint: &str, node_path: &str, server_id: &str) -> Resp {
    let app = req.app.clone();
    let url = format!("{node_endpoint}{node_path}");
    let user_id = req.user_id();
    let sep = if url.contains('?') { '&' } else { '?' };
    // `senderId` en query est ignoré par le node (il lit req.user) mais conservé pour les nodes non mis à jour.
    let final_url = match &user_id {
        Some(u) => format!("{url}{sep}senderId={}", encode_uri_component(u)),
        None => url,
    };
    let body = match req.read_raw(MAX_RAW_BODY).await {
        Ok(b) => b,
        Err(e) => return body_error(e, "Erreur lecture upload node multipart"),
    };
    let mut rb = app
        .http
        .request(req.method.clone(), &final_url)
        .header("x-internal-secret", derive_node_secret(server_id))
        .body(body)
        .timeout(UPLOAD_TIMEOUT);
    if let Some(ct) = req.header("content-type") {
        rb = rb.header("content-type", ct);
    }
    if let Some(u) = &user_id {
        rb = rb.header("x-user-id", u);
    }
    let response = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Erreur proxy node multipart: {e}");
            return err_json(502, "Server node indisponible");
        }
    };
    let code = response.status().as_u16();
    let ct = response.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Erreur proxy node multipart: {e}");
            return err_json(502, "Server node indisponible");
        }
    };
    if ct.as_deref().map(|c| c.contains("application/json")).unwrap_or(false) {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(d) => json(code, &d),
            Err(e) => {
                error!("Erreur proxy node multipart: {e}");
                err_json(502, "Server node indisponible")
            }
        }
    } else {
        send(code, "text/html; charset=utf-8", bytes.to_vec())
    }
}

/// Proxy multipart brut vers un microservice (envoi sans node).
pub async fn proxy_multipart_to_service(mut req: Req, target_url: &str, target_path: &str) -> Resp {
    let app = req.app.clone();
    let user_id = req.user_id();
    let sep = if target_path.contains('?') { '&' } else { '?' };
    let final_url = match &user_id {
        Some(u) => format!("{target_url}{target_path}{sep}senderId={}", encode_uri_component(u)),
        None => format!("{target_url}{target_path}"),
    };
    let body = match req.read_raw(MAX_RAW_BODY).await {
        Ok(b) => b,
        Err(e) => return body_error(e, "Erreur lecture upload service multipart"),
    };
    let mut rb = app.http.post(&final_url).body(body).timeout(UPLOAD_TIMEOUT);
    if let Some(ct) = req.header("content-type") {
        rb = rb.header("content-type", ct);
    }
    if let Some(a) = req.authorization() {
        rb = rb.header("authorization", a);
    }
    match rb.send().await {
        Ok(r) => {
            let code = r.status().as_u16();
            let ok = r.status().is_success();
            let bytes = r.bytes().await.unwrap_or_default();
            json(code, &safe_json(&bytes).unwrap_or_else(|| json!({ "success": ok })))
        }
        Err(e) => {
            error!("Erreur proxy multipart service: {e}");
            err_json(502, "Service indisponible")
        }
    }
}

/// Proxy brut vers le service média ; les médias sont relayés en flux, jamais chargés en mémoire.
pub async fn proxy_to_media(mut req: Req, target_endpoint: &str, media_path: &str) -> Resp {
    let app = req.app.clone();
    let url = format!("{target_endpoint}{media_path}");
    let is_write = !is_read(&req.method);

    let body = if is_write {
        match req.read_raw(MAX_RAW_BODY).await {
            Ok(b) => Some(b),
            Err(e) => return body_error(e, "Erreur lecture upload média"),
        }
    } else {
        None
    };

    let mut rb = app.http.request(req.method.clone(), &url).timeout(if is_write { UPLOAD_TIMEOUT } else { NODE_TIMEOUT });
    if let Some(ct) = req.header("content-type") {
        rb = rb.header("content-type", ct);
    }
    if let Some(a) = req.authorization() {
        rb = rb.header("authorization", a);
    }
    if let Some(b) = body {
        rb = rb.body(b);
    }
    let response = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Erreur proxy média: {e}");
            return err_json(502, "Service média indisponible");
        }
    };
    let code = response.status().as_u16();
    let ct = response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let cache_control = response.headers().get("cache-control").and_then(|v| v.to_str().ok()).map(str::to_string);
    let length = response.headers().get("content-length").and_then(|v| v.to_str().ok()).map(str::to_string);
    let ok = response.status().is_success();

    if ct.contains("application/json") {
        let bytes = response.bytes().await.unwrap_or_default();
        return json(code, &safe_json(&bytes).unwrap_or_else(|| json!({ "success": ok })));
    }
    if is_media_type(&ct) {
        let mut r = axum::response::Response::new(Body::from_stream(response.bytes_stream()));
        *r.status_mut() = axum::http::StatusCode::from_u16(code).unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        set_safe_file_headers(r.headers_mut(), Some(&ct));
        set_header(&mut r, "access-control-allow-origin", &first_origin());
        set_header(&mut r, "cross-origin-resource-policy", "cross-origin");
        if let Some(cc) = cache_control {
            set_header(&mut r, "cache-control", &cc);
        }
        if let Some(l) = length {
            set_header(&mut r, "content-length", &l);
        }
        return r;
    }
    // Tout autre type (text/html, image/svg+xml…) est servi en pièce jointe.
    let bytes = response.bytes().await.unwrap_or_default();
    let mut r = send(code, "application/octet-stream", bytes.to_vec());
    set_safe_file_headers(r.headers_mut(), Some(&ct));
    r
}

/// En-têtes de signature relayés tels quels (Stripe, Tebex, PayPal).
const WEBHOOK_HEADERS: [&str; 9] = [
    "content-type",
    "stripe-signature",
    "x-signature",
    "paypal-transmission-id",
    "paypal-transmission-time",
    "paypal-transmission-sig",
    "paypal-cert-url",
    "paypal-auth-algo",
    "user-agent",
];

/// Relaie un webhook de paiement SANS toucher au corps : les prestataires signent les octets exacts.
pub async fn proxy_raw_webhook(mut req: Req, target_url: &str) -> Resp {
    let app = req.app.clone();
    let body = match req.read_raw(2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return body_error(e, "Erreur lecture webhook"),
    };
    let path = api_path(&req.original_url);
    let path = path.strip_prefix("/api").map(str::to_string).unwrap_or(path);
    let mut rb = app.http.request(req.method.clone(), format!("{target_url}{path}")).timeout(NODE_TIMEOUT);
    for h in WEBHOOK_HEADERS {
        if let Some(v) = req.header(h) {
            rb = rb.header(h, v);
        }
    }
    if !is_read(&req.method) {
        rb = rb.body(body);
    }
    match rb.send().await {
        Ok(r) => {
            let code = r.status().as_u16();
            let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
            let text = r.text().await.unwrap_or_default();
            send(code, &with_charset(ct.as_deref().unwrap_or("text/html")), text.into_bytes())
        }
        Err(e) => {
            error!("Erreur proxy webhook: {e}");
            err_json(502, "Service indisponible")
        }
    }
}
