//! Couche HTTP qui reproduit la sémantique d'Express : routes évaluées dans l'ordre d'enregistrement,
//! chemins insensibles à la casse, paramètres décodés, `*` joker, chaîne de middlewares identique
//! (CORS → helmet → chemin → version d'API → IP bannies → limites → JSON → anomalies → brute-force).

pub mod middleware;
pub mod proxy;
pub mod routes;
pub mod routes_admin;
pub mod routes_misc;

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use sha1::{Digest, Sha1};

use crate::state::AppState;

pub type Resp = axum::response::Response;
pub type Handler = Arc<dyn Fn(Req) -> Pin<Box<dyn Future<Output = Resp> + Send>> + Send + Sync>;

/// Enveloppe une fonction asynchrone en `Handler`.
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    Arc::new(move |r| Box::pin(f(r)))
}

// ── Requête ─────────────────────────────────────────────────────────────────

pub struct Req {
    pub app: Arc<AppState>,
    pub method: Method,
    /// `req.originalUrl` : jamais réécrit (le préfixe de version y reste).
    pub original_url: String,
    /// `req.url` : après retrait du préfixe `/api/vN`.
    pub url: String,
    pub headers: HeaderMap,
    pub remote: Option<IpAddr>,
    pub params: Vec<(String, String)>,
    /// `req.body` : `{}` si non JSON, `Null` quand le parseur est contourné.
    pub body: Value,
    pub body_stream: parking_lot::Mutex<Option<Body>>,
    pub api_version: u32,
}

impl Req {
    /// `req.path` : le chemin de `req.url`, sans query.
    pub fn path(&self) -> &str {
        self.url.split('?').next().unwrap_or("")
    }

    pub fn query_string(&self) -> Option<&str> {
        self.url.split_once('?').map(|(_, q)| q)
    }

    /// Première valeur de `req.query[name]`.
    pub fn query(&self, name: &str) -> Option<String> {
        let q = self.query_string()?;
        url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn param(&self, name: &str) -> &str {
        self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("")
    }

    /// `extractUserIdFromJWT(req.headers.authorization)`.
    pub fn user_id(&self) -> Option<String> {
        crate::security::extract_user_id_from_jwt(self.header("authorization"))
    }

    pub fn authorization(&self) -> Option<&str> {
        self.header("authorization").filter(|s| !s.is_empty())
    }

    pub fn client_ip(&self) -> String {
        crate::security::get_client_ip(self.remote, &self.headers)
    }

    pub fn body_str(&self, key: &str) -> Option<&str> {
        self.body.get(key).and_then(|v| v.as_str())
    }

    /// Lecture du corps brut avec un plafond (413 au-delà).
    pub async fn read_raw(&mut self, limit: usize) -> Result<Bytes, BodyError> {
        let declared = self.header("content-length").and_then(|v| v.parse::<f64>().ok());
        if declared.map(|d| d.is_finite() && d > limit as f64).unwrap_or(false) {
            return Err(BodyError::TooLarge);
        }
        let Some(body) = self.body_stream.get_mut().take() else { return Ok(Bytes::new()) };
        match axum::body::to_bytes(body, limit).await {
            Ok(b) => Ok(b),
            Err(e) => {
                if format!("{e:?}").to_lowercase().contains("length limit") {
                    Err(BodyError::TooLarge)
                } else {
                    Err(BodyError::Aborted)
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum BodyError {
    TooLarge,
    Aborted,
}

// ── Réponses ────────────────────────────────────────────────────────────────

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// ETag faible d'Express (`W/"<len hex>-<sha1 base64 tronqué à 27>"`).
pub fn etag(body: &[u8]) -> String {
    let h = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(body));
    format!("W/\"{:x}-{}\"", body.len(), &h[..27])
}

/// `res.status(code).send(body)` : pose Content-Type, Content-Length et ETag.
pub fn send(code: u16, content_type: &str, body: Vec<u8>) -> Resp {
    // 204 et 304 n'ont jamais de corps : Express retire Content-Type et Content-Length.
    let no_body = code == 204 || code == 304;
    let mut r = axum::response::Response::new(if no_body { Body::empty() } else { Body::from(body.clone()) });
    *r.status_mut() = status(code);
    let h = r.headers_mut();
    if no_body {
        if let Ok(v) = HeaderValue::from_str(&etag(&body)) {
            h.insert(header::ETAG, v);
        }
        return r;
    }
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&etag(&body)) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    r
}

/// `res.status(code).json(value)`.
pub fn json(code: u16, v: &Value) -> Resp {
    send(code, "application/json; charset=utf-8", crate::json::stringify(v).into_bytes())
}

pub fn json_str(code: u16, body: String) -> Resp {
    send(code, "application/json; charset=utf-8", body.into_bytes())
}

/// `res.status(code).end()` sans corps.
pub fn empty(code: u16) -> Resp {
    let mut r = axum::response::Response::new(Body::empty());
    *r.status_mut() = status(code);
    r
}

pub fn set_header(resp: &mut Resp, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
        resp.headers_mut().insert(n, v);
    }
}

pub fn with_header(mut resp: Resp, name: &str, value: &str) -> Resp {
    set_header(&mut resp, name, value);
    resp
}

/// `{ "error": msg }`.
pub fn err_json(code: u16, msg: &str) -> Resp {
    json(code, &serde_json::json!({ "error": msg }))
}

// ── Négociation de contenu (`req.accepts(['html', 'json'])`) ────────────────

/// Retourne `true` si `html` est préféré à `json` (premier type en cas d'égalité ou d'en-tête absent).
pub fn accepts_html(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).filter(|s| !s.trim().is_empty()) else {
        return true;
    };
    struct Spec {
        ty: String,
        sub: String,
        q: f64,
    }
    let specs: Vec<Spec> = raw
        .split(',')
        .filter_map(|part| {
            let mut it = part.split(';');
            let mime = it.next()?.trim().to_lowercase();
            let (ty, sub) = mime.split_once('/')?;
            let mut q = 1.0;
            for p in it {
                if let Some((k, v)) = p.split_once('=') {
                    if k.trim() == "q" {
                        q = v.trim().parse().unwrap_or(1.0);
                    }
                }
            }
            Some(Spec { ty: ty.into(), sub: sub.into(), q })
        })
        .collect();
    // Même ordre de préférence que `negotiator` : q décroissant, spécificité décroissante,
    // position dans l'en-tête croissante, puis ordre des types proposés.
    let best = |ty: &str, sub: &str| -> Option<(f64, i32, i32)> {
        let mut found: Option<(f64, i32, i32)> = None;
        for (o, s) in specs.iter().enumerate() {
            let level = if s.ty == ty && s.sub == sub {
                6
            } else if s.ty == ty && s.sub == "*" {
                4
            } else if s.ty == "*" && s.sub == "*" {
                0
            } else {
                continue;
            };
            let cand = (s.q, level, o as i32);
            let better = match found {
                None => true,
                Some((fq, fl, fo)) => level > fl || (level == fl && (s.q > fq || (s.q == fq && o as i32 > fo))),
            };
            if better {
                found = Some(cand);
            }
        }
        found.filter(|(q, _, _)| *q > 0.0)
    };
    match (best("text", "html"), best("application", "json")) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(h), Some(j)) => {
            // html est proposé en premier : il gagne à égalité complète.
            if h.0 != j.0 {
                h.0 > j.0
            } else if h.1 != j.1 {
                h.1 > j.1
            } else {
                h.2 <= j.2
            }
        }
    }
}

pub const INDEX_HTML: &str = include_str!("../../../public/index.html");
pub const ERROR_404_HTML: &str = include_str!("../../../public/errors/404.html");
pub const ERROR_500_HTML: &str = include_str!("../../../public/errors/500.html");

/// `res.sendFile(...)` d'une page HTML embarquée.
pub fn html_file(code: u16, body: &str) -> Resp {
    let mut r = send(code, "text/html; charset=UTF-8", body.as_bytes().to_vec());
    set_header(&mut r, "cache-control", "public, max-age=0");
    set_header(&mut r, "accept-ranges", "bytes");
    r
}

// ── Routeur ─────────────────────────────────────────────────────────────────

pub struct Route {
    /// `None` = toutes les méthodes (`app.all`).
    pub method: Option<Method>,
    pub pattern: String,
    regex: Regex,
    names: Vec<String>,
    pub handler: Handler,
}

/// Compile un chemin façon path-to-regexp 0.1.x (Express 4) : insensible à la casse, barre finale
/// facultative, `:name` = `([^/]+?)`, `*` = `(.*)` numéroté.
fn compile_pattern(pattern: &str) -> (Regex, Vec<String>) {
    let mut names: Vec<String> = Vec::new();
    let mut star = 0;
    let mut re = String::from("(?is)^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ':' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                names.push(chars[i + 1..j].iter().collect());
                re.push_str("([^/]+?)");
                i = j;
                continue;
            }
            '*' => {
                names.push(star.to_string());
                star += 1;
                re.push_str("(.*)");
            }
            c if "\\.+?()[]{}|^$".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
        i += 1;
    }
    re.push_str(if pattern.ends_with('/') { "?$" } else { "/?$" });
    (Regex::new(&re).expect("motif de route invalide"), names)
}

#[derive(Default)]
pub struct Router {
    pub routes: Vec<Route>,
}

impl Router {
    pub fn add(&mut self, method: Option<Method>, pattern: &str, handler: Handler) {
        let (regex, names) = compile_pattern(pattern);
        self.routes.push(Route { method, pattern: pattern.to_string(), regex, names, handler });
    }
    pub fn get(&mut self, p: &str, h: Handler) {
        self.add(Some(Method::GET), p, h)
    }
    pub fn post(&mut self, p: &str, h: Handler) {
        self.add(Some(Method::POST), p, h)
    }
    pub fn patch(&mut self, p: &str, h: Handler) {
        self.add(Some(Method::PATCH), p, h)
    }
    pub fn put(&mut self, p: &str, h: Handler) {
        self.add(Some(Method::PUT), p, h)
    }
    pub fn delete(&mut self, p: &str, h: Handler) {
        self.add(Some(Method::DELETE), p, h)
    }
    pub fn all(&mut self, p: &str, h: Handler) {
        self.add(None, p, h)
    }

    /// Première route correspondante. HEAD est traité comme GET (comportement d'Express).
    pub fn find(&self, method: &Method, path: &str) -> Option<(&Route, Vec<(String, String)>)> {
        let m = if method == Method::HEAD { &Method::GET } else { method };
        for r in &self.routes {
            if let Some(rm) = &r.method {
                if rm != m && !(method == Method::HEAD && rm == Method::GET) {
                    continue;
                }
            }
            if let Some(c) = r.regex.captures(path) {
                let params = r
                    .names
                    .iter()
                    .enumerate()
                    .map(|(i, n)| (n.clone(), decode(c.get(i + 1).map(|m| m.as_str()).unwrap_or(""))))
                    .collect();
                return Some((r, params));
            }
        }
        None
    }
}

/// `decodeURIComponent` tolérant.
pub fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub static WEBHOOK_PATH: Lazy<Regex> = Lazy::new(|| Regex::new(r"^/api/servers/webhooks/[^/]+/[^/]+/?$").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_semantics() {
        let (re, names) = compile_pattern("/api/servers/:serverId/*");
        assert_eq!(names, vec!["serverId", "0"]);
        assert!(re.is_match("/API/Servers/abc/files"));
        assert!(re.is_match("/api/servers/abc/"));
        assert!(!re.is_match("/api/servers/abc"));
        let (re, _) = compile_pattern("/api/users");
        assert!(re.is_match("/api/users/"));
        assert!(re.is_match("/Api/USERS"));
        assert!(!re.is_match("/api/users/x"));
        let (re, _) = compile_pattern("/api/subscriptions/plans*");
        assert!(re.is_match("/api/subscriptions/plans"));
        assert!(re.is_match("/api/subscriptions/plans/x"));
        assert!(re.is_match("/api/subscriptions/plansxyz"));
    }

    #[test]
    fn find_params_and_order() {
        let mut r = Router::default();
        let h = handler(|_| async { empty(204) });
        r.post("/api/servers/:serverId/claim-admin", h.clone());
        r.all("/api/servers/:serverId/*", h.clone());
        let (route, p) = r.find(&Method::POST, "/api/servers/s%201/claim-admin").unwrap();
        assert_eq!(route.pattern, "/api/servers/:serverId/claim-admin");
        assert_eq!(p[0], ("serverId".to_string(), "s 1".to_string()));
        let (route, p) = r.find(&Method::GET, "/api/servers/s1/claim-admin").unwrap();
        assert_eq!(route.pattern, "/api/servers/:serverId/*");
        assert_eq!(p[1], ("0".to_string(), "claim-admin".to_string()));
        assert!(r.find(&Method::GET, "/api/other").is_none());
    }

    #[test]
    fn accepts() {
        let mut h = HeaderMap::new();
        assert!(accepts_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        assert!(accepts_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!accepts_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        assert!(accepts_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json, text/plain, */*"));
        assert!(!accepts_html(&h));
    }

    #[test]
    fn etag_format() {
        let e = etag(b"{}");
        assert!(e.starts_with("W/\"2-"));
        assert_eq!(e.len(), "W/\"2-\"".len() + 27);
    }
}
