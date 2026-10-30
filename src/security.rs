//! Helpers de sécurité et de chemin partagés : IP client signée, secret de nœud dérivé,
//! validation SSRF des endpoints de server-nodes, JWT, en-têtes de fichiers sûrs.
//! (équivalents de `http/helpers.ts` et `utils/node-endpoint.ts`)

use std::net::{IpAddr, Ipv4Addr};

use axum::http::{header, HeaderMap, HeaderValue};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::Regex;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::config;

type HmacSha256 = Hmac<Sha256>;

fn hmac_hex(key: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepte toute taille de clé");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// IP du client : `X-Forwarded-For` n'est cru que si la connexion vient d'un proxy de confiance.
pub fn get_client_ip(remote: Option<IpAddr>, headers: &HeaderMap) -> String {
    let remote_addr = remote.map(|a| a.to_string()).unwrap_or_else(|| "0.0.0.0".into());
    if config::get().trusted_proxies.contains(&remote_addr) {
        if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            return fwd.split(',').next().unwrap_or("").trim().to_string();
        }
    }
    remote_addr
}

/// En-têtes transmis aux microservices : IP réelle du client, signée (un appel direct ne peut pas la forger).
pub fn client_ip_headers(ip: &str) -> [(&'static str, String); 2] {
    [
        ("x-client-ip", ip.to_string()),
        ("x-client-ip-sig", hmac_hex(&config::get().internal_secret, &format!("client-ip:{ip}"))),
    ]
}

/// Secret propre à un serveur, dérivé de `INTERNAL_SECRET` (le secret maître ne quitte jamais le gateway).
pub fn derive_node_secret(server_id: &str) -> String {
    hmac_hex(&config::get().internal_secret, &format!("node:{server_id}"))
}

/// Comparaison en temps constant ; faux si l'un des deux est absent ou vide.
pub fn safe_secret_equal(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => {
            a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
        }
        _ => false,
    }
}

/// Décode le userId d'un en-tête `Authorization: Bearer …` (jamais d'erreur).
pub fn extract_user_id_from_jwt(auth_header: Option<&str>) -> Option<String> {
    let token = auth_header?.strip_prefix("Bearer ")?;
    let claims = verify_jwt(token).ok()?;
    if let Some(t) = claims.get("type") {
        let truthy = !matches!(t, serde_json::Value::Null | serde_json::Value::Bool(false))
            && t.as_str().map(|s| !s.is_empty()).unwrap_or(true);
        if truthy && t.as_str() != Some("access") {
            return None;
        }
    }
    for k in ["userId", "id"] {
        if let Some(s) = claims.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Vérification HS256 alignée sur `jsonwebtoken` (JS) : `exp`/`nbf` contrôlés s'ils existent, sans marge ni claim obligatoire.
pub fn verify_jwt(token: &str) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {
    let mut v = Validation::new(Algorithm::HS256);
    v.required_spec_claims.clear();
    v.validate_exp = true;
    v.validate_nbf = true;
    v.leeway = 0;
    jsonwebtoken::decode::<serde_json::Value>(token, &DecodingKey::from_secret(config::get().jwt_secret.as_bytes()), &v)
        .map(|d| d.claims)
}

// ── Chemins ────────────────────────────────────────────────────────────────

/// Chemin de la requête SANS préfixe de version (`/api/v1/x` → `/api/x`), query conservée.
pub fn api_path(original_url: &str) -> String {
    let b = original_url.as_bytes();
    if b.len() >= 6 && original_url[..5].eq_ignore_ascii_case("/api/") && (b[5] == b'v' || b[5] == b'V') {
        let mut i = 6;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i > 6 && (i == b.len() || b[i] == b'/' || b[i] == b'?') {
            return format!("/api{}", &original_url[i..]);
        }
    }
    original_url.to_string()
}

/// `encodeURIComponent` : tout est encodé sauf `A-Z a-z 0-9 - _ . ! ~ * ' ( )`.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn encode_uri_component(s: &str) -> String {
    utf8_percent_encode(s, URI_COMPONENT).to_string()
}

static NODE_MSG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^/channels/([^/]+)/messages$").unwrap());

/// Réécriture pour un server-node : `/api/servers/:id/X` → `/X` (et `/channels/:c/messages` → `/messages?channelId=:c`).
pub fn rewrite_node_path(original_url: &str, server_id: &str) -> String {
    let original = api_path(original_url);
    let full_path = original.split('?').next().unwrap_or("");
    // Comme l'original : seule la partie entre le 1er et le 2e « ? » est conservée.
    let query = if original.contains('?') {
        format!("?{}", original.split('?').nth(1).unwrap_or(""))
    } else {
        String::new()
    };
    let prefix = format!("/api/servers/{server_id}");
    let sub_path = full_path.strip_prefix(prefix.as_str()).unwrap_or(full_path);

    if let Some(c) = NODE_MSG_RE.captures(sub_path) {
        let sep = if query.is_empty() { "?".to_string() } else { format!("{query}&") };
        return format!("/messages{sep}channelId={}", encode_uri_component(&c[1]));
    }

    let sub = if sub_path.is_empty() { "/" } else { sub_path };
    format!("{sub}{query}")
}

// ── Fichiers fournis par les utilisateurs ──────────────────────────────────

static INLINE_SAFE_TYPES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(image/(png|jpe?g|gif|webp|avif)|video/(mp4|webm|ogg)|audio/(mpeg|ogg|webm|wav|mp4|x-wav)|application/pdf)(;|$)")
        .unwrap()
});

/// En-têtes de téléchargement sûrs : seuls les types inertes sont affichés en ligne.
pub fn set_safe_file_headers(headers: &mut HeaderMap, content_type: Option<&str>) {
    let ct = content_type.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("application/octet-stream");
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"),
    );
    if INLINE_SAFE_TYPES.is_match(ct) {
        if let Ok(v) = HeaderValue::from_str(ct) {
            headers.insert(header::CONTENT_TYPE, v);
            return;
        }
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
}

static SAFE_SEGMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$").unwrap());

pub fn is_safe_file_segment(v: &str) -> bool {
    SAFE_SEGMENT.is_match(v) && !v.contains("..")
}

// ── Endpoints de server-nodes (SSRF) ───────────────────────────────────────

/// Adresses que le gateway ne doit jamais joindre pour le compte d'un tiers
/// (loopback, privé, link-local dont les métadonnées cloud, CGNAT, multicast).
fn is_forbidden_address(addr: &str) -> bool {
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        let p = v4.octets();
        return p[0] == 0
            || p[0] == 10
            || p[0] == 127
            || (p[0] == 169 && p[1] == 254)
            || (p[0] == 172 && (16..=31).contains(&p[1]))
            || (p[0] == 192 && p[1] == 168)
            || (p[0] == 100 && (64..=127).contains(&p[1]))
            || p[0] >= 224;
    }
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        let a = addr.to_lowercase();
        if a == "::" || a == "::1" || a.starts_with("fe80") || a.starts_with("fc") || a.starts_with("fd") {
            return true;
        }
        if let Some(rest) = a.strip_prefix("::ffff:") {
            return is_forbidden_address(rest);
        }
        return false;
    }
    // Ni IPv4 ni IPv6 → on ne sait pas, on refuse.
    true
}

/// Valide l'endpoint déclaré par un server-node et retourne son origine normalisée, ou `None`.
///
/// Refuse : schémas hors http(s), HTTP en clair en production, identifiants, chemin/query/fragment,
/// noms internes, et tout nom résolvant vers une adresse privée (DNS rebinding).
pub async fn validate_node_endpoint(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 255 {
        return None;
    }
    let url = url::Url::parse(raw).ok()?;
    let production = config::get().is_production;

    if url.scheme() != "https" && url.scheme() != "http" {
        return None;
    }
    if production && url.scheme() != "https" {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if (!url.path().is_empty() && url.path() != "/") || url.query().is_some() || url.fragment().is_some() {
        return None;
    }

    let host = url.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    if host.is_empty() {
        return None;
    }

    // En développement uniquement, un node tourne légitimement en local.
    if !production && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
        return Some(url.origin().ascii_serialization());
    }

    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return None;
    }

    let addresses: Vec<String> = if host.parse::<IpAddr>().is_ok() {
        vec![host.clone()]
    } else {
        match tokio::net::lookup_host((host.as_str(), 0)).await {
            Ok(it) => it.map(|sa| sa.ip().to_string()).collect(),
            Err(_) => return None,
        }
    };

    if addresses.is_empty() || addresses.iter().any(|a| is_forbidden_address(a)) {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_path_strips_version() {
        assert_eq!(api_path("/api/v1/users?x=1"), "/api/users?x=1");
        assert_eq!(api_path("/API/V12"), "/api");
        assert_eq!(api_path("/api/v1x/users"), "/api/v1x/users");
        assert_eq!(api_path("/api/users"), "/api/users");
    }

    #[test]
    fn rewrite_node_path_cases() {
        assert_eq!(rewrite_node_path("/api/servers/s1/channels", "s1"), "/channels");
        assert_eq!(rewrite_node_path("/api/servers/s1", "s1"), "/");
        assert_eq!(rewrite_node_path("/api/servers/s1/channels/c 1/messages?limit=5", "s1"), "/messages?limit=5&channelId=c%201");
        assert_eq!(rewrite_node_path("/api/servers/s1/channels/c1/messages", "s1"), "/messages?channelId=c1");
        assert_eq!(rewrite_node_path("/api/v1/servers/s1/members?a=1?b=2", "s1"), "/members?a=1");
    }

    #[test]
    fn uri_component() {
        assert_eq!(encode_uri_component("a b/é!'()*~"), "a%20b%2F%C3%A9!'()*~");
    }

    #[test]
    fn safe_segment() {
        assert!(is_safe_file_segment("a.png"));
        assert!(!is_safe_file_segment("../a"));
        assert!(!is_safe_file_segment("a..b"));
        assert!(!is_safe_file_segment(".a"));
    }
}
