//! Constantes d'environnement centralisées (équivalent de `config/env.ts`).
//!
//! Fail-closed : `JWT_SECRET` et `INTERNAL_SECRET` sont obligatoires, `FRONTEND_URL` aussi en production.

use std::collections::HashSet;
use std::sync::OnceLock;

use once_cell::sync::Lazy;
use regex::Regex;

pub struct Config {
    pub jwt_secret: String,
    pub internal_secret: String,
    pub is_production: bool,
    pub is_dev: bool,
    pub port: u16,

    pub users_url: String,
    pub messages_url: String,
    pub friends_url: String,
    pub calls_url: String,
    pub servers_url: String,
    pub bots_url: String,
    pub media_url: String,
    pub serverhosting_url: String,
    pub subscriptions_url: String,

    pub rate_limit_anon: i64,
    pub rate_limit_user: i64,
    pub rate_limit_admin: i64,
    pub rate_limit_window: i64,
    pub rate_limit_auth_points: i64,
    pub rate_limit_auth_window: i64,

    pub trusted_proxies: HashSet<String>,
    pub allowed_origins: Vec<String>,
    pub admin_alert_emails: Vec<String>,
}

/// Chemins comparés en MINUSCULES (Express route sans tenir compte de la casse).
pub const AUTH_BRUTEFORCE_PATHS: [&str; 10] = [
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/2fa/login",
    "/api/auth/verify-2fa",
    "/api/auth/forgot-password",
    "/api/auth/reset-password",
    "/api/auth/resend-verification-email",
    "/api/auth/remote/init",
    "/api/helpdesk/public/tickets",
    "/api/archive/external-db",
];

pub static AUTH_BRUTEFORCE_REGEX: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"^/api/servers/[^/]+/claim-admin$",
        r"^/api/users/[^/]+/change-password$",
        r"^/api/users/[^/]+/change-username$",
        r"^/api/auth/2fa/(enable|disable)$",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

pub static IP_ENDPOINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^https?://(\d{1,3}\.){3}\d{1,3}").unwrap());

static CONFIG: OnceLock<Config> = OnceLock::new();

/// Équivalent de `parseInt(process.env.X || 'def')`.
fn parse_int(name: &str, default: i64) -> i64 {
    let raw = env_str(name).filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string());
    let t = raw.trim_start();
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    match digits.parse::<i64>() {
        Ok(n) => {
            if neg {
                -n
            } else {
                n
            }
        }
        Err(_) => default,
    }
}

fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// `process.env.X || fallback` (une chaîne vide retombe sur le défaut).
fn env_or(name: &str, fallback: &str) -> String {
    env_str(name).filter(|s| !s.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn csv(raw: &str) -> Vec<String> {
    raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

pub fn init() -> Result<&'static Config, String> {
    let _ = dotenvy::dotenv();

    let jwt_secret = env_str("JWT_SECRET").filter(|s| !s.is_empty()).ok_or(
        "JWT_SECRET manquant — définissez-le dans .env (openssl rand -hex 64). Refus de démarrer avec un secret par défaut.",
    )?;
    let internal_secret = env_str("INTERNAL_SECRET").filter(|s| !s.is_empty()).ok_or(
        "INTERNAL_SECRET manquant — définissez-le dans .env (openssl rand -hex 64). Refus de démarrer avec un secret par défaut.",
    )?;

    let node_env = env_str("NODE_ENV").unwrap_or_default();
    let is_production = node_env == "production";
    let frontend_url = env_str("FRONTEND_URL").filter(|s| !s.is_empty());
    if is_production && frontend_url.is_none() {
        return Err("FRONTEND_URL manquant en production — définissez-le dans .env (liste d'origines séparées par des virgules).".into());
    }

    let cfg = Config {
        jwt_secret,
        internal_secret,
        is_production,
        is_dev: node_env == "development",
        port: env_or("PORT", "3000").parse().unwrap_or(3000),

        users_url: env_or("USERS_SERVICE_URL", "https://users.alfychat.eu"),
        messages_url: env_or("MESSAGES_SERVICE_URL", "https://messages.alfychat.eu"),
        friends_url: env_or("FRIENDS_SERVICE_URL", "https://friends.s.backend.alfychat.app"),
        calls_url: env_or("CALLS_SERVICE_URL", "https://calls.s.backend.alfychat.app"),
        servers_url: env_or("SERVERS_SERVICE_URL", "https://servers.s.backend.alfychat.app"),
        bots_url: env_or("BOTS_SERVICE_URL", "https://bots.s.backend.alfychat.app"),
        media_url: env_or("MEDIA_SERVICE_URL", "https://media.s.backend.alfychat.app"),
        serverhosting_url: env_or("SERVERHOSTING_SERVICE_URL", "http://localhost:3008"),
        subscriptions_url: env_or("SUBSCRIPTIONS_SERVICE_URL", "http://localhost:3009"),

        rate_limit_anon: parse_int("RATE_LIMIT_ANON", 20),
        rate_limit_user: parse_int("RATE_LIMIT_USER", 150),
        rate_limit_admin: parse_int("RATE_LIMIT_ADMIN", 500),
        rate_limit_window: 1,
        rate_limit_auth_points: parse_int("RATE_LIMIT_AUTH_POINTS", 30),
        rate_limit_auth_window: parse_int("RATE_LIMIT_AUTH_WINDOW", 300),

        trusted_proxies: csv(&env_or("TRUSTED_PROXIES", "127.0.0.1,::1")).into_iter().collect(),
        allowed_origins: csv(&frontend_url.unwrap_or_else(|| "http://localhost:4000".into())),
        admin_alert_emails: csv(&env_or("ADMIN_ALERT_EMAILS", "")),
    };
    Ok(CONFIG.get_or_init(|| cfg))
}

pub fn get() -> &'static Config {
    CONFIG.get().expect("config::init() n'a pas été appelé")
}
