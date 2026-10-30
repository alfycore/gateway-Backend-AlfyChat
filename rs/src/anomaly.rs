//! Détection d'anomalies (équivalent de `monitoring/anomaly.ts`) : suit par sujet (userId ou IP) sur une
//! fenêtre glissante le débit, la diversité des endpoints et la part d'erreurs 4xx. Au-delà du seuil,
//! une entrée `SECURITY_ANOMALY` est journalisée (ni ban ni kick : observer d'abord).

use std::sync::Arc;

use axum::http::HeaderMap;
use base64::Engine;
use tracing::warn;

use crate::state::AppState;

const WINDOW_SECS: i64 = 60;
const REQ_THRESHOLD: i64 = 150;
const ENDPOINT_THRESHOLD: i64 = 25;
const ERR4XX_THRESHOLD: f64 = 0.50;
const ERR4XX_MIN_REQS: i64 = 20;
const SCORE_ALERT: f64 = 2.0;
const COOLDOWN_SECS: u64 = 300;

/// Événements WS d'infrastructure : jamais comptés.
const WS_IGNORED_EVENTS: [&str; 9] = ["ping", "pong", "heartbeat", "connect", "disconnect", "error", "presence:update", "typing:start", "typing:stop"];

pub fn ws_event_ignored(event: &str) -> bool {
    WS_IGNORED_EVENTS.contains(&event)
}

pub async fn record_and_score(app: &Arc<AppState>, subject: &str, endpoint: &str, is_error: bool) {
    let r = &app.redis;
    let inner = async {
        let req_count = r.anomaly_incr_req(&format!("anm:req:{subject}"), WINDOW_SECS).await?;
        let ep_count = r.anomaly_add_endpoint(&format!("anm:ep:{subject}"), endpoint, WINDOW_SECS).await?;
        let err_count = if is_error { r.anomaly_incr_req(&format!("anm:err:{subject}"), WINDOW_SECS).await? } else { 0 };

        let mut score = 0.0;
        if req_count > REQ_THRESHOLD {
            score += req_count as f64 / REQ_THRESHOLD as f64;
        }
        if ep_count > ENDPOINT_THRESHOLD {
            score += ep_count as f64 / ENDPOINT_THRESHOLD as f64;
        }
        if req_count >= ERR4XX_MIN_REQS {
            let err_rate = err_count as f64 / req_count as f64;
            if err_rate > ERR4XX_THRESHOLD {
                score += err_rate / ERR4XX_THRESHOLD;
            }
        }
        if score >= SCORE_ALERT {
            let key = format!("anm:alt:{subject}");
            if r.get(&key).await?.is_none() {
                r.set(&key, "1", Some(COOLDOWN_SECS)).await?;
                warn!(
                    SECURITY_ANOMALY = true,
                    subject = subject,
                    score = format!("{score:.2}"),
                    req_count = req_count,
                    ep_count = ep_count,
                    err_count = err_count,
                    window_secs = WINDOW_SECS,
                    "SECURITY_ANOMALY: comportement suspect détecté ({subject}, score={score:.2})"
                );
            }
        }
        Ok::<(), redis::RedisError>(())
    };
    // Le suivi ne doit jamais perturber le chemin de la requête.
    let _ = inner.await;
}

/// Décodage rapide du payload JWT (sans vérifier la signature : déjà fait en amont).
pub fn jwt_subject(auth: Option<&str>) -> Option<String> {
    let token = auth?.strip_prefix("Bearer ")?;
    let part = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part.trim_end_matches('=')).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    for k in ["userId", "id"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

pub fn ip_subject(headers: &HeaderMap, remote: Option<std::net::IpAddr>) -> String {
    let raw = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    raw.or_else(|| remote.map(|a| a.to_string())).unwrap_or_else(|| "unknown".into())
}
