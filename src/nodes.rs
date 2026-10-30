//! Dialogue avec les server-nodes connectés (équivalent de `services/forward.ts`) et cache de blocage MP.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::redis_client::now_ms;
use crate::state::{AppState, BlockEntry};

/// Envoie un événement à un server-node et attend son accusé de réception.
/// Erreurs : `NO_NODE` (pas de node connecté), `NODE_TIMEOUT`, ou le texte `error` renvoyé par le node.
pub async fn forward_to_node(app: &Arc<AppState>, server_id: &str, event: &str, data: &Value, timeout_ms: u64) -> Result<Value, String> {
    let node = app.node(server_id).ok_or_else(|| "NO_NODE".to_string())?;
    let stream = node
        .socket
        .timeout(Duration::from_millis(timeout_ms))
        .emit_with_ack::<_, Value>(event, data)
        .map_err(|_| "NO_NODE".to_string())?;
    match stream.await {
        Ok(resp) => match resp.get("error") {
            Some(e) if !matches!(e, Value::Null | Value::Bool(false)) && e != &Value::from("") => {
                Err(e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string()))
            }
            _ => Ok(resp),
        },
        Err(_) => Err("NODE_TIMEOUT".to_string()),
    }
}

pub const NODE_DEFAULT_TIMEOUT_MS: u64 = 15_000;

// ── Cache de blocage MP (60 s) ──────────────────────────────────────────────

const BLOCK_CACHE_TTL_MS: i64 = 60_000;

fn block_key(u1: &str, u2: &str) -> (String, bool) {
    let swapped = u1 > u2;
    (if swapped { format!("{u2}:{u1}") } else { format!("{u1}:{u2}") }, swapped)
}

/// Un MP est-il bloqué entre ces deux utilisateurs ? (en cache 60 s ; `false` si le service ne répond pas)
pub async fn is_dm_blocked(app: &Arc<AppState>, sender_id: &str, recipient_id: &str) -> bool {
    let (key, swapped) = block_key(sender_id, recipient_id);
    let now = now_ms();
    if let Some(c) = app.block_cache.lock().get(&key) {
        if c.expires_at > now {
            return c.a_blocked_b || c.b_blocked_a;
        }
    }
    let base = app.service_url("friends", &app.cfg.friends_url);
    let res = app.http.get(format!("{base}/friends/{sender_id}/block-status/{recipient_id}")).send().await;
    let Ok(res) = res else { return false };
    if !res.status().is_success() {
        return false;
    }
    let Ok(data) = res.json::<Value>().await else { return false };
    let truthy = |k: &str| data.get(k).map(|v| !matches!(v, Value::Null | Value::Bool(false)) && v != &Value::from(0) && v != &Value::from("")).unwrap_or(false);
    let (i_blocked_them, they_blocked_me) = (truthy("iBlockedThem"), truthy("theyBlockedMe"));
    let a_blocked_b = if swapped { they_blocked_me } else { i_blocked_them };
    let b_blocked_a = if swapped { i_blocked_them } else { they_blocked_me };
    app.block_cache.lock().insert(key, BlockEntry { a_blocked_b, b_blocked_a, expires_at: now + BLOCK_CACHE_TTL_MS });
    a_blocked_b || b_blocked_a
}

/// Invalide le cache quand un blocage / déblocage survient.
pub fn invalidate_block_cache(app: &Arc<AppState>, u1: &str, u2: &str) {
    let (key, _) = block_key(u1, u2);
    app.block_cache.lock().remove(&key);
}
