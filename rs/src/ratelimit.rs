//! Limitation de débit : limiteur Redis à fenêtre fixe (équivalent de `rate-limiter-flexible`)
//! et fenêtres glissantes en mémoire (équivalent de `state/rate-limit.ts`).

use std::collections::HashMap;
use std::time::Duration;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use redis::aio::ConnectionManager;

use crate::redis_client::now_ms;

// ── Limiteur Redis (fenêtre fixe) ───────────────────────────────────────────

/// Même principe que `RateLimiterRedis` : clé `<prefix>:<key>`, compteur incrémenté
/// à chaque tentative (même refusée), expiration posée à la première.
const CONSUME_LUA: &str = r#"
local key = KEYS[1]
local pts = tonumber(ARGV[1])
local dur = tonumber(ARGV[2])
redis.call('set', key, 0, 'EX', dur, 'NX')
local consumed = redis.call('incrby', key, pts)
local ttl = redis.call('pttl', key)
if ttl == -1 then
  redis.call('expire', key, dur)
  ttl = dur * 1000
end
return {consumed, ttl}
"#;

static CONSUME_SCRIPT: Lazy<redis::Script> = Lazy::new(|| redis::Script::new(CONSUME_LUA));

#[derive(Clone)]
pub struct RedisLimiter {
    pub prefix: &'static str,
    pub points: i64,
    pub duration: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Consumed {
    pub allowed: bool,
    pub consumed: i64,
    pub remaining: i64,
    pub ms_before_next: i64,
}

impl RedisLimiter {
    pub const fn new(prefix: &'static str, points: i64, duration: i64) -> Self {
        Self { prefix, points, duration }
    }

    /// `Err` = Redis indisponible (l'appelant décide s'il laisse passer).
    pub async fn consume(&self, conn: &ConnectionManager, key: &str) -> redis::RedisResult<Consumed> {
        let mut c = conn.clone();
        let (consumed, ttl): (i64, i64) = CONSUME_SCRIPT
            .key(format!("{}:{}", self.prefix, key))
            .arg(1)
            .arg(self.duration)
            .invoke_async(&mut c)
            .await?;
        Ok(Consumed {
            allowed: consumed <= self.points,
            consumed,
            remaining: (self.points - consumed).max(0),
            ms_before_next: ttl.max(0),
        })
    }
}

// ── Fenêtres glissantes en mémoire ──────────────────────────────────────────

pub struct SlidingWindow {
    window_ms: i64,
    max: usize,
    hits: Mutex<HashMap<String, Vec<i64>>>,
}

impl SlidingWindow {
    pub fn new(window_ms: i64, max: usize) -> Self {
        Self { window_ms, max, hits: Mutex::new(HashMap::new()) }
    }

    pub fn consume(&self, key: &str) -> bool {
        let now = now_ms();
        let mut g = self.hits.lock();
        let entry = g.entry(key.to_string()).or_default();
        entry.retain(|t| now - *t < self.window_ms);
        if entry.len() >= self.max {
            return false;
        }
        entry.push(now);
        true
    }

    /// Sans balayage, chaque utilisateur ayant écrit une fois garderait une entrée à vie.
    pub fn sweep(&self) {
        let now = now_ms();
        self.hits.lock().retain(|_, ts| ts.last().map(|l| now - *l <= self.window_ms).unwrap_or(false));
    }
}

pub const MSG_RATE_WINDOW: i64 = 10;
pub const MSG_RATE_MAX: i64 = 10;
pub const JOIN_RATE_WINDOW: i64 = 60_000;
pub const JOIN_RATE_MAX: usize = 5;
pub const INVITE_VERIFY_WINDOW: i64 = 60_000;
pub const INVITE_VERIFY_MAX: usize = 20;
pub const NODE_REGISTER_WINDOW: i64 = 10 * 60_000;
pub const NODE_REGISTER_MAX: usize = 3;

pub static MSG_LIMITER: RedisLimiter = RedisLimiter::new("rl_ws_msg", MSG_RATE_MAX, MSG_RATE_WINDOW);

pub struct WsLimits {
    msg_fallback: SlidingWindow,
    join: SlidingWindow,
    invite_verify: SlidingWindow,
    node_register: SlidingWindow,
}

impl WsLimits {
    pub fn new() -> Self {
        Self {
            msg_fallback: SlidingWindow::new(MSG_RATE_WINDOW * 1000, MSG_RATE_MAX as usize),
            join: SlidingWindow::new(JOIN_RATE_WINDOW, JOIN_RATE_MAX),
            invite_verify: SlidingWindow::new(INVITE_VERIFY_WINDOW, INVITE_VERIFY_MAX),
            node_register: SlidingWindow::new(NODE_REGISTER_WINDOW, NODE_REGISTER_MAX),
        }
    }

    /// Autorise un envoi/édition de message. Redis si disponible, sinon repli local :
    /// jamais bloquer le chat parce que Redis est momentanément indisponible.
    pub async fn check_message_rate(&self, redis: Option<&ConnectionManager>, user_id: &str) -> bool {
        let Some(conn) = redis else { return self.msg_fallback.consume(user_id) };
        match MSG_LIMITER.consume(conn, user_id).await {
            Ok(r) => r.allowed,
            Err(_) => true,
        }
    }

    pub fn check_server_join_rate(&self, user_id: &str) -> bool {
        self.join.consume(user_id)
    }

    pub fn check_invite_verify_rate(&self, user_id: &str) -> bool {
        self.invite_verify.consume(user_id)
    }

    pub fn check_node_register_rate(&self, user_id: &str) -> bool {
        self.node_register.consume(user_id)
    }

    pub fn spawn_sweeper(self: &std::sync::Arc<Self>) {
        let me = std::sync::Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5 * 60));
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(l) = me.upgrade() else { break };
                l.msg_fallback.sweep();
                l.join.sweep();
                l.invite_verify.sweep();
                l.node_register.sweep();
            }
        });
    }
}

// ── Débit par socket ────────────────────────────────────────────────────────

const SOCKET_WINDOW_MS: i64 = 10_000;
const SOCKET_MAX_EVENTS: u32 = 150;
const SOCKET_MAX_EXPENSIVE: u32 = 20;

/// Événements qui déclenchent des appels HTTP coûteux ou notifient des tiers.
pub const EXPENSIVE_EVENTS: &[&str] = &[
    "CALL_INITIATE", "CALL_INITIATE_GROUP", "CALL_INITIATE_SERVER", "CALL_JOIN", "CALL_ACCEPT",
    "CALL_REJECT", "CALL_END", "CALL_REJOIN",
    "FRIEND_REQUEST", "FRIEND_ACCEPT",
    "GROUP_CREATE", "GROUP_UPDATE", "GROUP_DELETE", "GROUP_LEAVE",
    "INVITE_CREATE", "INVITE_DELETE", "INVITE_LIST",
    "GET_BULK_PRESENCE", "MEMBER_LIST", "ROLE_LIST",
    "e2ee:history-request", "e2ee:history-response",
    "DM_ARCHIVE_REQUEST", "DM_ARCHIVE_PEER_RESPONSE", "DM_ARCHIVE_CONFIRM", "DM_ARCHIVE_STATUS",
    "CHANNEL_CREATE", "CHANNEL_UPDATE", "CHANNEL_DELETE", "CHANNEL_PERMS_SET",
    "ROLE_CREATE", "ROLE_UPDATE", "ROLE_DELETE", "MEMBER_UPDATE", "MEMBER_KICK", "MEMBER_BAN",
    "SERVER_UPDATE_NODE", "PROFILE_UPDATE", "CHANGE_USERNAME", "SFU_CREATE_TRANSPORT",
];

/// Fenêtre fixe par socket, en mémoire : la socket vit sur une seule instance, le compteur aussi.
pub struct SocketLimiter {
    inner: Mutex<(i64, u32, u32)>,
}

impl SocketLimiter {
    pub fn new() -> Self {
        Self { inner: Mutex::new((now_ms(), 0, 0)) }
    }

    /// `false` = événement refusé (équivalent de `next(new Error('RATE_LIMITED'))`).
    pub fn allow(&self, event: &str) -> bool {
        let now = now_ms();
        let mut g = self.inner.lock();
        if now - g.0 > SOCKET_WINDOW_MS {
            *g = (now, 0, 0);
        }
        g.1 += 1;
        if EXPENSIVE_EVENTS.contains(&event) {
            g.2 += 1;
        }
        !(g.1 > SOCKET_MAX_EVENTS || g.2 > SOCKET_MAX_EXPENSIVE)
    }
}
