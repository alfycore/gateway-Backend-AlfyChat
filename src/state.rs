//! État partagé du gateway (connexions, vocal, caches) — équivalent de `state/*` et de `runtime`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;

use crate::config::Config;
use crate::lb::gateway_registry::GatewayRegistry;
use crate::lb::registry::LbRegistry;
use crate::monitoring_db::MonitoringDb;
use crate::ratelimit::{RedisLimiter, WsLimits};
use crate::redis_client::RedisClient;
use crate::svc::Services;

/// Adaptateur Socket.IO multi-instances (Redis).
pub type A = socketioxide_redis::RedisAdapter<socketioxide::adapter::Emitter>;
pub type Io = socketioxide::SocketIo<A>;
pub type Sock = socketioxide::extract::SocketRef<A>;

#[derive(Clone)]
pub struct ConnectedClient {
    pub socket_id: String,
    pub user_id: String,
    pub session_id: String,
    pub connected_at: DateTime<Utc>,
    /// Profil de l'utilisateur (nom, avatar) — lu pour les listes de participants d'appel.
    pub user: Value,
}

#[derive(Clone)]
pub struct ConnectedNode {
    pub socket: Sock,
    pub socket_id: String,
    pub server_id: String,
    pub endpoint: Option<String>,
    pub connected_at: DateTime<Utc>,
}

/// Participant d'un salon vocal.
#[derive(Clone, Debug)]
pub struct VoiceParticipant {
    pub socket_id: String,
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub muted: bool,
    pub deafened: bool,
    pub server_id: String,
    pub video: bool,
    pub streaming: bool,
    pub server_muted: bool,
    pub server_deafened: bool,
    pub joined_at: Option<i64>,
}

impl VoiceParticipant {
    /// Forme publique (sans socketId).
    pub fn public(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("userId".into(), serde_json::json!(self.user_id));
        m.insert("username".into(), serde_json::json!(self.username));
        m.insert("displayName".into(), serde_json::json!(self.display_name.clone().unwrap_or_else(|| self.username.clone())));
        // `avatarUrl` indéfini est omis du JSON (comme en JavaScript)
        if let Some(a) = &self.avatar_url {
            m.insert("avatarUrl".into(), serde_json::json!(a));
        }
        m.insert("muted".into(), serde_json::json!(self.muted));
        m.insert("deafened".into(), serde_json::json!(self.deafened));
        m.insert("video".into(), serde_json::json!(self.video));
        m.insert("streaming".into(), serde_json::json!(self.streaming));
        m.insert("serverMuted".into(), serde_json::json!(self.server_muted));
        m.insert("serverDeafened".into(), serde_json::json!(self.server_deafened));
        m.insert("joinedAt".into(), serde_json::json!(self.joined_at));
        Value::Object(m)
    }
}

/// Présence vocale : salons, appartenance utilisateur → salon, statut libre de salon.
#[derive(Default)]
pub struct VoiceState {
    /// channelId → (userId → participant)
    pub channels: IndexMap<String, IndexMap<String, VoiceParticipant>>,
    /// Chaque utilisateur n'est que dans un seul salon vocal : userId → channelId
    pub user_channel: HashMap<String, String>,
    /// channelId → statut libre
    pub status: HashMap<String, String>,
}

#[derive(Default)]
pub struct Connections {
    pub clients: Mutex<HashMap<String, ConnectedClient>>,
    pub nodes: Mutex<HashMap<String, ConnectedNode>>,
    pub voice: Mutex<VoiceState>,
}

/// Statut de modération d'un utilisateur (service users).
#[derive(Clone, Debug, Default)]
pub struct Moderation {
    pub banned: bool,
    pub banned_until: Option<String>,
    pub ban_reason: Option<String>,
    pub muted: bool,
    pub muted_until: Option<String>,
    pub mute_reason: Option<String>,
    pub warnings: i64,
}

impl Moderation {
    pub fn from_value(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let b = |k: &str| v.get(k).map(|x| !matches!(x, Value::Null | Value::Bool(false)) && x != &Value::from(0) && x != &Value::from("")).unwrap_or(false);
        Self {
            banned: b("banned"),
            banned_until: s("bannedUntil"),
            ban_reason: s("banReason"),
            muted: b("muted"),
            muted_until: s("mutedUntil"),
            mute_reason: s("muteReason"),
            warnings: v.get("warnings").and_then(|x| x.as_i64()).unwrap_or(0),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChannelMeta {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub slow_mode: i64,
    pub user_limit: i64,
}

/// Cache des blocages MP (60 s).
pub struct BlockEntry {
    pub a_blocked_b: bool,
    pub b_blocked_a: bool,
    pub expires_at: i64,
}

pub struct HttpLimiters {
    pub anon: RedisLimiter,
    pub user: RedisLimiter,
    pub admin: RedisLimiter,
    pub auth: RedisLimiter,
}

pub struct AppState {
    pub cfg: &'static Config,
    pub redis: RedisClient,
    pub http: reqwest::Client,
    pub lb: Arc<LbRegistry>,
    pub gateways: GatewayRegistry,
    pub svc: Services,
    pub monitoring: MonitoringDb,
    pub gateway_id: String,
    pub started: Instant,
    pub io: OnceLock<Io>,
    pub conns: Connections,
    pub ws_limits: Arc<WsLimits>,
    pub limiters: HttpLimiters,
    pub banned_service_ids: Mutex<HashSet<String>>,
    pub allowed_service_ids: Mutex<HashSet<String>>,
    pub block_cache: Mutex<HashMap<String, BlockEntry>>,
    pub moderation_cache: Mutex<HashMap<String, (Option<Moderation>, Instant)>>,
    pub channel_meta_cache: Mutex<HashMap<String, (Instant, HashMap<String, ChannelMeta>)>>,
    pub resync_timers: Mutex<HashMap<String, tokio::task::AbortHandle>>,
    pub webhook_hits: Mutex<HashMap<String, Vec<i64>>>,
    pub stats_cache: Mutex<Option<(Value, Instant)>>,
}

impl AppState {
    pub fn io(&self) -> &Io {
        self.io.get().expect("Socket.IO non initialisé")
    }

    /// Résout l'URL d'un service pour les routes HTTP (équivalent de `getServiceUrl`).
    /// Dev : l'URL .env. Production : l'instance LB la plus saine, ou `""` (→ 503).
    pub fn service_url(&self, service_type: &str, fallback: &str) -> String {
        if !self.cfg.is_production {
            return fallback.to_string();
        }
        self.lb.select_best(service_type).map(|e| e.endpoint).unwrap_or_default()
    }

    /// Variante pour les services pas toujours déclarés au LB (hébergement, abonnements) :
    /// une instance en ligne est préférée, sinon l'URL .env reste utilisée, y compris en production.
    pub fn service_url_or_env(&self, service_type: &str, fallback: &str) -> String {
        if !self.cfg.is_production {
            return fallback.to_string();
        }
        self.lb.select_best(service_type).map(|e| e.endpoint).filter(|e| !e.is_empty()).unwrap_or_else(|| fallback.to_string())
    }

    pub fn clients_len(&self) -> usize {
        self.conns.clients.lock().len()
    }

    pub fn node(&self, server_id: &str) -> Option<ConnectedNode> {
        self.conns.nodes.lock().get(server_id).cloned()
    }

    pub fn has_node(&self, server_id: &str) -> bool {
        self.conns.nodes.lock().contains_key(server_id)
    }
}

/// Événement Socket.IO standard `{ type, payload, timestamp }`.
pub fn event(kind: &str, payload: Value) -> Value {
    serde_json::json!({ "type": kind, "payload": payload, "timestamp": crate::iso::to_string(&Utc::now()) })
}

#[derive(Serialize)]
pub struct Empty {}
