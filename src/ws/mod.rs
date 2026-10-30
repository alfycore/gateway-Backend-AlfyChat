//! Temps réel Socket.IO : état par socket, enregistrement des handlers, helpers d'émission.

pub mod calls;
pub mod connect;
pub mod helpers;
pub mod internal;
pub mod messages;
pub mod misc;
pub mod nodes_ns;
pub mod presence;
pub mod servers;

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use regex::Regex;
use serde_json::{json, Value};
use socketioxide::extract::{AckSender, TryData};
use socketioxide::handler::FromMessageParts;
use socketioxide::socket::Socket;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tracing::warn;

use crate::ratelimit::SocketLimiter;
use crate::state::{event, AppState, Sock, A};

/// Room Socket.IO d'un salon de serveur, NAMESPACÉE par serveur : un salon revendiqué à tort
/// ne reçoit jamais que les diffusions de son propre serveur.
pub fn ch_room(server_id: &str, channel_id: &str) -> String {
    format!("ch:{server_id}:{channel_id}")
}

// ── Accusé de réception ─────────────────────────────────────────────────────

/// Accusé de réception d'un événement : `present` vaut `false` si le client n'a pas passé de callback
/// (équivalent de `typeof callback === 'function'`).
pub struct Ack {
    inner: Option<AckSender<A>>,
    pub present: bool,
}

impl Ack {
    /// Répond au client. Sans effet s'il n'a pas demandé d'accusé ou si on a déjà répondu
    /// (Socket.IO ignore le second appel du callback).
    pub fn send(&mut self, data: &Value) {
        if let Some(a) = self.inner.take() {
            let _ = a.send(data);
        }
    }
}

impl FromMessageParts<A> for Ack {
    type Error = Infallible;
    fn from_message_parts(s: &Arc<Socket<A>>, v: &mut socketioxide_core::Value, ack_id: &Option<i64>) -> Result<Self, Infallible> {
        Ok(Ack { inner: Some(AckSender::<A>::from_message_parts(s, v, ack_id)?), present: ack_id.is_some() })
    }
}

// ── État par connexion ──────────────────────────────────────────────────────

pub struct SockCtx {
    pub app: Arc<AppState>,
    pub socket: Sock,
    pub user_id: String,
    pub session_id: String,
    /// Profil renvoyé par le service users.
    pub user: Value,
    pub token: Option<String>,
    pub limiter: SocketLimiter,
    pub ready: watch::Receiver<bool>,
    /// Suppressions en attente : messageId → userId (écriture DB pas encore terminée).
    pub pending_deletions: Mutex<HashMap<String, String>>,
    /// Demandes d'archive DM en attente d'un pair : requestId → minuterie.
    pub pending_archive: Mutex<HashMap<String, AbortHandle>>,
    /// Participants d'un appel, mis en cache quelques secondes (échange ICE).
    pub call_members: Mutex<HashMap<String, (std::collections::HashSet<String>, Instant)>>,
    /// Horodatage (ms) du dernier VOICE_SPEAKING relayé (borne le débit à 120 ms).
    pub last_speaking: Mutex<i64>,
}

impl SockCtx {
    pub fn io(&self) -> &crate::state::Io {
        self.app.io()
    }

    pub fn user_str(&self, key: &str) -> Option<&str> {
        self.user.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
    }

    /// `user.displayName || user.username`
    pub fn display_name(&self) -> String {
        self.user_str("displayName").or_else(|| self.user_str("username")).unwrap_or("").to_string()
    }

    pub fn username(&self) -> String {
        self.user_str("username").unwrap_or("").to_string()
    }

    /// `user.avatarUrl || null`
    pub fn avatar(&self) -> Value {
        self.user_str("avatarUrl").map(|s| json!(s)).unwrap_or(Value::Null)
    }

    pub fn in_room(&self, room: &str) -> bool {
        self.socket.rooms().iter().any(|r| r.as_ref() == room)
    }

    /// `socket.emit(type, { type, payload, timestamp })`
    pub fn emit_event(&self, kind: &str, payload: Value) {
        let _ = self.socket.emit(kind, &event(kind, payload));
    }

    /// Message d'erreur affichable au client (`emitError`).
    pub fn emit_error(&self, kind: &str, message: &str) {
        let _ = self.socket.emit("ERROR", &error_event(kind, message));
    }

    /// Émet un événement standard `{type, payload, timestamp}` à une room.
    pub async fn to_room(&self, room: &str, kind: &str, payload: Value) {
        let _ = self.io().to(room.to_string()).emit(kind, &event(kind, payload)).await;
    }

    /// Idem, mais sans l'émetteur (`socket.to(room).emit`).
    pub async fn to_room_others(&self, room: &str, kind: &str, payload: Value) {
        let _ = self.socket.to(room.to_string()).emit(kind, &event(kind, payload)).await;
    }

    /// Émet un événement brut (corps non enveloppé) à une room.
    pub async fn raw_to_room(&self, room: &str, name: &str, body: &Value) {
        let _ = self.io().to(room.to_string()).emit(name, body).await;
    }

    pub async fn raw_to_room_others(&self, room: &str, name: &str, body: &Value) {
        let _ = self.socket.to(room.to_string()).emit(name, body).await;
    }
}

static SERVICE_ERR_RE: once_cell::sync::Lazy<Regex> =
    once_cell::sync::Lazy::new(|| Regex::new(r"(?s)^Service error: (\d{3}) (.*)$").unwrap());

/// Message d'erreur nettoyé : pas de détail interne (corps bruts du media-server / des services).
pub fn clean_error(message: &str) -> String {
    let mut message = message.to_string();
    if message.starts_with("media-server ") {
        message = "Opération refusée".into();
    }
    if let Some(m) = SERVICE_ERR_RE.captures(&message) {
        let mut clean = format!("Erreur {}", &m[1]);
        if let Ok(body) = serde_json::from_str::<Value>(&m[2]) {
            if let Some(e) = body.get("error").and_then(|v| v.as_str()) {
                clean = e.to_string();
            }
        }
        message = clean;
    }
    message
}

pub fn error_event(kind: &str, message: &str) -> Value {
    json!({ "type": kind, "payload": { "message": clean_error(message) }, "timestamp": crate::iso::to_string(&chrono::Utc::now()) })
}

/// Message pour une erreur qui n'est pas une `Error` JS (objet brut jeté) : message générique.
pub const GENERIC_ERROR: &str = "Une erreur est survenue";

// ── Enregistrement des handlers ─────────────────────────────────────────────

/// Enregistre un handler. Dans l'ordre : limiteur par socket (le paquet est ignoré au-delà),
/// attente de la fin de l'initialisation (les paquets arrivés avant sont mis en file, pas perdus),
/// détection d'anomalies, puis le handler.
pub fn on<F, Fut>(c: &Arc<SockCtx>, event_name: &'static str, f: F)
where
    F: Fn(Arc<SockCtx>, Value, Ack) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let ctx = c.clone();
    c.socket.on(event_name, move |_s: Sock, TryData(args): TryData<Value>, ack: Ack| {
        let (ctx, f) = (ctx.clone(), f.clone());
        async move {
            if !ctx.limiter.allow(event_name) {
                warn!("RATE_LIMITED: {} ({event_name})", ctx.user_id);
                return;
            }
            let mut ready = ctx.ready.clone();
            let _ = ready.wait_for(|r| *r).await;
            if !crate::anomaly::ws_event_ignored(event_name) {
                let (app, uid) = (ctx.app.clone(), ctx.user_id.clone());
                tokio::spawn(async move { crate::anomaly::record_and_score(&app, &uid, &format!("WS:{event_name}"), false).await });
            }
            // Un seul argument de données (0 → Null) ; un éventuel callback n'est pas dans le corps.
            let data = args.unwrap_or(Value::Null);
            f(ctx, data, ack).await;
        }
    });
}
