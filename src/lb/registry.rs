//! Registre des microservices (répartition de charge) : source de vérité unique des services et des clés.
//!
//! `media-server` (SFU) n'est jamais réparti à la charge : ses salles vivent en mémoire,
//! le gateway épingle une instance.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand::RngCore;
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Seule liste de référence : les routes admin la valident, le front la reçoit via GET /api/admin/services.
pub const SERVICE_TYPES: [&str; 10] = [
    "users",
    "messages",
    "friends",
    "calls",
    "servers",
    "bots",
    "media",
    "serverhosting",
    "subscriptions",
    "media-server",
];

pub fn is_service_type(v: &str) -> bool {
    SERVICE_TYPES.contains(&v)
}

const HEARTBEAT_TIMEOUT_MS: i64 = 90_000;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_SCORE: f64 = 50.0;

static LOCAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^https?://(localhost|127\.0\.0\.1)").unwrap());
static IP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^https?://(\d{1,3}\.){3}\d{1,3}").unwrap());

fn is_local(endpoint: &str) -> bool {
    LOCAL_RE.is_match(endpoint) || IP_RE.is_match(endpoint)
}

/// Clé de service `sk_…` (32 octets en base64url) et son empreinte SHA-256.
pub fn generate_service_key() -> (String, String) {
    use base64::Engine;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    let raw = format!("sk_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b));
    let hash = hash_service_key(&raw);
    (raw, hash)
}

pub fn hash_service_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceMetrics {
    pub cpu_usage: f64,
    pub cpu_max: f64,
    pub ram_usage: f64,
    pub ram_max: f64,
    pub bandwidth_usage: f64,
    #[serde(rename = "requestCount20min")]
    pub request_count_20min: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<f64>,
}

impl ServiceMetrics {
    /// Métriques envoyées par un service (JSON libre) : un champ absent ou non numérique vaut 0 (cpuMax : 100).
    pub fn from_value(v: &serde_json::Value) -> Self {
        let n = |k: &str, d: f64| v.get(k).and_then(|x| x.as_f64()).unwrap_or(d);
        Self {
            cpu_usage: n("cpuUsage", 0.0),
            cpu_max: n("cpuMax", 100.0),
            ram_usage: n("ramUsage", 0.0),
            ram_max: n("ramMax", 0.0),
            bandwidth_usage: n("bandwidthUsage", 0.0),
            request_count_20min: n("requestCount20min", 0.0),
            response_time_ms: v.get("responseTimeMs").and_then(|x| x.as_f64()),
        }
    }

    pub fn empty() -> Self {
        Self {
            cpu_usage: 0.0,
            cpu_max: 100.0,
            ram_usage: 0.0,
            ram_max: 0.0,
            bandwidth_usage: 0.0,
            request_count_20min: 0.0,
            response_time_ms: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
    pub domain: String,
    pub location: String,
    #[serde(serialize_with = "crate::iso::ser")]
    pub registered_at: DateTime<Utc>,
    #[serde(serialize_with = "crate::iso::ser_opt")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub metrics: ServiceMetrics,
    /// "online" | "degraded" | "offline"
    pub status: String,
    pub enabled: bool,
    pub degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "crate::iso::ser_opt")]
    pub degraded_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    pub healthy: bool,
    pub is_local: bool,
}

pub struct PreRegister<'a> {
    pub id: &'a str,
    pub service_type: &'a str,
    pub location: &'a str,
    pub enabled: Option<bool>,
    pub key_hash: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub domain: Option<&'a str>,
}

pub struct Registration<'a> {
    pub endpoint: &'a str,
    pub domain: Option<&'a str>,
    pub gateway_id: Option<&'a str>,
}

#[derive(Default)]
struct Inner {
    entries: IndexMap<String, ServiceEntry>,
    /// keyHash → serviceId
    key_index: IndexMap<String, String>,
}

#[derive(Default)]
pub struct LbRegistry {
    inner: RwLock<Inner>,
}

fn host_of(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => endpoint.to_string(),
        },
        Err(_) => endpoint.to_string(),
    }
}

impl LbRegistry {
    /// Crée le registre et lance le nettoyage périodique (nécessite un runtime tokio).
    pub fn new() -> Arc<Self> {
        let reg = Arc::new(Self::default());
        let weak = Arc::downgrade(&reg);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                match weak.upgrade() {
                    Some(r) => r.cleanup(),
                    None => break,
                }
            }
        });
        reg
    }

    // ── Clés ───────────────────────────────────────────────────────────────

    pub fn add_key_hash(&self, service_id: &str, key_hash: &str) {
        let mut g = self.inner.write();
        g.key_index.retain(|_, id| id != service_id);
        g.key_index.insert(key_hash.to_string(), service_id.to_string());
    }

    pub fn remove_key(&self, service_id: &str) {
        self.inner.write().key_index.retain(|_, id| id != service_id);
    }

    pub fn validate_key(&self, raw_key: &str) -> Option<String> {
        self.inner.read().key_index.get(&hash_service_key(raw_key)).cloned()
    }

    // ── Pré-enregistrement (l'admin crée un emplacement) ──────────────────

    pub fn pre_register(&self, d: PreRegister) -> ServiceEntry {
        let entry = {
            let mut g = self.inner.write();
            let existing = g.entries.get(d.id).cloned();
            let entry = ServiceEntry {
                id: d.id.to_string(),
                service_type: d.service_type.to_string(),
                endpoint: d
                    .endpoint
                    .map(str::to_string)
                    .or_else(|| existing.as_ref().map(|e| e.endpoint.clone()))
                    .unwrap_or_default(),
                domain: d
                    .domain
                    .map(str::to_string)
                    .or_else(|| existing.as_ref().map(|e| e.domain.clone()))
                    .unwrap_or_default(),
                location: d.location.to_string(),
                registered_at: existing.as_ref().map(|e| e.registered_at).unwrap_or_else(Utc::now),
                last_heartbeat: existing.as_ref().and_then(|e| e.last_heartbeat),
                metrics: existing.as_ref().map(|e| e.metrics.clone()).unwrap_or_else(ServiceMetrics::empty),
                status: existing.as_ref().map(|e| e.status.clone()).unwrap_or_else(|| "offline".into()),
                enabled: d.enabled.or(existing.as_ref().map(|e| e.enabled)).unwrap_or(true),
                degraded: existing.as_ref().map(|e| e.degraded).unwrap_or(false),
                degraded_reason: existing.as_ref().and_then(|e| e.degraded_reason.clone()),
                degraded_at: existing.as_ref().and_then(|e| e.degraded_at),
                gateway_id: existing.as_ref().and_then(|e| e.gateway_id.clone()),
                healthy: existing.as_ref().map(|e| e.healthy).unwrap_or(false),
                is_local: is_local(d.endpoint.unwrap_or("")),
            };
            g.entries.insert(d.id.to_string(), entry.clone());
            entry
        };
        if let Some(h) = d.key_hash.filter(|h| !h.is_empty()) {
            self.add_key_hash(d.id, h);
        }
        entry
    }

    // ── Enregistrement en direct ──────────────────────────────────────────

    /// Sans clé — repli sur INTERNAL_SECRET (SERVICE_KEY absent).
    pub fn register_by_id(&self, service_id: &str, d: Registration) -> Option<ServiceEntry> {
        let mut g = self.inner.write();
        let e = g.entries.get_mut(service_id)?;
        if !e.enabled {
            return None;
        }
        Some(Self::apply_registration(e, d))
    }

    pub fn register_with_key(&self, raw_key: &str, d: Registration) -> Option<ServiceEntry> {
        let id = self.validate_key(raw_key)?;
        self.register_by_id(&id, d)
    }

    fn apply_registration(e: &mut ServiceEntry, d: Registration) -> ServiceEntry {
        let ep = d.endpoint.trim().to_string();
        e.domain = d.domain.map(str::to_string).unwrap_or_else(|| host_of(&ep));
        e.endpoint = ep.clone();
        e.last_heartbeat = Some(Utc::now());
        e.status = "online".into();
        e.healthy = true;
        e.is_local = is_local(&ep);
        e.gateway_id = d.gateway_id.map(str::to_string);
        e.degraded = false;
        e.degraded_reason = None;
        e.degraded_at = None;
        info!("LBRegistry: \"{}\" ({}) en ligne @ {} [{}]", e.id, e.service_type, ep, e.location);
        e.clone()
    }

    pub fn heartbeat(&self, service_id: &str, metrics: ServiceMetrics) -> bool {
        let mut g = self.inner.write();
        let Some(e) = g.entries.get_mut(service_id) else { return false };
        e.last_heartbeat = Some(Utc::now());
        e.metrics = metrics;
        e.status = "online".into();
        e.healthy = true;
        true
    }

    // ── Opérations admin ──────────────────────────────────────────────────

    pub fn remove(&self, id: &str) -> bool {
        self.remove_key(id);
        let ok = self.inner.write().entries.shift_remove(id).is_some();
        if ok {
            info!("LBRegistry: service \"{id}\" supprimé");
        }
        ok
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        let mut g = self.inner.write();
        let Some(e) = g.entries.get_mut(id) else { return false };
        e.enabled = enabled;
        if !enabled {
            e.status = "offline".into();
            e.healthy = false;
        }
        info!("LBRegistry: service \"{id}\" {}", if enabled { "activé" } else { "désactivé" });
        true
    }

    /// Arrêt gracieux d'un service : hors ligne et non sain, sans le retirer du registre.
    pub fn mark_offline(&self, id: &str) -> bool {
        let mut g = self.inner.write();
        match g.entries.get_mut(id) {
            Some(e) => {
                e.status = "offline".into();
                e.healthy = false;
                true
            }
            None => false,
        }
    }

    pub fn mark_degraded(&self, id: &str, reason: &str) -> Option<ServiceEntry> {
        let mut g = self.inner.write();
        let e = g.entries.get_mut(id)?;
        e.degraded = true;
        e.degraded_at = Some(Utc::now());
        e.degraded_reason = Some(reason.to_string());
        e.status = "degraded".into();
        warn!("LBRegistry: service \"{id}\" dégradé — {reason}");
        Some(e.clone())
    }

    pub fn restore_instance(&self, id: &str) -> bool {
        let mut g = self.inner.write();
        let Some(e) = g.entries.get_mut(id) else { return false };
        e.degraded = false;
        e.degraded_at = None;
        e.degraded_reason = None;
        e.status = if e.last_heartbeat.is_some() { "online".into() } else { "offline".into() };
        e.healthy = e.last_heartbeat.is_some();
        info!("LBRegistry: service \"{id}\" restauré");
        true
    }

    pub fn update_endpoint(&self, id: &str, endpoint: &str) -> bool {
        let mut g = self.inner.write();
        let Some(e) = g.entries.get_mut(id) else { return false };
        e.endpoint = endpoint.to_string();
        e.is_local = is_local(endpoint);
        e.domain = host_of(endpoint);
        true
    }

    // ── Lectures ──────────────────────────────────────────────────────────

    pub fn get_by_id(&self, id: &str) -> Option<ServiceEntry> {
        self.inner.read().entries.get(id).cloned()
    }

    pub fn get_all(&self) -> Vec<ServiceEntry> {
        self.inner.read().entries.values().cloned().collect()
    }

    pub fn get_degraded(&self) -> Vec<ServiceEntry> {
        self.get_all().into_iter().filter(|e| e.degraded).collect()
    }

    pub fn get_instances(&self, service_type: &str, include_unhealthy: bool, include_disabled: bool) -> Vec<ServiceEntry> {
        self.get_all()
            .into_iter()
            .filter(|e| {
                e.service_type == service_type
                    && (include_unhealthy || e.healthy)
                    && (include_disabled || e.enabled)
                    && !e.degraded
            })
            .collect()
    }

    /// Préfère les instances non locales ; à score égal, la première enregistrée l'emporte.
    pub fn select_best(&self, service_type: &str) -> Option<ServiceEntry> {
        let pool = self.get_instances(service_type, false, false);
        if pool.is_empty() {
            return None;
        }
        let remote: Vec<_> = pool.iter().filter(|e| !e.is_local).cloned().collect();
        Some(pick_best(if remote.is_empty() { pool } else { remote }))
    }

    pub fn select_best_by_location(&self, service_type: &str, loc: Option<&str>) -> Option<ServiceEntry> {
        let pool = self.get_instances(service_type, false, false);
        if pool.is_empty() {
            return None;
        }
        let remote: Vec<_> = pool.iter().filter(|e| !e.is_local).cloned().collect();
        let base = if remote.is_empty() { pool } else { remote };
        if let Some(loc) = loc.filter(|l| !l.is_empty()) {
            let in_region: Vec<_> = base
                .iter()
                .filter(|e| e.location.to_uppercase() == loc.to_uppercase())
                .cloned()
                .collect();
            if !in_region.is_empty() {
                return Some(pick_best(in_region));
            }
        }
        Some(pick_best(base))
    }

    fn cleanup(&self) {
        let now = Utc::now();
        let mut g = self.inner.write();
        for e in g.entries.values_mut() {
            let Some(hb) = e.last_heartbeat else { continue };
            if !e.healthy {
                continue;
            }
            if (now - hb).num_milliseconds() > HEARTBEAT_TIMEOUT_MS {
                e.healthy = false;
                e.status = "offline".into();
                warn!("LBRegistry: \"{}\" offline (heartbeat timeout)", e.id);
            }
        }
    }
}

pub fn compute_score(e: &ServiceEntry) -> f64 {
    let m = &e.metrics;
    if m.ram_max <= 0.0 && m.cpu_max <= 0.0 {
        return DEFAULT_SCORE;
    }
    let cpu = if m.cpu_max > 0.0 { (1.0 - m.cpu_usage / m.cpu_max).max(0.0) } else { 0.5 };
    let ram = if m.ram_max > 0.0 { (1.0 - m.ram_usage / m.ram_max).max(0.0) } else { 0.5 };
    let req = (1.0 - m.request_count_20min.min(2000.0) / 2000.0).max(0.0);
    cpu * 40.0 + ram * 30.0 + req * 30.0
}

/// Le premier de meilleur score l'emporte en cas d'égalité (reduce d'origine).
fn pick_best(candidates: Vec<ServiceEntry>) -> ServiceEntry {
    let mut it = candidates.into_iter();
    let mut best = it.next().expect("candidats non vides");
    for cur in it {
        if compute_score(&cur) > compute_score(&best) {
            best = cur;
        }
    }
    best
}
