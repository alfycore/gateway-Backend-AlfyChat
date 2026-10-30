//! Registre des instances de gateway (multi-gateway).

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use parking_lot::RwLock;
use serde::Serialize;
use tracing::info;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayEntry {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    #[serde(serialize_with = "crate::iso::ser")]
    pub registered_at: DateTime<Utc>,
    #[serde(serialize_with = "crate::iso::ser")]
    pub last_seen: DateTime<Utc>,
    pub is_self: bool,
}

#[derive(Default)]
pub struct GatewayRegistry {
    gateways: RwLock<IndexMap<String, GatewayEntry>>,
}

impl GatewayRegistry {
    pub fn register(&self, id: &str, name: &str, url: &str, enabled: Option<bool>, is_self: bool) -> GatewayEntry {
        let now = Utc::now();
        let mut g = self.gateways.write();
        let registered_at = g.get(id).map(|e| e.registered_at).unwrap_or(now);
        let entry = GatewayEntry {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            enabled: enabled.unwrap_or(true),
            registered_at,
            last_seen: now,
            is_self,
        };
        g.insert(id.into(), entry.clone());
        info!("GatewayRegistry: gateway \"{id}\" ({name}) @ {url}{}", if is_self { " [SELF]" } else { "" });
        entry
    }

    pub fn touch(&self, id: &str) {
        if let Some(g) = self.gateways.write().get_mut(id) {
            g.last_seen = Utc::now();
        }
    }

    pub fn remove(&self, id: &str) -> bool {
        let ok = self.gateways.write().shift_remove(id).is_some();
        if ok {
            info!("GatewayRegistry: gateway \"{id}\" supprimé");
        }
        ok
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        match self.gateways.write().get_mut(id) {
            Some(g) => {
                g.enabled = enabled;
                true
            }
            None => false,
        }
    }

    pub fn update(&self, id: &str, name: Option<&str>, url: Option<&str>) -> bool {
        match self.gateways.write().get_mut(id) {
            Some(g) => {
                if let Some(n) = name {
                    g.name = n.into();
                }
                if let Some(u) = url {
                    g.url = u.into();
                }
                true
            }
            None => false,
        }
    }

    pub fn get_all(&self) -> Vec<GatewayEntry> {
        self.gateways.read().values().cloned().collect()
    }

    pub fn get_by_id(&self, id: &str) -> Option<GatewayEntry> {
        self.gateways.read().get(id).cloned()
    }

    pub fn is_online(&self, id: &str, timeout_ms: i64) -> bool {
        self.gateways
            .read()
            .get(id)
            .map(|g| (Utc::now() - g.last_seen).num_milliseconds() < timeout_ms)
            .unwrap_or(false)
    }
}
