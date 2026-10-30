//! Client Redis du gateway (équivalent de `utils/redis.ts`) : mêmes clés, mêmes TTL, mêmes formats JSON.

use std::collections::HashMap;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Clone)]
pub struct RedisClient {
    conn: ConnectionManager,
    client: redis::Client,
}

/// Présence d'un utilisateur (`presence:<id>`, TTL 24 h). Les champs inconnus sont conservés tels quels.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceData {
    pub status: String,
    pub chosen_status: String,
    pub emoji: Option<String>,
    pub text: Option<String>,
    pub last_activity: i64,
    pub auto_idle: bool,
}

/// Champs à modifier ; `None` = inchangé, `Some(None)` = vider (emoji/text).
#[derive(Default, Clone, Debug)]
pub struct PresencePatch {
    pub status: Option<String>,
    pub chosen_status: Option<String>,
    pub emoji: Option<Option<String>>,
    pub text: Option<Option<String>>,
    pub last_activity: Option<i64>,
    pub auto_idle: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkPresence {
    pub user_id: String,
    pub status: String,
    pub custom_status: Option<String>,
    pub emoji: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BannedIp {
    pub ip: String,
    pub reason: Value,
    pub banned_by: Value,
    pub banned_at: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPing {
    pub count: i64,
    pub sender_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRooms {
    pub server_ids: Vec<String>,
    pub channel_ids: Vec<String>,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

const PRESENCE_TTL: u64 = 86400;

impl RedisClient {
    pub async fn connect(host: &str, port: u16, password: Option<&str>) -> RedisResult<Self> {
        let url = match password.filter(|p| !p.is_empty()) {
            Some(p) => format!("redis://:{}@{host}:{port}", utf8_percent_encode(p, NON_ALPHANUMERIC)),
            None => format!("redis://{host}:{port}"),
        };
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client.clone()).await?;
        tracing::info!("Redis client connecté");
        Ok(Self { conn, client })
    }

    /// Connexion partageable (équivalent de `getRawClient()` : limiteurs, adaptateur Socket.IO).
    pub fn raw(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub fn raw_client(&self) -> &redis::Client {
        &self.client
    }

    fn c(&self) -> ConnectionManager {
        self.conn.clone()
    }

    // ── Connexions / en ligne ─────────────────────────────────────────────

    pub async fn set_user_online(&self, user_id: &str, socket_id: &str) -> RedisResult<()> {
        let mut c = self.c();
        let _: () = c.sadd(format!("user:sockets:{user_id}"), socket_id).await?;
        let _: () = c.sadd("online:list", user_id).await?;
        let _: () = c.hset("online:users", user_id, socket_id).await?;
        Ok(())
    }

    pub async fn set_user_offline(&self, user_id: &str, socket_id: &str) -> RedisResult<()> {
        let mut c = self.c();
        let key = format!("user:sockets:{user_id}");
        let _: () = c.srem(&key, socket_id).await?;
        let remaining: i64 = c.scard(&key).await?;
        if remaining == 0 {
            let _: () = c.hdel("online:users", user_id).await?;
            let _: () = c.srem("online:list", user_id).await?;
        }
        Ok(())
    }

    pub async fn is_user_online(&self, user_id: &str) -> RedisResult<bool> {
        self.c().sismember("online:list", user_id).await
    }

    /// Sous-ensemble des utilisateurs en ligne, en UNE commande.
    pub async fn get_online_set(&self, user_ids: &[String]) -> RedisResult<std::collections::HashSet<String>> {
        let ids: Vec<&String> = user_ids.iter().filter(|s| !s.is_empty()).collect();
        let mut online = std::collections::HashSet::new();
        if ids.is_empty() {
            return Ok(online);
        }
        let mut cmd = redis::cmd("SMISMEMBER");
        cmd.arg("online:list");
        for id in &ids {
            cmd.arg(id.as_str());
        }
        let flags: Vec<i64> = cmd.query_async(&mut self.c()).await?;
        for (i, id) in ids.iter().enumerate() {
            if flags.get(i).copied() == Some(1) {
                online.insert((*id).clone());
            }
        }
        Ok(online)
    }

    pub async fn get_user_socket_id(&self, user_id: &str) -> RedisResult<Option<String>> {
        self.c().hget("online:users", user_id).await
    }

    // ── Présence ──────────────────────────────────────────────────────────

    pub async fn set_presence(&self, user_id: &str, patch: PresencePatch) -> RedisResult<()> {
        let key = format!("presence:{user_id}");
        let mut c = self.c();
        let raw: Option<String> = c.get(&key).await?;
        let current: Option<Map<String, Value>> = raw
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
            .and_then(|v| if let Value::Object(m) = v { Some(m) } else { None });

        let cur = |k: &str| current.as_ref().and_then(|m| m.get(k)).filter(|v| !v.is_null()).cloned();
        let mut merged = Map::new();
        merged.insert("status".into(), cur("status").unwrap_or_else(|| json!("online")));
        merged.insert("chosenStatus".into(), cur("chosenStatus").unwrap_or_else(|| json!("online")));
        merged.insert("emoji".into(), cur("emoji").unwrap_or(Value::Null));
        merged.insert("text".into(), cur("text").unwrap_or(Value::Null));
        merged.insert("lastActivity".into(), cur("lastActivity").unwrap_or_else(|| json!(now_ms())));
        merged.insert("autoIdle".into(), cur("autoIdle").unwrap_or_else(|| json!(false)));

        if let Some(v) = patch.status {
            merged.insert("status".into(), json!(v));
        }
        if let Some(v) = patch.chosen_status {
            merged.insert("chosenStatus".into(), json!(v));
        }
        if let Some(v) = patch.emoji {
            merged.insert("emoji".into(), json!(v));
        }
        if let Some(v) = patch.text {
            merged.insert("text".into(), json!(v));
        }
        if let Some(v) = patch.last_activity {
            merged.insert("lastActivity".into(), json!(v));
        }
        if let Some(v) = patch.auto_idle {
            merged.insert("autoIdle".into(), json!(v));
        }
        let _: () = c.set_ex(&key, Value::Object(merged).to_string(), PRESENCE_TTL).await?;
        Ok(())
    }

    pub async fn get_presence(&self, user_id: &str) -> RedisResult<Option<Value>> {
        let raw: Option<String> = self.c().get(format!("presence:{user_id}")).await?;
        Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
    }

    /// Met à jour uniquement `lastActivity` (appelé depuis HEARTBEAT).
    pub async fn touch_activity(&self, user_id: &str) -> RedisResult<()> {
        let key = format!("presence:{user_id}");
        let mut c = self.c();
        let raw: Option<String> = c.get(&key).await?;
        let Some(raw) = raw else { return Ok(()) };
        if let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(&raw) {
            m.insert("lastActivity".into(), json!(now_ms()));
            let _: () = c.set_ex(&key, Value::Object(m).to_string(), PRESENCE_TTL).await?;
        }
        Ok(())
    }

    /// Présence de plusieurs utilisateurs : GET + SCARD par utilisateur dans un seul pipeline.
    pub async fn get_bulk_presence(&self, user_ids: &[String]) -> RedisResult<Vec<BulkPresence>> {
        if user_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut pipe = redis::pipe();
        for uid in user_ids {
            pipe.get(format!("presence:{uid}"));
            pipe.scard(format!("user:sockets:{uid}"));
        }
        let results: Vec<redis::Value> = pipe.query_async(&mut self.c()).await?;
        let offline = |user_id: &String| BulkPresence { user_id: user_id.clone(), status: "offline".into(), custom_status: None, emoji: None };
        Ok(user_ids
            .iter()
            .enumerate()
            .map(|(i, user_id)| {
                let raw: Option<String> = results.get(i * 2).and_then(|v| redis::from_redis_value(v.clone()).ok());
                let scount: i64 = results.get(i * 2 + 1).and_then(|v| redis::from_redis_value(v.clone()).ok()).unwrap_or(0);
                let Some(raw) = raw else { return offline(user_id) };
                if scount == 0 {
                    return offline(user_id);
                }
                match serde_json::from_str::<Value>(&raw) {
                    Ok(p) => {
                        let status = p.get("status").and_then(|s| s.as_str()).unwrap_or("online");
                        BulkPresence {
                            user_id: user_id.clone(),
                            status: if status == "invisible" { "offline".into() } else { status.to_string() },
                            custom_status: p.get("text").and_then(|s| s.as_str()).map(str::to_string),
                            emoji: p.get("emoji").and_then(|s| s.as_str()).map(str::to_string),
                        }
                    }
                    Err(_) => offline(user_id),
                }
            })
            .collect())
    }

    // ── Sessions ──────────────────────────────────────────────────────────

    pub async fn set_session(&self, user_id: &str, session_id: &str, data: &Value, ttl: u64) -> RedisResult<()> {
        let mut c = self.c();
        let _: () = c.set_ex(format!("session:{user_id}:{session_id}"), data.to_string(), ttl).await?;
        let _: () = c.sadd(format!("user:sessions:{user_id}"), session_id).await?;
        Ok(())
    }

    pub async fn get_session(&self, user_id: &str, session_id: &str) -> RedisResult<Option<Value>> {
        let raw: Option<String> = self.c().get(format!("session:{user_id}:{session_id}")).await?;
        Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
    }

    pub async fn delete_session(&self, user_id: &str, session_id: &str) -> RedisResult<()> {
        let mut c = self.c();
        let _: () = c.del(format!("session:{user_id}:{session_id}")).await?;
        let _: () = c.srem(format!("user:sessions:{user_id}"), session_id).await?;
        Ok(())
    }

    // ── Frappe en cours ───────────────────────────────────────────────────

    pub async fn set_typing(&self, conversation_id: &str, user_id: &str) -> RedisResult<()> {
        let key = format!("typing:{conversation_id}");
        let mut c = self.c();
        let _: () = c.hset(&key, user_id, now_ms().to_string()).await?;
        let _: () = c.expire(&key, 5).await?;
        Ok(())
    }

    pub async fn remove_typing(&self, conversation_id: &str, user_id: &str) -> RedisResult<()> {
        self.c().hdel(format!("typing:{conversation_id}"), user_id).await
    }

    // ── Clé/valeur générique ──────────────────────────────────────────────

    /// `ttl` en secondes ; `None` ou 0 = sans expiration.
    pub async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> RedisResult<()> {
        match ttl.filter(|t| *t > 0) {
            Some(t) => self.c().set_ex(key, value, t).await,
            None => self.c().set(key, value).await,
        }
    }

    pub async fn get(&self, key: &str) -> RedisResult<Option<String>> {
        self.c().get(key).await
    }

    pub async fn del(&self, key: &str) -> RedisResult<()> {
        self.c().del(key).await
    }

    /// Supprime les clés d'un motif avec SCAN — jamais KEYS, qui bloquerait ce Redis partagé.
    pub async fn delete_by_pattern(&self, pattern: &str, batch: usize) -> RedisResult<u64> {
        let mut c = self.c();
        let mut cursor: u64 = 0;
        let mut deleted = 0u64;
        loop {
            let (next, keys): (u64, Vec<String>) =
                redis::cmd("SCAN").arg(cursor).arg("MATCH").arg(pattern).arg("COUNT").arg(batch).query_async(&mut c).await?;
            cursor = next;
            if !keys.is_empty() {
                let n = keys.len() as u64;
                let _: () = c.del(keys).await?;
                deleted += n;
            }
            if cursor == 0 {
                break;
            }
        }
        Ok(deleted)
    }

    /// Compte les clés d'un motif avec SCAN (remplace `KEYS` pour les statistiques).
    pub async fn count_by_pattern(&self, pattern: &str, batch: usize) -> RedisResult<Vec<String>> {
        let mut c = self.c();
        let mut cursor: u64 = 0;
        let mut out = Vec::new();
        loop {
            let (next, keys): (u64, Vec<String>) =
                redis::cmd("SCAN").arg(cursor).arg("MATCH").arg(pattern).arg("COUNT").arg(batch).query_async(&mut c).await?;
            cursor = next;
            out.extend(keys);
            if cursor == 0 {
                break;
            }
        }
        Ok(out)
    }

    // ── Rooms de l'utilisateur (reconnexion) ──────────────────────────────

    pub async fn save_user_rooms(&self, user_id: &str, server_ids: &[String], channel_ids: &[String]) -> RedisResult<()> {
        let v = json!({ "serverIds": server_ids, "channelIds": channel_ids });
        self.c().set_ex(format!("rooms:{user_id}"), v.to_string(), 7 * 24 * 3600).await
    }

    pub async fn get_user_rooms(&self, user_id: &str) -> RedisResult<Option<UserRooms>> {
        let raw: Option<String> = self.c().get(format!("rooms:{user_id}")).await?;
        let Some(v) = raw.and_then(|r| serde_json::from_str::<Value>(&r).ok()) else { return Ok(None) };
        let list = |k: &str| -> Vec<String> {
            v.get(k)
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        Ok(Some(UserRooms { server_ids: list("serverIds"), channel_ids: list("channelIds") }))
    }

    // ── Bannissement d'IP ─────────────────────────────────────────────────

    pub async fn ban_ip(&self, ip: &str, reason: &str, banned_by: &str) -> RedisResult<()> {
        let data = json!({
            "reason": reason,
            "bannedBy": banned_by,
            "bannedAt": crate::iso::to_string(&chrono::Utc::now()),
        });
        self.c().hset("banned:ips", ip, data.to_string()).await
    }

    pub async fn unban_ip(&self, ip: &str) -> RedisResult<()> {
        self.c().hdel("banned:ips", ip).await
    }

    pub async fn is_ip_banned(&self, ip: &str) -> RedisResult<bool> {
        self.c().hexists("banned:ips", ip).await
    }

    pub async fn get_banned_ips(&self) -> RedisResult<Vec<BannedIp>> {
        let all: HashMap<String, String> = self.c().hgetall("banned:ips").await?;
        let mut out = Vec::with_capacity(all.len());
        for (ip, data) in all {
            let parsed: Value = serde_json::from_str(&data).unwrap_or(Value::Null);
            out.push(BannedIp {
                ip,
                reason: parsed.get("reason").cloned().unwrap_or(Value::Null),
                banned_by: parsed.get("bannedBy").cloned().unwrap_or(Value::Null),
                banned_at: parsed.get("bannedAt").cloned().unwrap_or(Value::Null),
            });
        }
        Ok(out)
    }

    // ── Statistiques de limitation ────────────────────────────────────────

    pub async fn increment_rate_limit_with_key(&self, key: &str, window_seconds: i64) -> RedisResult<i64> {
        let mut c = self.c();
        let count: i64 = c.incr(key, 1).await?;
        if count == 1 {
            let _: () = c.expire(key, window_seconds).await?;
        }
        Ok(count)
    }

    pub async fn increment_rate_limit(&self, ip: &str, window: i64) -> RedisResult<i64> {
        self.increment_rate_limit_with_key(&format!("ratelimit:{ip}"), window).await
    }

    pub async fn get_rate_limit_count(&self, ip: &str) -> RedisResult<i64> {
        let v: Option<String> = self.c().get(format!("ratelimit:{ip}")).await?;
        Ok(v.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    /// `(totalBlocked, activeWindows)` — SCAN au lieu de KEYS.
    pub async fn get_rate_limit_stats(&self) -> RedisResult<(i64, usize)> {
        let blocked: Option<String> = self.c().get("ratelimit:total_blocked").await?;
        let keys = self.count_by_pattern("ratelimit:*", 200).await?;
        let active = keys.iter().filter(|k| k.as_str() != "ratelimit:total_blocked").count();
        Ok((blocked.and_then(|s| s.parse().ok()).unwrap_or(0), active))
    }

    pub async fn increment_rate_limit_blocked(&self) -> RedisResult<()> {
        self.c().incr("ratelimit:total_blocked", 1).await
    }

    // ── Pings MP en attente ───────────────────────────────────────────────

    pub async fn add_pending_ping(&self, user_id: &str, conversation_id: &str, sender_name: &str) -> RedisResult<()> {
        let key = format!("pending_pings:{user_id}");
        let meta = format!("pending_pings_meta:{user_id}");
        let mut c = self.c();
        let _: () = c.hincr(&key, conversation_id, 1).await?;
        let _: () = c.hset(&meta, conversation_id, sender_name).await?;
        let _: () = c.expire(&key, 30 * 24 * 60 * 60).await?;
        let _: () = c.expire(&meta, 30 * 24 * 60 * 60).await?;
        Ok(())
    }

    pub async fn get_pending_pings(&self, user_id: &str) -> RedisResult<indexmap::IndexMap<String, PendingPing>> {
        let mut c = self.c();
        let counts: HashMap<String, String> = c.hgetall(format!("pending_pings:{user_id}")).await?;
        let meta: HashMap<String, String> = c.hgetall(format!("pending_pings_meta:{user_id}")).await?;
        let mut out = indexmap::IndexMap::new();
        for (conv, count) in counts {
            let sender_name = meta.get(&conv).cloned().unwrap_or_default();
            out.insert(conv, PendingPing { count: count.parse().unwrap_or(0), sender_name });
        }
        Ok(out)
    }

    pub async fn clear_pending_pings(&self, user_id: &str) -> RedisResult<()> {
        let mut c = self.c();
        let _: () = c.del(format!("pending_pings:{user_id}")).await?;
        let _: () = c.del(format!("pending_pings_meta:{user_id}")).await?;
        Ok(())
    }

    // ── Détection d'anomalies ─────────────────────────────────────────────

    pub async fn anomaly_incr_req(&self, key: &str, window_secs: i64) -> RedisResult<i64> {
        self.increment_rate_limit_with_key(key, window_secs).await
    }

    /// Ajoute un endpoint distinct à un SET (TTL posé à la première insertion) et renvoie le nombre d'endpoints distincts.
    pub async fn anomaly_add_endpoint(&self, key: &str, endpoint: &str, window_secs: i64) -> RedisResult<i64> {
        let mut c = self.c();
        let added: i64 = c.sadd(key, endpoint).await?;
        if added == 1 {
            let ttl: i64 = c.ttl(key).await?;
            if ttl == -1 {
                let _: () = c.expire(key, window_secs).await?;
            }
        }
        c.scard(key).await
    }

    pub async fn publish(&self, channel: &str, message: &Value) -> RedisResult<()> {
        self.c().publish(channel, message.to_string()).await
    }
}
