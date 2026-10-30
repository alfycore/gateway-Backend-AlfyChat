//! Client des microservices (équivalent de `services/proxy.ts`) :
//! disjoncteur par hôte (sémantique opossum), retry des méthodes idempotentes, failover multi-instances.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use reqwest::Method;
use serde_json::{json, Map, Value};
use tracing::{error, info, warn};

use crate::lb::registry::LbRegistry;
use crate::perms::js_number;
use crate::security::encode_uri_component;

// ── Erreurs ─────────────────────────────────────────────────────────────────

/// Erreur d'appel à un service. `status` = `statusCode` de l'erreur JS (absent pour un échec réseau / disjoncteur).
#[derive(Debug, Clone)]
pub struct SvcErr {
    pub status: Option<u16>,
    pub message: String,
}

impl SvcErr {
    pub fn new(message: impl Into<String>) -> Self {
        Self { status: None, message: message.into() }
    }
    pub fn with_status(status: u16, message: impl Into<String>) -> Self {
        Self { status: Some(status), message: message.into() }
    }
    pub fn is_client_error(&self) -> bool {
        matches!(self.status, Some(s) if (400..500).contains(&s))
    }
}

impl std::fmt::Display for SvcErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type SvcRes = Result<Value, SvcErr>;

// ── Segments d'URL ──────────────────────────────────────────────────────────
// Les identifiants interpolés dans les URL internes viennent du client : tout passe par `seg()`
// (alphabet restreint, puis encodage) pour qu'un `../` ne puisse pas viser une autre route.

static SEGMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,128}$").unwrap());

pub fn seg(value: &str) -> Result<String, SvcErr> {
    if !SEGMENT_RE.is_match(value) {
        return Err(SvcErr::with_status(400, "INVALID_ID"));
    }
    Ok(encode_uri_component(value))
}

// ── Disjoncteur (opossum) ───────────────────────────────────────────────────

const BREAKER_TIMEOUT: Duration = Duration::from_millis(15_000);
const ERROR_THRESHOLD_PCT: f64 = 75.0;
const RESET_TIMEOUT: Duration = Duration::from_millis(10_000);
const VOLUME_THRESHOLD: usize = 10;
const ROLLING_WINDOW: Duration = Duration::from_millis(10_000);

enum BState {
    Closed,
    Open(Instant),
    HalfOpen,
}

struct Breaker {
    host: String,
    inner: Mutex<(BState, VecDeque<(Instant, bool)>)>,
}

impl Breaker {
    fn new(host: String) -> Self {
        Self { host, inner: Mutex::new((BState::Closed, VecDeque::new())) }
    }

    /// `false` = circuit ouvert (la requête est rejetée sans partir).
    fn allow(&self) -> bool {
        let mut g = self.inner.lock();
        if let BState::Open(since) = g.0 {
            if since.elapsed() >= RESET_TIMEOUT {
                g.0 = BState::HalfOpen;
                info!("Circuit HALF-OPEN: {}", self.host);
            } else {
                return false;
            }
        }
        true
    }

    fn record(&self, failure: bool) {
        let mut g = self.inner.lock();
        let now = Instant::now();
        g.1.push_back((now, failure));
        while g.1.front().map(|(t, _)| now.duration_since(*t) > ROLLING_WINDOW).unwrap_or(false) {
            g.1.pop_front();
        }
        match g.0 {
            BState::HalfOpen => {
                if failure {
                    g.0 = BState::Open(now);
                    warn!("Circuit OUVERT: {}", self.host);
                } else {
                    g.0 = BState::Closed;
                    g.1.clear();
                    info!("Circuit FERMÉ: {}", self.host);
                }
            }
            BState::Closed if failure => {
                let fires = g.1.len();
                if fires >= VOLUME_THRESHOLD {
                    let failures = g.1.iter().filter(|(_, f)| *f).count();
                    if failures as f64 / fires as f64 * 100.0 > ERROR_THRESHOLD_PCT {
                        g.0 = BState::Open(now);
                        warn!("Circuit OUVERT: {}", self.host);
                    }
                }
            }
            _ => {}
        }
    }
}

// ── Options de requête ──────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct Opts {
    pub method: Option<Method>,
    pub body: Option<Value>,
    pub headers: Vec<(&'static str, String)>,
    pub token: Option<String>,
    pub timeout: Option<Duration>,
}

impl Opts {
    pub fn get() -> Self {
        Self::default()
    }
    pub fn method(m: Method, body: Option<Value>) -> Self {
        Self { method: Some(m), body, ..Self::default() }
    }
    pub fn post(body: Value) -> Self {
        Self::method(Method::POST, Some(body))
    }
    pub fn patch(body: Value) -> Self {
        Self::method(Method::PATCH, Some(body))
    }
    pub fn delete() -> Self {
        Self::method(Method::DELETE, None)
    }
    pub fn header(mut self, k: &'static str, v: impl Into<String>) -> Self {
        self.headers.push((k, v.into()));
        self
    }
    pub fn user(self, user_id: &str) -> Self {
        self.header("x-user-id", user_id)
    }
    pub fn token(mut self, token: Option<&str>) -> Self {
        self.token = token.filter(|t| !t.is_empty()).map(str::to_string);
        self
    }
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }
}

/// Objet JSON en omettant les champs `None` (équivalent de `JSON.stringify` qui ignore `undefined`).
pub fn obj(fields: Vec<(&str, Option<Value>)>) -> Value {
    let mut m = Map::new();
    for (k, v) in fields {
        if let Some(v) = v {
            m.insert(k.to_string(), v);
        }
    }
    Value::Object(m)
}

// ── Résolution d'URL ────────────────────────────────────────────────────────

pub struct ServiceUrls {
    pub users: String,
    pub messages: String,
    pub friends: String,
    pub calls: String,
    pub servers: String,
    pub bots: String,
    pub media_server: String,
}

impl ServiceUrls {
    pub fn from_env() -> Self {
        let e = |k: &str, d: &str| std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string());
        Self {
            users: e("USERS_SERVICE_URL", "http://localhost:3001"),
            messages: e("MESSAGES_SERVICE_URL", "http://localhost:3002"),
            friends: e("FRIENDS_SERVICE_URL", "http://localhost:3003"),
            calls: e("CALLS_SERVICE_URL", "http://localhost:3004"),
            servers: e("SERVERS_SERVICE_URL", "http://localhost:3005"),
            bots: e("BOTS_SERVICE_URL", "http://localhost:3006"),
            media_server: e("MEDIA_SERVER_URL", "http://localhost:3010"),
        }
    }
}

// ── Client ──────────────────────────────────────────────────────────────────

static FIVE_XX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Breaker is open|503|502|500").unwrap());
const ALERT_THROTTLE_MS: i64 = 10 * 60 * 1000;

pub struct Services {
    http: reqwest::Client,
    lb: Arc<LbRegistry>,
    internal_secret: String,
    is_production: bool,
    admin_emails: Vec<String>,
    urls: ServiceUrls,
    breakers: Mutex<HashMap<String, Arc<Breaker>>>,
    alert_throttle: Mutex<HashMap<String, i64>>,
}

fn host_of(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => url.to_string(),
        },
        Err(_) => url.to_string(),
    }
}

impl Services {
    pub fn new(
        http: reqwest::Client,
        lb: Arc<LbRegistry>,
        internal_secret: String,
        is_production: bool,
        admin_emails: Vec<String>,
        urls: ServiceUrls,
    ) -> Self {
        Self {
            http,
            lb,
            internal_secret,
            is_production,
            admin_emails,
            urls,
            breakers: Mutex::new(HashMap::new()),
            alert_throttle: Mutex::new(HashMap::new()),
        }
    }

    fn breaker(&self, url: &str) -> Arc<Breaker> {
        let host = host_of(url);
        self.breakers.lock().entry(host.clone()).or_insert_with(|| Arc::new(Breaker::new(host))).clone()
    }

    /// En production, le LB est la seule source de vérité ; en dev, repli sur l'URL fournie.
    fn resolve(&self, service_type: &str, fallback: &str) -> String {
        if let Some(best) = self.lb.select_best(service_type) {
            return best.endpoint;
        }
        if self.is_production {
            String::new()
        } else {
            fallback.to_string()
        }
    }

    fn notify_admin_degraded(&self, id: &str, service_type: &str, endpoint: &str, domain: &str, reason: &str) {
        let now = crate::redis_client::now_ms();
        {
            let mut t = self.alert_throttle.lock();
            if now - t.get(id).copied().unwrap_or(0) < ALERT_THROTTLE_MS {
                return;
            }
            t.insert(id.to_string(), now);
        }
        let subject = format!("[AlfyChat] ⚠️ Service dégradé : {id}");
        let text = [
            format!("L'instance \"{id}\" ({service_type}) a retourné une erreur 5XX."),
            String::new(),
            format!("  Endpoint : {endpoint}"),
            format!("  Domaine  : {domain}"),
            format!("  Raison   : {reason}"),
            format!("  Heure    : {}", crate::iso::to_string(&chrono::Utc::now())),
            String::new(),
            "L'instance a été SUSPENDUE automatiquement et ne recevra plus de trafic.".into(),
            String::new(),
            "Pour la réactiver, un administrateur ou technicien doit confirmer via :".into(),
            format!("  PATCH /api/admin/services/{}/restore", encode_uri_component(id)),
            String::new(),
            "— AlfyChat Gateway".into(),
        ]
        .join("\n");
        let to = self.admin_emails.clone();
        tokio::spawn(async move { crate::mailer::send_mail(&to, &subject, &text).await });
    }

    /// Une requête brute : erreur sur statut non-2xx, sinon corps JSON.
    async fn do_request(&self, url: &str, o: &Opts) -> SvcRes {
        let method = o.method.clone().unwrap_or(Method::GET);
        let mut req = self.http.request(method, url).header("Content-Type", "application/json");
        if !self.internal_secret.is_empty() {
            req = req.header("X-Internal-Secret", &self.internal_secret);
        }
        if let Some(t) = &o.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        // Les en-têtes de l'appelant remplacent les valeurs par défaut.
        for (k, v) in &o.headers {
            req = req.header(*k, v);
        }
        if let Some(b) = &o.body {
            req = req.body(b.to_string());
        }
        if let Some(t) = o.timeout {
            req = req.timeout(t);
        }
        let resp = req.send().await.map_err(|e| SvcErr::new(describe_reqwest(&e)))?;
        let status = resp.status();
        let reason = status.canonical_reason().unwrap_or("").to_string();
        let bytes = resp.bytes().await.map_err(|e| SvcErr::new(describe_reqwest(&e)))?;
        if !status.is_success() {
            let detail = match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) => v.to_string(),
                Err(_) => reason,
            };
            return Err(SvcErr::with_status(status.as_u16(), format!("Service error: {} {}", status.as_u16(), detail)));
        }
        serde_json::from_slice::<Value>(&bytes).map_err(|_| SvcErr::new("Unexpected end of JSON input"))
    }

    /// Deux nouvelles tentatives (300 ms puis 600 ms), jamais sur un 4xx.
    async fn with_retry(&self, url: &str, o: &Opts) -> SvcRes {
        let mut delay = 300u64;
        let mut retries = 2;
        loop {
            match self.do_request(url, o).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if retries <= 0 || e.is_client_error() {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    retries -= 1;
                    delay *= 2;
                }
            }
        }
    }

    async fn try_fetch(&self, url: &str, o: &Opts, retryable: bool) -> SvcRes {
        let breaker = self.breaker(url);
        if !breaker.allow() {
            return Err(SvcErr::new("Breaker is open"));
        }
        let fut = async {
            if retryable {
                self.with_retry(url, o).await
            } else {
                self.do_request(url, o).await
            }
        };
        let res = match tokio::time::timeout(BREAKER_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(SvcErr::new("Timed out after 15000ms")),
        };
        // Un 4xx est une réponse normale du service (refus, conflit…), pas une panne.
        let failure = matches!(&res, Err(e) if !e.is_client_error());
        breaker.record(failure);
        res
    }

    /// Fetch avec bascule sur une autre instance saine du même type en cas de 5XX.
    pub async fn fetch_with_failover(&self, primary_url: &str, service_type: Option<&str>, o: Opts) -> SvcRes {
        let method = o.method.clone().unwrap_or(Method::GET);
        let retryable = matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE");

        let primary_err = match self.try_fetch(primary_url, &o, retryable).await {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        let is_5xx = |e: &SvcErr| e.status.map(|s| s >= 500).unwrap_or(false) || FIVE_XX_RE.is_match(&e.message);

        let Some(service_type) = service_type.filter(|_| is_5xx(&primary_err) && retryable) else {
            error!("Fetch error for {primary_url}: {}", primary_err.message);
            return Err(primary_err);
        };

        let primary_instance = self
            .lb
            .get_all()
            .into_iter()
            .filter(|i| i.service_type == service_type)
            .find(|i| primary_url.starts_with(&i.endpoint));
        if let Some(pi) = &primary_instance {
            self.lb.mark_degraded(&pi.id, &primary_err.message);
            self.notify_admin_degraded(&pi.id, &pi.service_type, &pi.endpoint, &pi.domain, &primary_err.message);
            warn!("[Failover] Instance primaire dégradée: {} — recherche d'un fallback…", pi.id);
        }

        let mut fallbacks: Vec<_> = self
            .lb
            .get_instances(service_type, false, false)
            .into_iter()
            .filter(|i| Some(&i.id) != primary_instance.as_ref().map(|p| &p.id) && !i.degraded)
            .collect();
        if fallbacks.is_empty() {
            error!("[Failover] Aucun fallback disponible pour {service_type}");
            return Err(primary_err);
        }
        fallbacks.sort_by(|a, b| {
            crate::lb::registry::compute_score(b)
                .partial_cmp(&crate::lb::registry::compute_score(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for fb in fallbacks {
            let base = primary_instance
                .as_ref()
                .map(|p| p.endpoint.clone())
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| primary_url.split('/').take(3).collect::<Vec<_>>().join("/"));
            let fallback_url = primary_url.replacen(&base, &fb.endpoint, 1);
            info!("[Failover] Bascule vers {} ({})", fb.id, fb.endpoint);
            match self.try_fetch(&fallback_url, &o, retryable).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if is_5xx(&e) {
                        self.lb.mark_degraded(&fb.id, &e.message);
                        self.notify_admin_degraded(&fb.id, &fb.service_type, &fb.endpoint, &fb.domain, &e.message);
                        warn!("[Failover] Fallback {} aussi dégradé, essai suivant…", fb.id);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        error!("[Failover] Tous les fallbacks épuisés pour {service_type}");
        Err(primary_err)
    }

    /// Appel sans failover (services absents du registre).
    pub async fn fetch(&self, url: &str, o: Opts) -> SvcRes {
        self.fetch_with_failover(url, None, o).await
    }

    // ── URL de base par service ───────────────────────────────────────────

    fn users_base(&self) -> String {
        self.resolve("users", &self.urls.users)
    }
    fn messages_base(&self) -> String {
        self.resolve("messages", &self.urls.messages)
    }
    fn friends_base(&self) -> String {
        self.resolve("friends", &self.urls.friends)
    }
    fn calls_base(&self) -> String {
        self.resolve("calls", &self.urls.calls)
    }
    fn servers_base(&self) -> String {
        self.resolve("servers", &self.urls.servers)
    }
    fn bots_base(&self) -> String {
        self.resolve("bots", &self.urls.bots)
    }
}

fn describe_reqwest(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "The operation was aborted due to timeout".into()
    } else if e.is_builder() {
        "Failed to parse URL".into()
    } else {
        format!("fetch failed: {e}")
    }
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

// ═══════════════════════════ USERS ═══════════════════════════

impl Services {
    pub async fn users_get_user(&self, user_id: &str) -> SvcRes {
        self.fetch(&format!("{}/users/{}", self.users_base(), seg(user_id)?), Opts::get()).await
    }

    /// Statut de modération global (ban / mute) — endpoint interne.
    pub async fn users_get_moderation_status(&self, user_id: &str) -> SvcRes {
        self.fetch(&format!("{}/internal/moderation/{}", self.users_base(), seg(user_id)?), Opts::get()).await
    }

    pub async fn users_update_status(&self, user_id: &str, status: &str, custom_status: Option<Option<&str>>, emoji: Option<Option<&str>>) -> SvcRes {
        let nullable = |o: Option<&str>| o.map(s).unwrap_or(Value::Null);
        let mut fields: Vec<(&str, Option<Value>)> = vec![("status", Some(s(status)))];
        if let Some(cs) = custom_status {
            fields.push(("customStatus", Some(nullable(cs))));
            fields.push(("text", Some(nullable(cs))));
        }
        if let Some(e) = emoji {
            fields.push(("emoji", Some(nullable(e))));
        }
        self.fetch(
            &format!("{}/users/{}/status", self.users_base(), seg(user_id)?),
            Opts::patch(obj(fields)).user(user_id),
        )
        .await
    }

    pub async fn users_update_last_seen(&self, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/users/{}/last-seen", self.users_base(), seg(user_id)?),
            Opts::method(Method::PATCH, None).user(user_id),
        )
        .await
    }

    pub async fn users_get_preferences(&self, user_id: &str) -> SvcRes {
        self.fetch(&format!("{}/users/{}/preferences", self.users_base(), seg(user_id)?), Opts::get().user(user_id)).await
    }

    pub async fn users_update_profile(&self, user_id: &str, data: Value) -> SvcRes {
        self.fetch(&format!("{}/users/{}", self.users_base(), seg(user_id)?), Opts::patch(data).user(user_id)).await
    }

    pub async fn users_change_username(&self, user_id: &str, new_username: &str, password: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/users/{}/change-username", self.users_base(), seg(user_id)?),
            Opts::post(json!({ "newUsername": new_username, "password": password })).token(token),
        )
        .await
    }

    /// Fire-and-forget : ne bloque jamais l'envoi du message.
    pub async fn users_send_push(&self, payload: Value) {
        let _ = self.fetch(&format!("{}/push/send", self.users_base()), Opts::post(payload)).await;
    }
}

// ═══════════════════════════ MESSAGES ═══════════════════════════

impl Services {
    pub async fn messages_get_conversations(&self, user_id: &str, token: Option<&str>) -> SvcRes {
        let base = self.messages_base();
        self.fetch_with_failover(
            &format!("{base}/conversations"),
            Some("messages"),
            Opts::get().user(user_id).token(token).timeout(Duration::from_secs(5)),
        )
        .await
    }

    pub async fn messages_is_participant(&self, conversation_id: &str, user_id: &str) -> bool {
        let (Ok(c), Ok(u)) = (seg(conversation_id), seg(user_id)) else { return false };
        match self.fetch(&format!("{}/conversations/{c}/participants/{u}/check", self.messages_base()), Opts::get()).await {
            Ok(v) => v.get("isParticipant") == Some(&Value::Bool(true)),
            Err(_) => false,
        }
    }

    pub async fn messages_create_message(&self, data: Value) -> SvcRes {
        let base = self.messages_base();
        self.fetch_with_failover(&format!("{base}/messages"), Some("messages"), Opts::post(data)).await
    }

    pub async fn messages_update_message(&self, message_id: &str, content: &str, user_id: &str, sender_content: Option<&str>, e2ee_type: Option<i64>) -> SvcRes {
        let base = self.messages_base();
        let body = obj(vec![
            ("content", Some(s(content))),
            ("senderContent", sender_content.map(s)),
            ("e2eeType", e2ee_type.map(|n| json!(n))),
        ]);
        self.fetch_with_failover(
            &format!("{base}/messages/{}", seg(message_id)?),
            Some("messages"),
            Opts::patch(body).user(user_id),
        )
        .await
    }

    pub async fn messages_delete_message(&self, message_id: &str, user_id: &str) -> SvcRes {
        let base = self.messages_base();
        self.fetch_with_failover(&format!("{base}/messages/{}", seg(message_id)?), Some("messages"), Opts::delete().user(user_id)).await
    }

    pub async fn messages_add_reaction(&self, message_id: &str, user_id: &str, emoji: &str) -> SvcRes {
        self.fetch(
            &format!("{}/messages/{}/reactions", self.messages_base(), seg(message_id)?),
            Opts::post(json!({ "emoji": emoji })).user(user_id),
        )
        .await
    }

    pub async fn messages_remove_reaction(&self, message_id: &str, user_id: &str, emoji: &str) -> SvcRes {
        self.fetch(
            &format!("{}/messages/{}/reactions/{}", self.messages_base(), seg(message_id)?, encode_uri_component(emoji)),
            Opts::delete().user(user_id),
        )
        .await
    }

    /// Le service messages attend `participantIds`, pas `participants`. `rest` : type, name, avatarUrl, isOpen…
    pub async fn messages_create_conversation(&self, mut rest: Map<String, Value>, participants: Value, created_by: &str) -> SvcRes {
        rest.remove("participants");
        rest.remove("createdBy");
        rest.insert("participantIds".into(), participants);
        self.fetch(
            &format!("{}/conversations", self.messages_base()),
            Opts::post(Value::Object(rest)).user(created_by),
        )
        .await
    }

    pub async fn messages_update_conversation(&self, conversation_id: &str, data: Value, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/conversations/{}", self.messages_base(), seg(conversation_id)?),
            Opts::patch(data).token(token),
        )
        .await
    }

    pub async fn messages_get_participants(&self, conversation_id: &str) -> SvcRes {
        self.fetch(&format!("{}/conversations/{}/participants", self.messages_base(), seg(conversation_id)?), Opts::get()).await
    }

    pub async fn messages_add_participant(&self, conversation_id: &str, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/conversations/{}/participants", self.messages_base(), seg(conversation_id)?),
            Opts::post(json!({ "userId": user_id })).token(token),
        )
        .await
    }

    pub async fn messages_remove_participant(&self, conversation_id: &str, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/conversations/{}/participants/{}", self.messages_base(), seg(conversation_id)?, seg(user_id)?),
            Opts::delete().token(token),
        )
        .await
    }

    pub async fn messages_leave_conversation(&self, conversation_id: &str, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/conversations/{}/leave", self.messages_base(), seg(conversation_id)?),
            Opts::method(Method::POST, None).token(token).user(user_id),
        )
        .await
    }

    pub async fn messages_delete_conversation(&self, conversation_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/conversations/{}", self.messages_base(), seg(conversation_id)?),
            Opts::delete().token(token),
        )
        .await
    }

    pub async fn messages_get_archive_status(&self, conversation_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(&format!("{}/archive/status/{}", self.messages_base(), seg(conversation_id)?), Opts::get().token(token)).await
    }

    pub async fn messages_get_archive_stats(&self, conversation_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(&format!("{}/archive/stats/{}", self.messages_base(), seg(conversation_id)?), Opts::get().token(token)).await
    }

    pub async fn messages_check_archive_quota(&self, conversation_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(&format!("{}/archive/quota/{}", self.messages_base(), seg(conversation_id)?), Opts::get().token(token)).await
    }

    pub async fn messages_confirm_archive(&self, conversation_id: &str, archive_log_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/archive/confirm", self.messages_base()),
            Opts::post(json!({ "conversationId": conversation_id, "archiveLogId": archive_log_id })).token(token),
        )
        .await
    }

    pub async fn messages_get_cached_archived_message(&self, message_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(&format!("{}/archive/message/{}", self.messages_base(), seg(message_id)?), Opts::get().token(token)).await
    }

    pub async fn messages_cache_archived_messages(&self, messages: Value) -> SvcRes {
        self.fetch(&format!("{}/archive/cache", self.messages_base()), Opts::post(json!({ "messages": messages }))).await
    }

    pub async fn messages_save_notification(
        &self,
        user_id: &str,
        conversation_id: &str,
        sender_name: &str,
        sender_id: Option<&str>,
        notification_type: Option<&str>,
        channel_name: Option<&str>,
    ) -> SvcRes {
        let body = obj(vec![
            ("userId", Some(s(user_id))),
            ("conversationId", Some(s(conversation_id))),
            ("senderName", Some(s(sender_name))),
            ("senderId", sender_id.map(s)),
            ("notificationType", notification_type.map(s)),
            ("channelName", channel_name.map(s)),
        ]);
        self.fetch(&format!("{}/notifications", self.messages_base()), Opts::post(body)).await
    }

    pub async fn messages_get_notifications(&self, token: Option<&str>) -> SvcRes {
        self.fetch(&format!("{}/notifications", self.messages_base()), Opts::get().token(token)).await
    }
}

// ═══════════════════════════ FRIENDS ═══════════════════════════

impl Services {
    /// Liste d'amis ; `[]` si le service est injoignable.
    pub async fn friends_get_friends(&self, user_id: &str) -> Value {
        match self.fetch(&format!("{}/friends", self.friends_base()), Opts::get().user(user_id)).await {
            Ok(v) => v,
            Err(_) => {
                warn!("Impossible de récupérer les amis pour {user_id}");
                json!([])
            }
        }
    }

    pub async fn friends_send_request(&self, from_user_id: &str, to_user_id: &str, message: Option<&str>) -> SvcRes {
        let body = obj(vec![("toUserId", Some(s(to_user_id))), ("message", message.map(s))]);
        self.fetch(&format!("{}/friends/requests", self.friends_base()), Opts::post(body).user(from_user_id)).await
    }

    pub async fn friends_accept_request(&self, request_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/friends/requests/{}/accept", self.friends_base(), seg(request_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn friends_decline_request(&self, request_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/friends/requests/{}/decline", self.friends_base(), seg(request_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn friends_remove_friend(&self, user_id: &str, friend_id: &str) -> SvcRes {
        self.fetch(&format!("{}/friends/{}", self.friends_base(), seg(friend_id)?), Opts::delete().user(user_id)).await
    }

    pub async fn friends_block_user(&self, user_id: &str, blocked: &str) -> SvcRes {
        self.fetch(
            &format!("{}/friends/{}/block", self.friends_base(), seg(blocked)?),
            Opts::method(Method::POST, None).user(user_id),
        )
        .await
    }

    pub async fn friends_unblock_user(&self, user_id: &str, blocked: &str) -> SvcRes {
        self.fetch(
            &format!("{}/friends/{}/unblock", self.friends_base(), seg(blocked)?),
            Opts::method(Method::POST, None).user(user_id),
        )
        .await
    }
}

// ═══════════════════════════ CALLS ═══════════════════════════

impl Services {
    pub async fn calls_initiate(&self, call_type: &str, initiator_id: &str, conversation_id: Option<&str>, channel_id: Option<&str>, recipient_id: Option<&str>) -> SvcRes {
        let mut participant_ids = vec![initiator_id.to_string()];
        if let Some(r) = recipient_id.filter(|r| !r.is_empty() && *r != initiator_id) {
            participant_ids.push(r.to_string());
        }
        let body = json!({
            "type": call_type,
            "initiatorId": initiator_id,
            "conversationId": conversation_id.filter(|c| !c.is_empty()),
            "channelId": channel_id.filter(|c| !c.is_empty()),
            "participantIds": participant_ids,
        });
        self.fetch(&format!("{}/calls", self.calls_base()), Opts::post(body).user(initiator_id)).await
    }

    pub async fn calls_join(&self, call_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/calls/{}/join", self.calls_base(), seg(call_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn calls_get(&self, call_id: &str) -> Option<Value> {
        let id = seg(call_id).ok()?;
        self.fetch(&format!("{}/calls/{id}", self.calls_base()), Opts::get()).await.ok()
    }

    pub async fn calls_reject(&self, call_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/calls/{}/reject", self.calls_base(), seg(call_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn calls_end(&self, call_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/calls/{}/end", self.calls_base(), seg(call_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn calls_leave(&self, call_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/calls/{}/leave", self.calls_base(), seg(call_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn calls_create_dm(&self, data: Value, initiator_id: &str) -> SvcRes {
        self.fetch(&format!("{}/calls/dm", self.calls_base()), Opts::post(data).user(initiator_id)).await
    }

    pub async fn calls_create_group(&self, data: Value, initiator_id: &str) -> SvcRes {
        self.fetch(&format!("{}/calls/group", self.calls_base()), Opts::post(data).user(initiator_id)).await
    }

    pub async fn calls_create_server(&self, data: Value, initiator_id: &str) -> SvcRes {
        self.fetch(&format!("{}/calls/server", self.calls_base()), Opts::post(data).user(initiator_id)).await
    }

    pub async fn calls_get_quality(&self, call_id: &str) -> SvcRes {
        self.fetch(&format!("{}/calls/{}/quality", self.calls_base(), seg(call_id)?), Opts::get()).await
    }

    /// Nombre maximal de participants d'un appel de serveur (1500 si le service ne répond pas).
    pub async fn calls_get_server_limit(&self, server_id: &str) -> Value {
        let Ok(id) = seg(server_id) else { return json!(1500) };
        match self.fetch(&format!("{}/calls/limits/{id}", self.calls_base()), Opts::get()).await {
            Ok(v) => v.get("maxParticipants").cloned().unwrap_or(Value::Null),
            Err(_) => json!(1500),
        }
    }
}

// ═══════════════════════════ MEDIA-SERVER (SFU) ═══════════════════════════

impl Services {
    /// Instance épinglée, pas « la moins chargée » : une salle n'existe que sur le SFU qui l'a créée.
    /// Sans instance déclarée au LB, l'URL .env reste utilisée (même en prod).
    fn media_server_base(&self) -> String {
        let mut inst = self.lb.get_instances("media-server", false, false);
        inst.sort_by(|a, b| a.id.to_lowercase().cmp(&b.id.to_lowercase()).then_with(|| a.id.cmp(&b.id)));
        inst.into_iter().next().map(|i| i.endpoint).filter(|e| !e.is_empty()).unwrap_or_else(|| self.urls.media_server.clone())
    }

    async fn ms_send(&self, method: Method, path: &str, body: Option<&Value>, timeout: Option<Duration>) -> Result<reqwest::Response, SvcErr> {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.media_server_base(), path))
            .header("Content-Type", "application/json")
            .header("x-internal-secret", &self.internal_secret);
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        req.send().await.map_err(|e| SvcErr::new(describe_reqwest(&e)))
    }

    async fn ms_post(&self, path: &str, body: Value) -> SvcRes {
        let res = self.ms_send(Method::POST, path, Some(&body), Some(Duration::from_secs(10))).await?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let detail = res.text().await.unwrap_or_default();
            return Err(SvcErr::new(format!("media-server {path}: {status} {detail}")));
        }
        res.json::<Value>().await.map_err(|_| SvcErr::new("Unexpected end of JSON input"))
    }

    async fn ms_get(&self, path: &str) -> SvcRes {
        let res = self.ms_send(Method::GET, path, None, None).await?;
        if !res.status().is_success() {
            return Err(SvcErr::new(format!("media-server GET {path}: {}", res.status().as_u16())));
        }
        res.json::<Value>().await.map_err(|_| SvcErr::new("Unexpected end of JSON input"))
    }

    pub async fn sfu_create_room(&self, call_id: &str, call_category: &str) -> SvcRes {
        self.ms_post("/internal/rooms", json!({ "callId": call_id, "callCategory": call_category })).await
    }

    pub async fn sfu_destroy_room(&self, call_id: &str) -> Result<(), SvcErr> {
        self.ms_send(Method::DELETE, &format!("/internal/rooms/{}", seg(call_id)?), None, None).await.map(|_| ())
    }

    pub async fn sfu_get_rtp_capabilities(&self, call_id: &str) -> SvcRes {
        self.ms_get(&format!("/internal/rooms/{}/capabilities", seg(call_id)?)).await
    }

    pub async fn sfu_create_transport(&self, call_id: &str, user_id: &str, direction: &str) -> SvcRes {
        self.ms_post(&format!("/internal/rooms/{}/transports", seg(call_id)?), json!({ "userId": user_id, "direction": direction })).await
    }

    pub async fn sfu_connect_transport(&self, call_id: &str, transport_id: &str, dtls: &Value, user_id: &str) -> SvcRes {
        self.ms_post(
            &format!("/internal/rooms/{}/connect", seg(call_id)?),
            json!({ "transportId": transport_id, "dtlsParameters": dtls, "userId": user_id }),
        )
        .await
    }

    pub async fn sfu_produce(&self, call_id: &str, transport_id: &str, kind: &str, rtp: &Value, user_id: &str, app_data: Option<&Value>) -> SvcRes {
        let body = obj(vec![
            ("transportId", Some(s(transport_id))),
            ("kind", Some(s(kind))),
            ("rtpParameters", Some(rtp.clone())),
            ("userId", Some(s(user_id))),
            ("appData", app_data.cloned()),
        ]);
        self.ms_post(&format!("/internal/rooms/{}/produce", seg(call_id)?), body).await
    }

    pub async fn sfu_consume(&self, call_id: &str, recv_transport_id: &str, producer_id: &str, rtp_caps: &Value, user_id: &str) -> SvcRes {
        self.ms_post(
            &format!("/internal/rooms/{}/consume", seg(call_id)?),
            json!({ "recvTransportId": recv_transport_id, "producerId": producer_id, "rtpCapabilities": rtp_caps, "userId": user_id }),
        )
        .await
    }

    pub async fn sfu_resume_consumer(&self, call_id: &str, consumer_id: &str, user_id: &str) -> SvcRes {
        self.ms_post(&format!("/internal/rooms/{}/resume", seg(call_id)?), json!({ "consumerId": consumer_id, "userId": user_id })).await
    }

    pub async fn sfu_close_producer(&self, call_id: &str, producer_id: &str, user_id: &str) -> SvcRes {
        self.ms_post(&format!("/internal/rooms/{}/close-producer", seg(call_id)?), json!({ "producerId": producer_id, "userId": user_id })).await
    }

    pub async fn sfu_get_room_stats(&self, call_id: &str) -> SvcRes {
        self.ms_get(&format!("/internal/rooms/{}/stats", seg(call_id)?)).await
    }

    pub async fn sfu_get_producers(&self, call_id: &str) -> SvcRes {
        self.ms_get(&format!("/internal/rooms/{}/producers", seg(call_id)?)).await
    }
}

// ═══════════════════════════ SERVERS ═══════════════════════════

impl Services {
    /// Le service servers ne lit QUE `x-user-id` sur un appel interne (le paramètre d'URL est ignoré).
    pub async fn servers_get_user_servers(&self, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers?userId={}", self.servers_base(), seg(user_id)?),
            Opts::get().token(token).user(user_id),
        )
        .await
    }

    pub async fn servers_get_server(&self, server_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}", self.servers_base(), seg(server_id)?), Opts::get()).await
    }

    pub async fn servers_get_channels(&self, server_id: &str, user_id: Option<&str>) -> SvcRes {
        let mut o = Opts::get();
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&format!("{}/servers/{}/channels", self.servers_base(), seg(server_id)?), o).await
    }

    pub async fn servers_join(&self, server_id: &str, user_id: &str, invite_code: Option<&str>) -> SvcRes {
        let body = obj(vec![("userId", Some(s(user_id))), ("inviteCode", invite_code.filter(|c| !c.is_empty()).map(s))]);
        self.fetch(&format!("{}/servers/{}/join", self.servers_base(), seg(server_id)?), Opts::post(body).user(user_id)).await
    }

    pub async fn servers_leave(&self, server_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/leave", self.servers_base(), seg(server_id)?),
            Opts::post(json!({ "userId": user_id })).user(user_id),
        )
        .await
    }

    pub async fn servers_register_host(&self, data: Value) -> SvcRes {
        self.fetch(&format!("{}/servers/register", self.servers_base()), Opts::post(data)).await
    }

    pub async fn servers_create(&self, data: Value) -> SvcRes {
        self.fetch(&format!("{}/servers", self.servers_base()), Opts::post(data)).await
    }

    /// `updates` doit être un objet JSON ; `userId` y est ajouté.
    pub async fn servers_update(&self, server_id: &str, updates: Value, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}", self.servers_base(), seg(server_id)?),
            Opts::patch(with_user(updates, user_id)).user(user_id).token(token),
        )
        .await
    }

    pub async fn servers_delete(&self, server_id: &str, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}", self.servers_base(), seg(server_id)?),
            Opts::method(Method::DELETE, Some(json!({ "userId": user_id }))).user(user_id).token(token),
        )
        .await
    }

    pub async fn servers_create_channel(&self, server_id: &str, data: Value, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels", self.servers_base(), seg(server_id)?),
            Opts::post(with_user(data, user_id)).user(user_id).token(token),
        )
        .await
    }

    pub async fn servers_update_channel(&self, server_id: &str, channel_id: &str, updates: Value, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::patch(with_user(updates, user_id)).user(user_id).token(token),
        )
        .await
    }

    /// Réorganisation par lot (glisser-déposer).
    pub async fn servers_reorder_channels(&self, server_id: &str, positions: &Value, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels", self.servers_base(), seg(server_id)?),
            Opts::patch(json!({ "positions": positions })).user(user_id),
        )
        .await
    }

    /// Règles AutoMod actives — `blocked` si le message doit être refusé.
    pub async fn servers_automod_check(&self, server_id: &str, content: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/automod/check", self.servers_base(), seg(server_id)?),
            Opts::post(json!({ "content": content, "userId": user_id })),
        )
        .await
    }

    pub async fn servers_get_channel_overrides(&self, server_id: &str, channel_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}/overrides", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::get(),
        )
        .await
    }

    pub async fn servers_set_channel_override(&self, server_id: &str, channel_id: &str, data: Value, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}/overrides", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::method(Method::PUT, Some(data)).user(user_id),
        )
        .await
    }

    pub async fn servers_delete_channel_override(&self, server_id: &str, channel_id: &str, target_type: &str, target_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!(
                "{}/servers/{}/channels/{}/overrides/{}/{}",
                self.servers_base(),
                seg(server_id)?,
                seg(channel_id)?,
                seg(target_type)?,
                seg(target_id)?
            ),
            Opts::delete().user(user_id),
        )
        .await
    }

    pub async fn servers_sync_channel_overrides(&self, server_id: &str, channel_id: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}/overrides/sync", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::post(json!({})).user(user_id),
        )
        .await
    }

    pub async fn servers_reorder_roles(&self, server_id: &str, positions: &Value, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/roles", self.servers_base(), seg(server_id)?),
            Opts::patch(json!({ "positions": positions })).user(user_id),
        )
        .await
    }

    pub async fn servers_delete_channel(&self, server_id: &str, channel_id: &str, user_id: &str, token: Option<&str>) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::method(Method::DELETE, Some(json!({ "userId": user_id }))).user(user_id).token(token),
        )
        .await
    }

    pub async fn servers_kick_member(&self, server_id: &str, member_id: &str, requester_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/members/{}/kick", self.servers_base(), seg(server_id)?, seg(member_id)?),
            Opts::post(json!({ "requesterId": requester_id })).user(requester_id),
        )
        .await
    }

    pub async fn servers_ban_member(&self, server_id: &str, member_id: &str, requester_id: &str, reason: Option<&str>) -> SvcRes {
        let body = obj(vec![("requesterId", Some(s(requester_id))), ("reason", reason.map(s))]);
        self.fetch(
            &format!("{}/servers/{}/members/{}/ban", self.servers_base(), seg(server_id)?, seg(member_id)?),
            Opts::post(body).user(requester_id),
        )
        .await
    }

    pub async fn servers_get_channel_messages(&self, server_id: &str, channel_id: &str, limit: &Value, before: Option<&str>, user_id: Option<&str>) -> SvcRes {
        let n = js_number(limit);
        let n = if n.is_nan() || n == 0.0 { 50.0 } else { n };
        let lim = n.max(1.0).min(100.0);
        let mut url = format!(
            "{}/servers/{}/channels/{}/messages?limit={}",
            self.servers_base(),
            seg(server_id)?,
            seg(channel_id)?,
            lim
        );
        if let Some(b) = before.filter(|b| !b.is_empty()) {
            url.push_str(&format!("&before={}", encode_uri_component(b)));
        }
        let mut o = Opts::get();
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&url, o).await
    }

    pub async fn servers_create_message(&self, server_id: &str, channel_id: &str, data: Value, sender_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/channels/{}/messages", self.servers_base(), seg(server_id)?, seg(channel_id)?),
            Opts::post(data).user(sender_id),
        )
        .await
    }

    pub async fn servers_edit_message(&self, server_id: &str, message_id: &str, content: &str, sender_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/messages/{}", self.servers_base(), seg(server_id)?, seg(message_id)?),
            Opts::patch(json!({ "content": content, "senderId": sender_id })).user(sender_id),
        )
        .await
    }

    pub async fn servers_delete_message(&self, server_id: &str, message_id: &str, sender_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/messages/{}", self.servers_base(), seg(server_id)?, seg(message_id)?),
            Opts::method(Method::DELETE, Some(json!({ "senderId": sender_id }))).user(sender_id),
        )
        .await
    }

    pub async fn servers_add_reaction(&self, server_id: &str, message_id: &str, user_id: &str, emoji: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/{}/messages/{}/reactions", self.servers_base(), seg(server_id)?, seg(message_id)?),
            Opts::post(json!({ "userId": user_id, "emoji": emoji })).user(user_id),
        )
        .await
    }

    pub async fn servers_remove_reaction(&self, server_id: &str, message_id: &str, user_id: &str, emoji: &str) -> SvcRes {
        self.fetch(
            &format!(
                "{}/servers/{}/messages/{}/reactions/{}",
                self.servers_base(),
                seg(server_id)?,
                seg(message_id)?,
                encode_uri_component(emoji)
            ),
            Opts::method(Method::DELETE, Some(json!({ "userId": user_id }))).user(user_id),
        )
        .await
    }

    pub async fn servers_get_members(&self, server_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}/members", self.servers_base(), seg(server_id)?), Opts::get()).await
    }

    pub async fn servers_update_member(&self, server_id: &str, member_id: &str, data: Value, actor_id: Option<&str>, token: Option<&str>) -> SvcRes {
        let mut o = Opts::patch(data).token(token);
        if let Some(a) = actor_id.filter(|a| !a.is_empty()) {
            o = o.user(a);
        }
        self.fetch(&format!("{}/servers/{}/members/{}", self.servers_base(), seg(server_id)?, seg(member_id)?), o).await
    }

    pub async fn servers_is_member(&self, server_id: &str, user_id: &str) -> Result<bool, SvcErr> {
        let v = self
            .fetch(&format!("{}/servers/{}/members/{}/check", self.servers_base(), seg(server_id)?, seg(user_id)?), Opts::get())
            .await?;
        Ok(v.get("isMember") == Some(&Value::Bool(true)))
    }

    /// Fiche minimale d'un membre (rôles, pseudo, date d'arrivée) — même route que `is_member`.
    pub async fn servers_get_member_record(&self, server_id: &str, user_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}/members/{}/check", self.servers_base(), seg(server_id)?, seg(user_id)?), Opts::get()).await
    }

    /// Permissions cumulées d'un membre — un entier, calculé côté SQL.
    pub async fn servers_get_member_permissions(&self, server_id: &str, user_id: &str, channel_id: Option<&str>) -> SvcRes {
        let q = channel_id.map(|c| format!("?channelId={}", encode_uri_component(c))).unwrap_or_default();
        self.fetch(
            &format!("{}/servers/{}/members/{}/permissions{q}", self.servers_base(), seg(server_id)?, seg(user_id)?),
            Opts::get(),
        )
        .await
    }

    pub async fn servers_get_roles(&self, server_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}/roles", self.servers_base(), seg(server_id)?), Opts::get()).await
    }

    pub async fn servers_create_role(&self, server_id: &str, data: Value, user_id: Option<&str>) -> SvcRes {
        let mut o = Opts::post(data);
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&format!("{}/servers/{}/roles", self.servers_base(), seg(server_id)?), o).await
    }

    pub async fn servers_update_role(&self, server_id: &str, role_id: &str, data: Value, user_id: Option<&str>) -> SvcRes {
        let mut o = Opts::patch(data);
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&format!("{}/servers/{}/roles/{}", self.servers_base(), seg(server_id)?, seg(role_id)?), o).await
    }

    pub async fn servers_delete_role(&self, server_id: &str, role_id: &str, user_id: Option<&str>) -> SvcRes {
        let mut o = Opts::delete();
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&format!("{}/servers/{}/roles/{}", self.servers_base(), seg(server_id)?, seg(role_id)?), o).await
    }

    pub async fn servers_create_invite(&self, server_id: &str, data: Value, creator_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}/invites", self.servers_base(), seg(server_id)?), Opts::post(data).user(creator_id)).await
    }

    pub async fn servers_delete_invite(&self, invite_id: &str, user_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/invites/{}", self.servers_base(), seg(invite_id)?), Opts::delete().user(user_id)).await
    }

    pub async fn servers_get_invites(&self, server_id: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/{}/invites", self.servers_base(), seg(server_id)?), Opts::get()).await
    }

    pub async fn servers_resolve_invite(&self, code: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/invite/{}", self.servers_base(), seg(code)?), Opts::get()).await
    }

    pub async fn servers_join_by_invite(&self, invite_code: &str, user_id: &str) -> SvcRes {
        self.fetch(
            &format!("{}/servers/join", self.servers_base()),
            Opts::post(json!({ "inviteCode": invite_code, "userId": user_id })),
        )
        .await
    }

    pub async fn servers_validate_node_token(&self, node_token: &str) -> SvcRes {
        self.fetch(&format!("{}/servers/nodes/validate", self.servers_base()), Opts::post(json!({ "nodeToken": node_token }))).await
    }

    pub async fn servers_register_node(&self, name: Option<&str>, owner_id: Option<&str>) -> SvcRes {
        let body = obj(vec![("name", name.map(s)), ("ownerId", owner_id.map(s))]);
        let mut o = Opts::post(body);
        if let Some(u) = owner_id.filter(|u| !u.is_empty()) {
            o = o.user(u);
        }
        self.fetch(&format!("{}/servers/nodes/register", self.servers_base()), o).await
    }
}

/// `{ ...updates, userId }` — `userId` écrase une éventuelle clé du même nom.
fn with_user(v: Value, user_id: &str) -> Value {
    let mut m = match v {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    m.insert("userId".into(), s(user_id));
    Value::Object(m)
}

// ═══════════════════════════ BOTS ═══════════════════════════

impl Services {
    pub async fn bots_get_bot(&self, bot_id: &str) -> SvcRes {
        self.fetch(&format!("{}/bots/{}", self.bots_base(), seg(bot_id)?), Opts::get()).await
    }

    pub async fn bots_validate_token(&self, token: &str) -> SvcRes {
        self.fetch(&format!("{}/bots/validate", self.bots_base()), Opts::post(json!({ "token": token }))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seg_validates() {
        assert_eq!(seg("abc-DEF_12").unwrap(), "abc-DEF_12");
        assert!(seg("../x").is_err());
        assert!(seg("").is_err());
        assert!(seg(&"a".repeat(129)).is_err());
        assert_eq!(seg("a/b").unwrap_err().status, Some(400));
    }

    #[test]
    fn breaker_opens_after_volume() {
        let b = Breaker::new("h".into());
        for _ in 0..9 {
            b.record(true);
            assert!(b.allow());
        }
        b.record(true);
        assert!(!b.allow());
    }

    #[test]
    fn breaker_ignores_low_volume() {
        let b = Breaker::new("h".into());
        for _ in 0..5 {
            b.record(true);
        }
        assert!(b.allow());
    }

    #[test]
    fn with_user_overrides() {
        assert_eq!(with_user(json!({"a":1,"userId":"x"}), "u"), json!({"a":1,"userId":"u"}));
        assert_eq!(with_user(Value::Null, "u"), json!({"userId":"u"}));
    }
}
