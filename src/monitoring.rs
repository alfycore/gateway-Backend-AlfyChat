//! Cycle de supervision (sondes `/health`, métriques des instances, persistance) et client Kener v4
//! (équivalents de `monitoring/cycle.ts` et `monitoring/kener-client.ts`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::monitoring_db::ServiceSnapshot;
use crate::state::AppState;

// ── Kener ───────────────────────────────────────────────────────────────────

static KENER_URL: Lazy<String> =
    Lazy::new(|| std::env::var("KENER_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://status.alfychat.app".into()).trim_end_matches('/').to_string());
static KENER_TOKEN: Lazy<String> = Lazy::new(|| std::env::var("KENER_API_TOKEN").unwrap_or_default());
static ACTIVE_INCIDENTS: Lazy<Mutex<HashMap<String, i64>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static PREV_STATES: Lazy<Mutex<HashMap<String, &'static str>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn kener_tag(service: &str) -> Option<&'static str> {
    Some(match service {
        "gateway" => "eu",
        "website" => "ws",
        "users" => "su1",
        "messages" => "sm1",
        "friends" => "sf1",
        "calls" => "sc1",
        "servers" => "ss1",
        "bots" => "sb1",
        "media" => "media3to",
        _ => return None,
    })
}

async fn kener_fetch(http: &reqwest::Client, method: reqwest::Method, path: &str, body: Value) -> Result<Value, String> {
    let res = http
        .request(method, format!("{}{path}", *KENER_URL))
        .header("Authorization", format!("Bearer {}", *KENER_TOKEN))
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(8))
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status.as_u16(), text.chars().take(200).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn add_comment(http: &reqwest::Client, id: i64, state: &str, comment: &str) -> Result<(), String> {
    kener_fetch(
        http,
        reqwest::Method::POST,
        &format!("/api/v4/incidents/{id}/comments"),
        json!({ "comment": comment, "state": state, "timestamp": chrono::Utc::now().timestamp() }),
    )
    .await
    .map(|_| ())
    .map_err(|e| format!("Kener addIncidentComment {e}"))
}

/// Appelée à chaque transition de statut : ouvre un incident sur up→degraded/down, le résout au retour à up.
async fn handle_status_transition(http: reqwest::Client, service: String, prev: Option<&'static str>, next: &'static str, reason: Option<String>) {
    if KENER_TOKEN.is_empty() {
        return;
    }
    let Some(tag) = kener_tag(&service) else { return };
    let existing = ACTIVE_INCIDENTS.lock().get(&service).copied();
    let result: Result<(), String> = async {
        if (next == "down" || next == "degraded") && prev != Some(next) && existing.is_none() {
            let (impact, label) = if next == "down" { ("DOWN", "hors ligne") } else { ("DEGRADED", "dégradé") };
            let data = kener_fetch(
                &http,
                reqwest::Method::POST,
                "/api/v4/incidents",
                json!({
                    "title": format!("{service} {label}"),
                    "start_date_time": chrono::Utc::now().timestamp(),
                    "incident_type": "INCIDENT",
                    "monitors": [{ "monitor_tag": tag, "impact": impact }],
                }),
            )
            .await
            .map_err(|e| format!("Kener createIncident {e}"))?;
            let id = data.get("incident").and_then(|i| i.get("id")).and_then(|v| v.as_i64()).ok_or("incident sans id")?;
            ACTIVE_INCIDENTS.lock().insert(service.clone(), id);
            let comment = match &reason {
                Some(r) => format!("Détection automatique — {r}"),
                None => format!("Détection automatique du gateway : {service} est {label}."),
            };
            add_comment(&http, id, "INVESTIGATING", &comment).await?;
            warn!("[Kener] Incident #{id} ouvert pour {service} ({impact})");
            return Ok(());
        }
        if next == "down" && prev == Some("degraded") {
            if let Some(id) = existing {
                add_comment(&http, id, "IDENTIFIED", &format!("Aggravation : {service} est passé de dégradé à hors ligne.")).await?;
                return Ok(());
            }
        }
        if next == "up" {
            if let Some(id) = existing {
                add_comment(&http, id, "RESOLVED", &format!("Service rétabli : {service} répond à nouveau normalement.")).await?;
                kener_fetch(&http, reqwest::Method::PATCH, &format!("/api/v4/incidents/{id}"), json!({ "end_date_time": chrono::Utc::now().timestamp() }))
                    .await
                    .map_err(|e| format!("Kener setIncidentEnd {e}"))?;
                ACTIVE_INCIDENTS.lock().remove(&service);
                info!("[Kener] Incident #{id} résolu pour {service}");
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        // Les soucis Kener ne doivent jamais faire tomber le cycle de supervision.
        error!("[Kener] Échec traitement transition {service} {prev:?}→{next} : {e}");
    }
}

// ── Cycle ───────────────────────────────────────────────────────────────────

fn first_origin(list: Option<String>, fallback: &str) -> String {
    let l = list.filter(|s| !s.is_empty()).unwrap_or_else(|| fallback.to_string());
    let f = l.split(',').next().unwrap_or("").trim().to_string();
    if f.is_empty() {
        fallback.to_string()
    } else {
        f
    }
}

pub fn monitored_services() -> Vec<(&'static str, String)> {
    let e = |k: &str, d: &str| std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string());
    vec![
        ("website", first_origin(std::env::var("FRONTEND_URL").ok(), "https://alfychat.app")),
        ("site", e("SITE_URL", "https://alfychat.com")),
        ("links", format!("{}/health", e("LINKS_SERVICE_URL", "https://alfy.chat"))),
        ("users", format!("{}/health", e("USERS_SERVICE_URL", "http://localhost:3001"))),
        ("messages", format!("{}/health", e("MESSAGES_SERVICE_URL", "http://localhost:3002"))),
        ("friends", format!("{}/health", e("FRIENDS_SERVICE_URL", "http://localhost:3003"))),
        ("calls", format!("{}/health", e("CALLS_SERVICE_URL", "http://localhost:3004"))),
        ("servers", format!("{}/health", e("SERVERS_SERVICE_URL", "http://localhost:3005"))),
        ("bots", format!("{}/health", e("BOTS_SERVICE_URL", "http://localhost:3006"))),
        ("media", format!("{}/health", e("MEDIA_SERVICE_URL", "https://media.s.backend.alfychat.app"))),
        ("serverhosting", format!("{}/health", e("SERVERHOSTING_SERVICE_URL", "http://localhost:3008"))),
        ("subscriptions", format!("{}/health", e("SUBSCRIPTIONS_SERVICE_URL", "http://localhost:3009"))),
        ("media-server", format!("{}/health", e("MEDIA_SERVER_URL", "http://localhost:3010"))),
    ]
}

pub fn interval() -> Duration {
    Duration::from_millis(std::env::var("MONITORING_INTERVAL").ok().and_then(|v| v.parse().ok()).unwrap_or(60_000))
}

fn icon(s: &str) -> &'static str {
    match s {
        "up" => "✓",
        "degraded" => "~",
        _ => "✗",
    }
}

/// Un cycle de sondes sur tous les services supervisés, puis lecture de `/metrics` des instances enregistrées.
pub async fn run_cycle(app: &Arc<AppState>) {
    let now = chrono::Utc::now();
    let connected = app.clients_len() as i64;

    let mut snapshots: Vec<ServiceSnapshot> = futures::future::join_all(monitored_services().into_iter().map(|(name, url)| {
        let http = app.http.clone();
        async move {
            let start = Instant::now();
            match http.get(&url).timeout(Duration::from_secs(5)).send().await {
                Ok(resp) => {
                    let ms = start.elapsed().as_millis() as i64;
                    let code = resp.status().as_u16();
                    let status: &'static str = if resp.status().is_success() { "up" } else { "degraded" };
                    let prev = PREV_STATES.lock().get(name).copied();
                    if let Some(prev) = prev.filter(|p| *p != status) {
                        if status == "up" {
                            info!("[Monitoring] ✓ {name} RÉCUPÉRÉ (était {prev}) — {ms}ms");
                        } else {
                            warn!("[Monitoring] {} {name} DÉGRADÉ (HTTP {code}) — {ms}ms", icon(status));
                        }
                        tokio::spawn(handle_status_transition(http.clone(), name.to_string(), Some(prev), status, Some(format!("HTTP {code} en {ms}ms"))));
                    }
                    PREV_STATES.lock().insert(name.to_string(), status);
                    ServiceSnapshot { service: name.into(), status, response_time_ms: Some(ms), status_code: Some(code as i64), checked_at: now }
                }
                Err(e) => {
                    let reason = if e.is_timeout() { "timeout (5s)".to_string() } else { e.to_string() };
                    let prev = PREV_STATES.lock().get(name).copied();
                    if prev != Some("down") {
                        error!("[Monitoring] ✗ {name} HORS LIGNE — {reason}");
                        tokio::spawn(handle_status_transition(http.clone(), name.to_string(), prev, "down", Some(reason)));
                    }
                    PREV_STATES.lock().insert(name.to_string(), "down");
                    ServiceSnapshot { service: name.into(), status: "down", response_time_ms: None, status_code: None, checked_at: now }
                }
            }
        }
    }))
    .await;

    // Métriques des instances enregistrées
    futures::future::join_all(app.lb.get_all().into_iter().map(|inst| {
        let (http, lb) = (app.http.clone(), app.lb.clone());
        async move {
            let Ok(resp) = http.get(format!("{}/metrics", inst.endpoint)).timeout(Duration::from_secs(4)).send().await else { return };
            if !resp.status().is_success() {
                return;
            }
            let Ok(data) = resp.json::<Value>().await else { return };
            if data.get("cpuUsage").map(|v| v.is_number()).unwrap_or(false) && data.get("ramUsage").map(|v| v.is_number()).unwrap_or(false) {
                lb.heartbeat(&inst.id, crate::lb::registry::ServiceMetrics::from_value(&data));
            }
        }
    }))
    .await;

    // Le gateway lui-même
    let gw_start = Instant::now();
    let port = app.cfg.port;
    let _ = app.http.get(format!("http://localhost:{port}/health")).timeout(Duration::from_secs(2)).send().await;
    snapshots.push(ServiceSnapshot { service: "gateway".into(), status: "up", response_time_ms: Some(gw_start.elapsed().as_millis() as i64), status_code: Some(200), checked_at: now });

    app.monitoring.save_service_snapshot(&snapshots).await;
    app.monitoring.save_user_stats(connected).await;

    let count = |s: &str| snapshots.iter().filter(|x| x.status == s).count();
    let (up, degraded, down) = (count("up"), count("degraded"), count("down"));
    let parts = snapshots
        .iter()
        .filter(|s| s.service != "gateway")
        .map(|s| format!("{} {}{}", icon(s.status), s.service, s.response_time_ms.map(|m| format!(" {m}ms")).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("  ");
    let summary = format!("[Monitoring] {up}↑ {degraded}~ {down}↓  |  {parts}  |  {connected} users");
    if down > 0 || degraded > 0 {
        warn!("{summary}");
    } else {
        info!("{summary}");
    }
}
