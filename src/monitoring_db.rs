//! Persistance de la supervision (santé des services, utilisateurs connectés, incidents, registre des instances).
//! Équivalent de `utils/monitoring-db.ts` : mêmes tables, mêmes migrations, mêmes formes JSON.

use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{MySqlPool, Row};
use tracing::{error, info};

use crate::iso;

pub struct MonitoringDb {
    pool: parking_lot::RwLock<Option<MySqlPool>>,
}

pub struct ServiceSnapshot {
    pub service: String,
    pub status: &'static str,
    pub response_time_ms: Option<i64>,
    pub status_code: Option<i64>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

pub struct InstanceRow {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
    pub domain: String,
    pub location: String,
    pub enabled: bool,
    pub service_key_hash: Option<String>,
}

pub struct GatewayRow {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

/// Champs optionnels d'un incident (`None` = non modifié).
#[derive(Default)]
pub struct IncidentPatch {
    pub title: Option<String>,
    pub message: Option<Option<String>>,
    pub severity: Option<String>,
    pub services: Option<Vec<String>>,
    pub status: Option<String>,
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string())
}

/// DATETIME → chaîne ISO (mysql2 renvoie un `Date`, sérialisé en ISO UTC).
fn dt(row: &sqlx::mysql::MySqlRow, col: &str) -> Value {
    match row.try_get::<Option<chrono::NaiveDateTime>, _>(col) {
        Ok(Some(d)) => json!(iso::to_string(&d.and_utc())),
        _ => Value::Null,
    }
}

fn opt_str(row: &sqlx::mysql::MySqlRow, col: &str) -> Value {
    match row.try_get::<Option<String>, _>(col) {
        Ok(Some(s)) => json!(s),
        _ => Value::Null,
    }
}

fn opt_int(row: &sqlx::mysql::MySqlRow, col: &str) -> Value {
    match row.try_get::<Option<i64>, _>(col).or_else(|_| row.try_get::<Option<i32>, _>(col).map(|o| o.map(i64::from))) {
        Ok(Some(n)) => json!(n),
        _ => Value::Null,
    }
}

impl MonitoringDb {
    pub fn new() -> Self {
        Self { pool: parking_lot::RwLock::new(None) }
    }

    fn pool(&self) -> Option<MySqlPool> {
        self.pool.read().clone()
    }

    pub fn is_ready(&self) -> bool {
        self.pool.read().is_some()
    }

    pub async fn init(&self) {
        let opts = MySqlConnectOptions::new()
            .host(&env("DB_HOST", "localhost"))
            .port(env("DB_PORT", "3306").parse().unwrap_or(3306))
            .username(&env("DB_USER", "root"))
            .password(&std::env::var("DB_PASSWORD").unwrap_or_default())
            .database(&env("DB_NAME", "alfyv2"));
        let pool = match MySqlPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(opts)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                error!("MonitoringDB: erreur d'initialisation : {e}");
                return;
            }
        };
        match self.create_tables(&pool).await {
            Ok(()) => {
                *self.pool.write() = Some(pool);
                info!("MonitoringDB: connecté et tables prêtes");
            }
            Err(e) => error!("MonitoringDB: erreur d'initialisation : {e}"),
        }
    }

    async fn migration_done(pool: &MySqlPool, id: &str) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query("SELECT id FROM gateway_migrations WHERE id = ?").bind(id).fetch_optional(pool).await?.is_some())
    }

    async fn column_exists(pool: &MySqlPool, table: &str, col: &str) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query("SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?")
            .bind(table)
            .bind(col)
            .fetch_optional(pool)
            .await?
            .is_some())
    }

    async fn create_tables(&self, pool: &MySqlPool) -> Result<(), sqlx::Error> {
        // Instances de services (registre du répartiteur de charge, persistant)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS service_instances (
               id           VARCHAR(128) NOT NULL PRIMARY KEY,
               service_type VARCHAR(32)  NOT NULL,
               endpoint     VARCHAR(512) NOT NULL,
               domain       VARCHAR(256) NOT NULL,
               location     VARCHAR(32)  NOT NULL DEFAULT 'EU',
               enabled      TINYINT(1)   NOT NULL DEFAULT 1,
               created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
               updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
               INDEX idx_service_type (service_type)
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS gateway_migrations (
               id         VARCHAR(64) NOT NULL PRIMARY KEY,
               applied_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;

        // m001 : colonne enabled
        if !Self::migration_done(pool, "m001-enabled-column").await? {
            if !Self::column_exists(pool, "service_instances", "enabled").await? {
                sqlx::query("ALTER TABLE service_instances ADD COLUMN enabled TINYINT(1) NOT NULL DEFAULT 1").execute(pool).await?;
            }
            sqlx::query("INSERT IGNORE INTO gateway_migrations (id) VALUES ('m001-enabled-column')").execute(pool).await?;
        }

        // m003 : service_key_hash (clé unique par service)
        if !Self::migration_done(pool, "m003-service-key-hash").await? {
            if !Self::column_exists(pool, "service_instances", "service_key_hash").await? {
                sqlx::query("ALTER TABLE service_instances ADD COLUMN service_key_hash VARCHAR(64) NULL").execute(pool).await?;
            }
            sqlx::query("INSERT IGNORE INTO gateway_migrations (id) VALUES ('m003-service-key-hash')").execute(pool).await?;
            info!("MonitoringDB: migration m003 — colonne service_key_hash ajoutée");
        }

        // m002 : remise à zéro — purge les IP/localhost et réinitialise avec les domaines officiels
        if !Self::migration_done(pool, "m002-domain-only-reset").await? {
            sqlx::query("DELETE FROM service_instances").execute(pool).await?;
            sqlx::query(
                "INSERT INTO service_instances (id, service_type, endpoint, domain, location) VALUES
                   ('users-default',    'users',    'https://users.alfychat.eu',              'users.alfychat.eu',              'EU'),
                   ('users-eu-1',       'users',    'https://1.users.alfychat.eu',            '1.users.alfychat.eu',            'EU'),
                   ('messages-default', 'messages', 'https://messages.alfychat.eu',           'messages.alfychat.eu',           'EU'),
                   ('messages-eu-1',    'messages', 'https://1.messages.alfychat.eu',         '1.messages.alfychat.eu',         'EU'),
                   ('friends-default',  'friends',  'https://friends.s.backend.alfychat.app', 'friends.s.backend.alfychat.app', 'EU'),
                   ('calls-default',    'calls',    'https://calls.s.backend.alfychat.app',   'calls.s.backend.alfychat.app',   'EU'),
                   ('servers-default',  'servers',  'https://servers.s.backend.alfychat.app', 'servers.s.backend.alfychat.app', 'EU'),
                   ('bots-default',     'bots',     'https://bots.s.backend.alfychat.app',    'bots.s.backend.alfychat.app',    'EU'),
                   ('media-default',    'media',    'https://media.s.backend.alfychat.app',   'media.s.backend.alfychat.app',   'EU')",
            )
            .execute(pool)
            .await?;
            sqlx::query("INSERT IGNORE INTO gateway_migrations (id) VALUES ('m002-domain-only-reset')").execute(pool).await?;
            info!("MonitoringDB: migration m002 — table service_instances réinitialisée avec les domaines officiels");
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS service_monitoring (
               id         INT AUTO_INCREMENT PRIMARY KEY,
               service    VARCHAR(64)  NOT NULL,
               status     VARCHAR(16)  NOT NULL,
               response_time_ms INT,
               status_code INT,
               checked_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
               INDEX idx_service_time (service, checked_at)
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_stats (
               id              INT AUTO_INCREMENT PRIMARY KEY,
               connected_users INT NOT NULL DEFAULT 0,
               recorded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
               INDEX idx_recorded_at (recorded_at)
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS status_incidents (
               id          INT AUTO_INCREMENT PRIMARY KEY,
               title       VARCHAR(255) NOT NULL,
               message     TEXT,
               severity    ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
               services    VARCHAR(500) DEFAULT NULL,
               status      ENUM('investigating','identified','monitoring','resolved') NOT NULL DEFAULT 'investigating',
               created_by  VARCHAR(64),
               created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
               updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
               resolved_at DATETIME DEFAULT NULL,
               INDEX idx_status (status),
               INDEX idx_created_at (created_at)
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;

        // Instances de gateway (multi-gateway)
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lb_gateways (
               id           VARCHAR(64)  NOT NULL PRIMARY KEY,
               name         VARCHAR(128) NOT NULL,
               url          VARCHAR(512) NOT NULL,
               enabled      TINYINT(1)   NOT NULL DEFAULT 1,
               created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
               updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
             ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .execute(pool)
        .await?;

        // m004 : gateway_id sur service_instances
        if !Self::migration_done(pool, "m004-gateway-id").await? {
            if !Self::column_exists(pool, "service_instances", "gateway_id").await? {
                sqlx::query("ALTER TABLE service_instances ADD COLUMN gateway_id VARCHAR(64) NULL").execute(pool).await?;
            }
            sqlx::query("INSERT IGNORE INTO gateway_migrations (id) VALUES ('m004-gateway-id')").execute(pool).await?;
            info!("MonitoringDB: migration m004 — colonne gateway_id ajoutée");
        }

        // m005 : instances « talos » + correction des anciens domaines *.s.backend.*
        if !Self::migration_done(pool, "m005-talos-add").await? {
            sqlx::query(
                "INSERT IGNORE INTO service_instances (id, service_type, endpoint, domain, location) VALUES
                   ('users-talos',    'users',    'https://talos.users.alfychat.eu',    'talos.users.alfychat.eu',    'EU'),
                   ('messages-talos', 'messages', 'https://talos.messages.alfychat.eu', 'talos.messages.alfychat.eu', 'EU'),
                   ('friends-talos',  'friends',  'https://talos.friends.alfychat.eu',  'talos.friends.alfychat.eu',  'EU'),
                   ('calls-talos',    'calls',    'https://talos.calls.alfychat.eu',    'talos.calls.alfychat.eu',    'EU'),
                   ('servers-talos',  'servers',  'https://talos.servers.alfychat.eu',  'talos.servers.alfychat.eu',  'EU'),
                   ('bots-talos',     'bots',     'https://talos.bots.alfychat.eu',     'talos.bots.alfychat.eu',     'EU'),
                   ('media-talos',    'media',    'https://talos.media.alfychat.eu',    'talos.media.alfychat.eu',    'EU')",
            )
            .execute(pool)
            .await?;
            for svc in ["users", "messages", "friends", "calls", "servers", "bots", "media"] {
                sqlx::query(&format!(
                    "UPDATE service_instances SET endpoint='https://1.{svc}.alfychat.eu', domain='1.{svc}.alfychat.eu' WHERE id='{svc}-default' AND endpoint LIKE '%.s.backend.%'"
                ))
                .execute(pool)
                .await?;
            }
            sqlx::query("INSERT IGNORE INTO gateway_migrations (id) VALUES ('m005-talos-add')").execute(pool).await?;
            info!("MonitoringDB: migration m005 — instances talos ajoutées, endpoints *.s.backend.* corrigés vers 1.*");
        }
        Ok(())
    }

    // ── Instantanés ───────────────────────────────────────────────────────

    pub async fn save_service_snapshot(&self, snapshots: &[ServiceSnapshot]) {
        let Some(pool) = self.pool() else { return };
        for s in snapshots {
            let r = sqlx::query("INSERT INTO service_monitoring (service, status, response_time_ms, status_code, checked_at) VALUES (?, ?, ?, ?, ?)")
                .bind(&s.service)
                .bind(s.status)
                .bind(s.response_time_ms)
                .bind(s.status_code)
                .bind(s.checked_at.naive_utc())
                .execute(&pool)
                .await;
            if let Err(e) = r {
                error!("MonitoringDB: erreur saveServiceSnapshot : {e}");
                return;
            }
        }
    }

    pub async fn save_user_stats(&self, connected_users: i64) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query("INSERT INTO user_stats (connected_users, recorded_at) VALUES (?, NOW())").bind(connected_users).execute(&pool).await {
            error!("MonitoringDB: erreur saveUserStats : {e}");
        }
    }

    fn service_row(r: &sqlx::mysql::MySqlRow) -> Value {
        json!({
            "id": opt_int(r, "id"),
            "service": opt_str(r, "service"),
            "status": opt_str(r, "status"),
            "response_time_ms": opt_int(r, "response_time_ms"),
            "status_code": opt_int(r, "status_code"),
            "checked_at": dt(r, "checked_at"),
        })
    }

    /// Dernier statut de chaque service.
    pub async fn get_latest_service_status(&self) -> Result<Vec<Value>, sqlx::Error> {
        let Some(pool) = self.pool() else { return Ok(vec![]) };
        let rows = sqlx::query(
            "SELECT sm.*
             FROM service_monitoring sm
             INNER JOIN (
               SELECT service, MAX(checked_at) AS max_time
               FROM service_monitoring
               GROUP BY service
             ) latest ON sm.service = latest.service AND sm.checked_at = latest.max_time
             ORDER BY sm.service",
        )
        .fetch_all(&pool)
        .await?;
        Ok(rows.iter().map(Self::service_row).collect())
    }

    pub async fn get_service_history(&self, service: &str, hours: i64) -> Result<Vec<Value>, sqlx::Error> {
        let Some(pool) = self.pool() else { return Ok(vec![]) };
        let rows = sqlx::query(
            "SELECT * FROM service_monitoring
             WHERE service = ? AND checked_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
             ORDER BY checked_at ASC",
        )
        .bind(service)
        .bind(hours)
        .fetch_all(&pool)
        .await?;
        Ok(rows.iter().map(Self::service_row).collect())
    }

    pub async fn get_user_stats_history(&self, hours: i64) -> Result<Vec<Value>, sqlx::Error> {
        let Some(pool) = self.pool() else { return Ok(vec![]) };
        let rows = sqlx::query("SELECT * FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? HOUR) ORDER BY recorded_at ASC")
            .bind(hours)
            .fetch_all(&pool)
            .await?;
        Ok(rows
            .iter()
            .map(|r| json!({ "id": opt_int(r, "id"), "connected_users": opt_int(r, "connected_users"), "recorded_at": dt(r, "recorded_at") }))
            .collect())
    }

    pub async fn get_peak_users(&self, hours: i64) -> Result<i64, sqlx::Error> {
        let Some(pool) = self.pool() else { return Ok(0) };
        let row = sqlx::query("SELECT CAST(MAX(connected_users) AS SIGNED) AS peak FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)")
            .bind(hours)
            .fetch_one(&pool)
            .await?;
        Ok(row.try_get::<Option<i64>, _>("peak")?.unwrap_or(0))
    }

    /// Statistiques agrégées par période (30min | 10min | hour | day | month).
    pub async fn get_user_stats_aggregated(&self, period: &str) -> Result<Vec<Value>, sqlx::Error> {
        let Some(pool) = self.pool() else { return Ok(vec![]) };
        let query = match period {
            "30min" => {
                "SELECT DATE_FORMAT(recorded_at, '%Y-%m-%d %H:%i') AS label,
                        CAST(connected_users AS SIGNED) AS avg, CAST(connected_users AS SIGNED) AS max, CAST(connected_users AS SIGNED) AS min
                 FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 30 MINUTE) ORDER BY recorded_at ASC"
            }
            "10min" => {
                "SELECT DATE_FORMAT(DATE_SUB(recorded_at, INTERVAL MOD(MINUTE(recorded_at), 10) MINUTE), '%Y-%m-%d %H:%i') AS label,
                        CAST(ROUND(AVG(connected_users)) AS SIGNED) AS avg, CAST(MAX(connected_users) AS SIGNED) AS max, CAST(MIN(connected_users) AS SIGNED) AS min
                 FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 6 HOUR) GROUP BY label ORDER BY label ASC"
            }
            "hour" => {
                "SELECT DATE_FORMAT(recorded_at, '%Y-%m-%d %H:00') AS label,
                        CAST(ROUND(AVG(connected_users)) AS SIGNED) AS avg, CAST(MAX(connected_users) AS SIGNED) AS max, CAST(MIN(connected_users) AS SIGNED) AS min
                 FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                 GROUP BY DATE_FORMAT(recorded_at, '%Y-%m-%d %H:00') ORDER BY label ASC"
            }
            "day" => {
                "SELECT DATE_FORMAT(recorded_at, '%Y-%m-%d') AS label,
                        CAST(ROUND(AVG(connected_users)) AS SIGNED) AS avg, CAST(MAX(connected_users) AS SIGNED) AS max, CAST(MIN(connected_users) AS SIGNED) AS min
                 FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                 GROUP BY DATE_FORMAT(recorded_at, '%Y-%m-%d') ORDER BY label ASC"
            }
            _ => {
                "SELECT DATE_FORMAT(recorded_at, '%Y-%m') AS label,
                        CAST(ROUND(AVG(connected_users)) AS SIGNED) AS avg, CAST(MAX(connected_users) AS SIGNED) AS max, CAST(MIN(connected_users) AS SIGNED) AS min
                 FROM user_stats WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
                 GROUP BY DATE_FORMAT(recorded_at, '%Y-%m') ORDER BY label ASC"
            }
        };
        let rows = sqlx::query(query).fetch_all(&pool).await?;
        Ok(rows
            .iter()
            .map(|r| {
                json!({
                    "label": r.try_get::<String, _>("label").unwrap_or_default(),
                    "avg": r.try_get::<Option<i64>, _>("avg").ok().flatten().unwrap_or(0),
                    "max": r.try_get::<Option<i64>, _>("max").ok().flatten().unwrap_or(0),
                    "min": r.try_get::<Option<i64>, _>("min").ok().flatten().unwrap_or(0),
                })
            })
            .collect())
    }

    /// Supprime les données plus anciennes que `days` jours.
    pub async fn prune(&self, days: i64) {
        let Some(pool) = self.pool() else { return };
        let a = sqlx::query("DELETE FROM service_monitoring WHERE checked_at < DATE_SUB(NOW(), INTERVAL ? DAY)").bind(days).execute(&pool).await;
        let b = sqlx::query("DELETE FROM user_stats WHERE recorded_at < DATE_SUB(NOW(), INTERVAL ? DAY)").bind(days).execute(&pool).await;
        if let Some(e) = a.err().or(b.err()) {
            error!("MonitoringDB: erreur prune : {e}");
        }
    }

    // ── Incidents ─────────────────────────────────────────────────────────

    pub async fn get_incidents(&self, include_resolved: bool) -> Vec<Value> {
        let Some(pool) = self.pool() else { return vec![] };
        let sql = if include_resolved {
            "SELECT * FROM status_incidents ORDER BY created_at DESC LIMIT 100"
        } else {
            "SELECT * FROM status_incidents WHERE status != 'resolved' ORDER BY created_at DESC"
        };
        match sqlx::query(sql).fetch_all(&pool).await {
            Ok(rows) => rows
                .iter()
                .map(|r| {
                    json!({
                        "id": opt_int(r, "id"),
                        "title": opt_str(r, "title"),
                        "message": opt_str(r, "message"),
                        "severity": opt_str(r, "severity"),
                        "services": opt_str(r, "services"),
                        "status": opt_str(r, "status"),
                        "created_by": opt_str(r, "created_by"),
                        "created_at": dt(r, "created_at"),
                        "updated_at": dt(r, "updated_at"),
                        "resolved_at": dt(r, "resolved_at"),
                    })
                })
                .collect(),
            Err(e) => {
                error!("MonitoringDB: erreur getIncidents : {e}");
                vec![]
            }
        }
    }

    pub async fn create_incident(
        &self,
        title: &str,
        message: Option<&str>,
        severity: &str,
        services: Option<&[String]>,
        status: Option<&str>,
        created_by: Option<&str>,
    ) -> Option<i64> {
        let pool = self.pool()?;
        let services_json = services.map(|s| serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
        match sqlx::query("INSERT INTO status_incidents (title, message, severity, services, status, created_by) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(title)
            .bind(message)
            .bind(severity)
            .bind(services_json)
            .bind(status.unwrap_or("investigating"))
            .bind(created_by)
            .execute(&pool)
            .await
        {
            Ok(r) => Some(r.last_insert_id() as i64),
            Err(e) => {
                error!("MonitoringDB: erreur createIncident : {e}");
                None
            }
        }
    }

    pub async fn update_incident(&self, id: i64, p: IncidentPatch) -> bool {
        let Some(pool) = self.pool() else { return false };
        let mut fields: Vec<&str> = vec![];
        if p.title.is_some() {
            fields.push("title = ?");
        }
        if p.message.is_some() {
            fields.push("message = ?");
        }
        if p.severity.is_some() {
            fields.push("severity = ?");
        }
        if p.services.is_some() {
            fields.push("services = ?");
        }
        if let Some(st) = &p.status {
            fields.push("status = ?");
            fields.push(if st == "resolved" { "resolved_at = NOW()" } else { "resolved_at = NULL" });
        }
        if fields.is_empty() {
            return true;
        }
        let sql = format!("UPDATE status_incidents SET {} WHERE id = ?", fields.join(", "));
        let mut q = sqlx::query(&sql);
        if let Some(t) = &p.title {
            q = q.bind(t);
        }
        if let Some(m) = &p.message {
            q = q.bind(m.as_deref());
        }
        if let Some(s) = &p.severity {
            q = q.bind(s);
        }
        if let Some(s) = &p.services {
            q = q.bind(serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
        }
        if let Some(s) = &p.status {
            q = q.bind(s);
        }
        match q.bind(id).execute(&pool).await {
            Ok(_) => true,
            Err(e) => {
                error!("MonitoringDB: erreur updateIncident : {e}");
                false
            }
        }
    }

    pub async fn delete_incident(&self, id: i64) -> bool {
        let Some(pool) = self.pool() else { return false };
        match sqlx::query("DELETE FROM status_incidents WHERE id = ?").bind(id).execute(&pool).await {
            Ok(_) => true,
            Err(e) => {
                error!("MonitoringDB: erreur deleteIncident : {e}");
                false
            }
        }
    }

    // ── Disponibilité quotidienne ─────────────────────────────────────────

    pub async fn get_service_uptime_daily(&self, service: &str, days: i64) -> Vec<Value> {
        let Some(pool) = self.pool() else { return vec![] };
        let res = sqlx::query(
            "SELECT CAST(DATE(checked_at) AS CHAR) AS date,
                    CAST(COUNT(*) AS SIGNED) AS total_checks,
                    CAST(SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END) AS SIGNED) AS down_checks,
                    CAST(ROUND(100.0 * SUM(CASE WHEN status != 'down' THEN 1 ELSE 0 END) / COUNT(*), 2) AS CHAR) AS uptime_pct
             FROM service_monitoring
             WHERE service = ? AND checked_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
             GROUP BY DATE(checked_at)
             ORDER BY DATE(checked_at) ASC",
        )
        .bind(service)
        .bind(days)
        .fetch_all(&pool)
        .await;
        match res {
            Ok(rows) => rows
                .iter()
                .map(|r| {
                    let pct: f64 = r.try_get::<Option<String>, _>("uptime_pct").ok().flatten().and_then(|s| s.parse().ok()).filter(|n: &f64| *n != 0.0).unwrap_or(100.0);
                    json!({
                        "date": r.try_get::<Option<String>, _>("date").ok().flatten().unwrap_or_default(),
                        "uptime_pct": pct,
                        "total_checks": r.try_get::<Option<i64>, _>("total_checks").ok().flatten().unwrap_or(0),
                        "down_checks": r.try_get::<Option<i64>, _>("down_checks").ok().flatten().unwrap_or(0),
                    })
                })
                .collect(),
            Err(e) => {
                error!("MonitoringDB: erreur getServiceUptimeDaily : {e}");
                vec![]
            }
        }
    }

    // ── Instances de services (registre persistant) ───────────────────────

    pub async fn load_service_instances(&self) -> Vec<InstanceRow> {
        let Some(pool) = self.pool() else { return vec![] };
        match sqlx::query(
            "SELECT id, service_type AS serviceType, endpoint, domain, location, enabled, service_key_hash AS serviceKeyHash
             FROM service_instances ORDER BY service_type, id",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(rows) => rows
                .iter()
                .map(|r| InstanceRow {
                    id: r.try_get("id").unwrap_or_default(),
                    service_type: r.try_get("serviceType").unwrap_or_default(),
                    endpoint: r.try_get("endpoint").unwrap_or_default(),
                    domain: r.try_get("domain").unwrap_or_default(),
                    location: r.try_get("location").unwrap_or_default(),
                    enabled: r.try_get::<Option<i8>, _>("enabled").ok().flatten().map(|n| n != 0).unwrap_or(true),
                    service_key_hash: r.try_get::<Option<String>, _>("serviceKeyHash").ok().flatten(),
                })
                .collect(),
            Err(e) => {
                error!("MonitoringDB: erreur loadServiceInstances : {e}");
                vec![]
            }
        }
    }

    /// Crée ou met à jour une instance (ne touche pas à `enabled` si la ligne existe).
    pub async fn upsert_service_instance(&self, id: &str, service_type: &str, endpoint: &str, domain: &str, location: &str) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query(
            "INSERT INTO service_instances (id, service_type, endpoint, domain, location, enabled)
             VALUES (?, ?, ?, ?, ?, 1)
             ON DUPLICATE KEY UPDATE
               service_type = VALUES(service_type),
               endpoint     = VALUES(endpoint),
               domain       = VALUES(domain),
               location     = VALUES(location),
               updated_at   = NOW()",
        )
        .bind(id)
        .bind(service_type)
        .bind(endpoint)
        .bind(domain)
        .bind(location.to_uppercase())
        .execute(&pool)
        .await
        {
            error!("MonitoringDB: erreur upsertServiceInstance : {e}");
        }
    }

    pub async fn update_service_endpoint(&self, id: &str, endpoint: &str) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query("UPDATE service_instances SET endpoint = ?, updated_at = NOW() WHERE id = ?").bind(endpoint).bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur updateServiceEndpoint : {e}");
        }
    }

    pub async fn set_instance_enabled(&self, id: &str, enabled: bool) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query("UPDATE service_instances SET enabled = ?, updated_at = NOW() WHERE id = ?").bind(enabled as i32).bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur setInstanceEnabled : {e}");
        }
    }

    pub async fn remove_service_instance(&self, id: &str) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query("DELETE FROM service_instances WHERE id = ?").bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur removeServiceInstance : {e}");
        }
    }

    /// Stocke le SHA-256 de la clé de service (jamais la clé brute).
    pub async fn store_service_key_hash(&self, id: &str, raw_key: &str) {
        let Some(pool) = self.pool() else { return };
        let hash = hex::encode(Sha256::digest(raw_key.as_bytes()));
        if let Err(e) = sqlx::query("UPDATE service_instances SET service_key_hash = ?, updated_at = NOW() WHERE id = ?").bind(hash).bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur storeServiceKeyHash : {e}");
        }
    }

    // ── Registre des gateways ─────────────────────────────────────────────

    pub async fn load_gateways(&self) -> Vec<GatewayRow> {
        let Some(pool) = self.pool() else { return vec![] };
        match sqlx::query("SELECT id, name, url, enabled FROM lb_gateways ORDER BY created_at ASC").fetch_all(&pool).await {
            Ok(rows) => rows
                .iter()
                .map(|r| GatewayRow {
                    id: r.try_get("id").unwrap_or_default(),
                    name: r.try_get("name").unwrap_or_default(),
                    url: r.try_get("url").unwrap_or_default(),
                    enabled: r.try_get::<Option<i8>, _>("enabled").ok().flatten().map(|n| n != 0).unwrap_or(false),
                })
                .collect(),
            Err(e) => {
                error!("MonitoringDB: erreur loadGateways : {e}");
                vec![]
            }
        }
    }

    pub async fn upsert_gateway(&self, id: &str, name: &str, url: &str, enabled: bool) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query(
            "INSERT INTO lb_gateways (id, name, url, enabled) VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE name = VALUES(name), url = VALUES(url), enabled = VALUES(enabled), updated_at = NOW()",
        )
        .bind(id)
        .bind(name)
        .bind(url)
        .bind(enabled as i32)
        .execute(&pool)
        .await
        {
            error!("MonitoringDB: erreur upsertGateway : {e}");
        }
    }

    pub async fn delete_gateway(&self, id: &str) {
        let Some(pool) = self.pool() else { return };
        if let Err(e) = sqlx::query("DELETE FROM lb_gateways WHERE id = ?").bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur deleteGateway : {e}");
        }
    }

    pub async fn patch_gateway(&self, id: &str, name: Option<&str>, url: Option<&str>, enabled: Option<bool>) {
        let Some(pool) = self.pool() else { return };
        let mut sets: Vec<&str> = vec![];
        if name.is_some() {
            sets.push("name = ?");
        }
        if url.is_some() {
            sets.push("url = ?");
        }
        if enabled.is_some() {
            sets.push("enabled = ?");
        }
        if sets.is_empty() {
            return;
        }
        let sql = format!("UPDATE lb_gateways SET {}, updated_at = NOW() WHERE id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        if let Some(n) = name {
            q = q.bind(n);
        }
        if let Some(u) = url {
            q = q.bind(u);
        }
        if let Some(e) = enabled {
            q = q.bind(e as i32);
        }
        if let Err(e) = q.bind(id).execute(&pool).await {
            error!("MonitoringDB: erreur patchGateway : {e}");
        }
    }
}
