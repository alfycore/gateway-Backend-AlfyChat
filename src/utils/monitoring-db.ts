// ==========================================
// ALFYCHAT - MONITORING DATABASE MODULE
// Persists service health & user stats in MySQL
// ==========================================

import mysql from 'mysql2/promise';
import { createHash } from 'node:crypto';
import { logger } from './logger';

export type IncidentSeverity = 'info' | 'warning' | 'critical';
export type IncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved';

export interface Incident {
  id: number;
  title: string;
  message: string | null;
  severity: IncidentSeverity;
  services: string | null; // JSON array string
  status: IncidentStatus;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface ServiceUptimeDay {
  date: string;        // YYYY-MM-DD
  uptime_pct: number;  // 0–100
  total_checks: number;
  down_checks: number;
}

export interface ServiceSnapshot {
  service: string;
  status: 'up' | 'down' | 'degraded';
  responseTimeMs: number | null;
  statusCode: number | null;
  checkedAt: Date;
}

export interface UserStatsSnapshot {
  connectedUsers: number;
  recordedAt: Date;
}

export interface ServiceHistory {
  id: number;
  service: string;
  status: string;
  responseTimeMs: number | null;
  statusCode: number | null;
  checkedAt: string;
}

export interface UserStatsHistory {
  id: number;
  connectedUsers: number;
  recordedAt: string;
}

class MonitoringDB {
  private pool: mysql.Pool | null = null;
  private ready = false;

  async init(): Promise<void> {
    try {
      this.pool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '3306'),
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'alfyv2',
        connectionLimit: 5,
        connectTimeout: 10000,
      });

      await this.createTables();
      this.ready = true;
      logger.info('MonitoringDB: connecté et tables prêtes');
    } catch (err) {
      logger.error({ err }, 'MonitoringDB: erreur d\'initialisation');
    }
  }

  private async createTables(): Promise<void> {
    const conn = await this.pool!.getConnection();
    try {
      // ── Instances de services (load balancer registry persistant) ──────────
      await conn.execute(`
        CREATE TABLE IF NOT EXISTS service_instances (
          id           VARCHAR(128) NOT NULL PRIMARY KEY,
          service_type VARCHAR(32)  NOT NULL,
          endpoint     VARCHAR(512) NOT NULL,
          domain       VARCHAR(256) NOT NULL,
          location     VARCHAR(32)  NOT NULL DEFAULT 'EU',
          enabled      TINYINT(1)   NOT NULL DEFAULT 1,
          created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_service_type (service_type)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      `);
      // Table de migrations pour n'appliquer chaque migration qu'une seule fois
      await conn.execute(`
        CREATE TABLE IF NOT EXISTS gateway_migrations (
          id         VARCHAR(64) NOT NULL PRIMARY KEY,
          applied_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      // Migration m001 : ajouter la colonne enabled
      const [m001] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT id FROM gateway_migrations WHERE id = 'm001-enabled-column'`
      );
      if (!(m001 as any[]).length) {
        const [cols] = await conn.execute<mysql.RowDataPacket[]>(
          `SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'service_instances' AND COLUMN_NAME = 'enabled'`
        );
        if (!(cols as any[]).length) {
          await conn.execute(`ALTER TABLE service_instances ADD COLUMN enabled TINYINT(1) NOT NULL DEFAULT 1`);
        }
        await conn.execute(`INSERT IGNORE INTO gateway_migrations (id) VALUES ('m001-enabled-column')`);
      }

      // Migration m003 : ajouter la colonne service_key_hash (clé unique par service)
      const [m003] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT id FROM gateway_migrations WHERE id = 'm003-service-key-hash'`
      );
      if (!(m003 as any[]).length) {
        const [cols] = await conn.execute<mysql.RowDataPacket[]>(
          `SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'service_instances' AND COLUMN_NAME = 'service_key_hash'`
        );
        if (!(cols as any[]).length) {
          await conn.execute(`ALTER TABLE service_instances ADD COLUMN service_key_hash VARCHAR(64) NULL`);
        }
        await conn.execute(`INSERT IGNORE INTO gateway_migrations (id) VALUES ('m003-service-key-hash')`);
        logger.info('MonitoringDB: migration m003 — colonne service_key_hash ajoutée');
      }

      // Migration m002 : remise à zéro — purge les IPs/localhost et réinitialise avec les domaines officiels
      const [m002] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT id FROM gateway_migrations WHERE id = 'm002-domain-only-reset'`
      );
      if (!(m002 as any[]).length) {
        await conn.execute(`DELETE FROM service_instances`);
        await conn.execute(`
          INSERT INTO service_instances (id, service_type, endpoint, domain, location) VALUES
            ('users-default',    'users',    'https://users.alfychat.eu',              'users.alfychat.eu',              'EU'),
            ('users-eu-1',       'users',    'https://1.users.alfychat.eu',            '1.users.alfychat.eu',            'EU'),
            ('messages-default', 'messages', 'https://messages.alfychat.eu',           'messages.alfychat.eu',           'EU'),
            ('messages-eu-1',    'messages', 'https://1.messages.alfychat.eu',         '1.messages.alfychat.eu',         'EU'),
            ('friends-default',  'friends',  'https://friends.s.backend.alfychat.app', 'friends.s.backend.alfychat.app', 'EU'),
            ('calls-default',    'calls',    'https://calls.s.backend.alfychat.app',   'calls.s.backend.alfychat.app',   'EU'),
            ('servers-default',  'servers',  'https://servers.s.backend.alfychat.app', 'servers.s.backend.alfychat.app', 'EU'),
            ('bots-default',     'bots',     'https://bots.s.backend.alfychat.app',    'bots.s.backend.alfychat.app',    'EU'),
            ('media-default',    'media',    'https://media.s.backend.alfychat.app',   'media.s.backend.alfychat.app',   'EU')
        `);
        await conn.execute(`INSERT IGNORE INTO gateway_migrations (id) VALUES ('m002-domain-only-reset')`);
        logger.info('MonitoringDB: migration m002 — table service_instances réinitialisée avec les domaines officiels');
      }

      await conn.execute(`
        CREATE TABLE IF NOT EXISTS service_monitoring (
          id         INT AUTO_INCREMENT PRIMARY KEY,
          service    VARCHAR(64)  NOT NULL,
          status     VARCHAR(16)  NOT NULL,
          response_time_ms INT,
          status_code INT,
          checked_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_service_time (service, checked_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      `);

      await conn.execute(`
        CREATE TABLE IF NOT EXISTS user_stats (
          id              INT AUTO_INCREMENT PRIMARY KEY,
          connected_users INT NOT NULL DEFAULT 0,
          recorded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_recorded_at (recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      `);

      await conn.execute(`
        CREATE TABLE IF NOT EXISTS status_incidents (
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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      `);
    } finally {
      conn.release();
    }
  }

  async saveServiceSnapshot(snapshots: ServiceSnapshot[]): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      for (const s of snapshots) {
        await conn.execute(
          `INSERT INTO service_monitoring (service, status, response_time_ms, status_code, checked_at)
           VALUES (?, ?, ?, ?, ?)`,
          [s.service, s.status, s.responseTimeMs, s.statusCode, s.checkedAt],
        );
      }
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur saveServiceSnapshot');
    } finally {
      conn.release();
    }
  }

  async saveUserStats(connectedUsers: number): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `INSERT INTO user_stats (connected_users, recorded_at) VALUES (?, NOW())`,
        [connectedUsers],
      );
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur saveUserStats');
    } finally {
      conn.release();
    }
  }

  /** Returns latest status per service */
  async getLatestServiceStatus(): Promise<ServiceHistory[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(`
        SELECT sm.*
        FROM service_monitoring sm
        INNER JOIN (
          SELECT service, MAX(checked_at) AS max_time
          FROM service_monitoring
          GROUP BY service
        ) latest ON sm.service = latest.service AND sm.checked_at = latest.max_time
        ORDER BY sm.service;
      `);
      return rows as ServiceHistory[];
    } finally {
      conn.release();
    }
  }

  /** Returns service history for the last N hours (default 24) */
  async getServiceHistory(service: string, hours = 24): Promise<ServiceHistory[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT * FROM service_monitoring
         WHERE service = ? AND checked_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
         ORDER BY checked_at ASC`,
        [service, hours],
      );
      return rows as ServiceHistory[];
    } finally {
      conn.release();
    }
  }

  /** Returns user stats for the last N hours (default 24) */
  async getUserStatsHistory(hours = 24): Promise<UserStatsHistory[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT * FROM user_stats
         WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
         ORDER BY recorded_at ASC`,
        [hours],
      );
      return rows as UserStatsHistory[];
    } finally {
      conn.release();
    }
  }

  /** Peak connected users in the last N hours */
  async getPeakUsers(hours = 24): Promise<number> {
    if (!this.ready || !this.pool) return 0;
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT MAX(connected_users) AS peak FROM user_stats
         WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)`,
        [hours],
      );
      return rows[0]?.peak ?? 0;
    } finally {
      conn.release();
    }
  }

  /**
   * Aggregated user stats by period.
   * - 'hour'  → one point per hour, last 24 hours  (AVG connected_users per hour)
   * - 'day'   → one point per day,  last 30 days   (AVG connected_users per day)
   * - 'month' → one point per month, last 12 months (AVG connected_users per month)
   */
  async getUserStatsAggregated(period: '30min' | '10min' | 'hour' | 'day' | 'month'): Promise<{ label: string; avg: number; max: number; min: number }[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      let query: string;
      let params: any[];

      if (period === '30min') {
        // Last 30 minutes, raw rows (1-min granularity)
        query = `
          SELECT
            DATE_FORMAT(recorded_at, '%Y-%m-%d %H:%i') AS label,
            connected_users                             AS avg,
            connected_users                             AS max,
            connected_users                             AS min
          FROM user_stats
          WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)
          ORDER BY recorded_at ASC`;
        params = [];
      } else if (period === '10min') {
        // Last 6 hours, grouped by 10-minute buckets
        query = `
          SELECT
            DATE_FORMAT(
              DATE_SUB(recorded_at, INTERVAL MOD(MINUTE(recorded_at), 10) MINUTE),
              '%Y-%m-%d %H:%i'
            )                              AS label,
            ROUND(AVG(connected_users))    AS avg,
            MAX(connected_users)           AS max,
            MIN(connected_users)           AS min
          FROM user_stats
          WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 6 HOUR)
          GROUP BY label
          ORDER BY label ASC`;
        params = [];
      } else if (period === 'hour') {
        // Last 24 hours, grouped by hour
        query = `
          SELECT
            DATE_FORMAT(recorded_at, '%Y-%m-%d %H:00') AS label,
            ROUND(AVG(connected_users))                AS avg,
            MAX(connected_users)                       AS max,
            MIN(connected_users)                       AS min
          FROM user_stats
          WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
          GROUP BY DATE_FORMAT(recorded_at, '%Y-%m-%d %H:00')
          ORDER BY label ASC`;
        params = [];
      } else if (period === 'day') {
        // Last 30 days, grouped by calendar day
        query = `
          SELECT
            DATE_FORMAT(recorded_at, '%Y-%m-%d') AS label,
            ROUND(AVG(connected_users))           AS avg,
            MAX(connected_users)                  AS max,
            MIN(connected_users)                  AS min
          FROM user_stats
          WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
          GROUP BY DATE_FORMAT(recorded_at, '%Y-%m-%d')
          ORDER BY label ASC`;
        params = [];
      } else {
        // Last 12 months, grouped by month
        query = `
          SELECT
            DATE_FORMAT(recorded_at, '%Y-%m') AS label,
            ROUND(AVG(connected_users))        AS avg,
            MAX(connected_users)               AS max,
            MIN(connected_users)               AS min
          FROM user_stats
          WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
          GROUP BY DATE_FORMAT(recorded_at, '%Y-%m')
          ORDER BY label ASC`;
        params = [];
      }

      const [rows] = await conn.execute<mysql.RowDataPacket[]>(query, params);
      return (rows as any[]).map((r) => ({
        label: r.label,
        avg: Number(r.avg) || 0,
        max: Number(r.max) || 0,
        min: Number(r.min) || 0,
      }));
    } finally {
      conn.release();
    }
  }

  /** Prune old monitoring data (older than N days) */
  async prune(days = 30): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `DELETE FROM service_monitoring WHERE checked_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [days],
      );
      await conn.execute(
        `DELETE FROM user_stats WHERE recorded_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
        [days],
      );
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur prune');
    } finally {
      conn.release();
    }
  }

  // ── Incidents ────────────────────────────────────────────────────────────

  async getIncidents(includeResolved = false): Promise<Incident[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        includeResolved
          ? `SELECT * FROM status_incidents ORDER BY created_at DESC LIMIT 100`
          : `SELECT * FROM status_incidents WHERE status != 'resolved' ORDER BY created_at DESC`,
      );
      return rows as Incident[];
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur getIncidents');
      return [];
    } finally {
      conn.release();
    }
  }

  async createIncident(data: {
    title: string;
    message?: string;
    severity: IncidentSeverity;
    services?: string[];
    status?: IncidentStatus;
    createdBy?: string;
  }): Promise<number | null> {
    if (!this.ready || !this.pool) return null;
    const conn = await this.pool.getConnection();
    try {
      const [result] = await conn.execute<mysql.ResultSetHeader>(
        `INSERT INTO status_incidents (title, message, severity, services, status, created_by)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          data.title,
          data.message ?? null,
          data.severity,
          data.services ? JSON.stringify(data.services) : null,
          data.status ?? 'investigating',
          data.createdBy ?? null,
        ],
      );
      return result.insertId;
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur createIncident');
      return null;
    } finally {
      conn.release();
    }
  }

  async updateIncident(id: number, data: {
    title?: string;
    message?: string;
    severity?: IncidentSeverity;
    services?: string[];
    status?: IncidentStatus;
  }): Promise<boolean> {
    if (!this.ready || !this.pool) return false;
    const conn = await this.pool.getConnection();
    try {
      const fields: string[] = [];
      const values: any[] = [];
      if (data.title !== undefined)    { fields.push('title = ?');    values.push(data.title); }
      if (data.message !== undefined)  { fields.push('message = ?');  values.push(data.message); }
      if (data.severity !== undefined) { fields.push('severity = ?'); values.push(data.severity); }
      if (data.services !== undefined) { fields.push('services = ?'); values.push(JSON.stringify(data.services)); }
      if (data.status !== undefined) {
        fields.push('status = ?');
        values.push(data.status);
        if (data.status === 'resolved') fields.push('resolved_at = NOW()');
        else                            fields.push('resolved_at = NULL');
      }
      if (!fields.length) return true;
      values.push(id);
      await conn.execute(`UPDATE status_incidents SET ${fields.join(', ')} WHERE id = ?`, values);
      return true;
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur updateIncident');
      return false;
    } finally {
      conn.release();
    }
  }

  async deleteIncident(id: number): Promise<boolean> {
    if (!this.ready || !this.pool) return false;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(`DELETE FROM status_incidents WHERE id = ?`, [id]);
      return true;
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur deleteIncident');
      return false;
    } finally {
      conn.release();
    }
  }

  // ── Uptime history (daily buckets, last N days) ─────────────────────────

  async getServiceUptimeDaily(service: string, days = 90): Promise<ServiceUptimeDay[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT
           DATE(checked_at)                                         AS date,
           COUNT(*)                                                 AS total_checks,
           SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END)        AS down_checks,
           ROUND(100.0 * SUM(CASE WHEN status != 'down' THEN 1 ELSE 0 END) / COUNT(*), 2) AS uptime_pct
         FROM service_monitoring
         WHERE service = ? AND checked_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
         GROUP BY DATE(checked_at)
         ORDER BY date ASC`,
        [service, days],
      );
      return (rows as any[]).map((r) => ({
        date: r.date instanceof Date ? r.date.toISOString().slice(0, 10) : String(r.date),
        uptime_pct: Number(r.uptime_pct) || 100,
        total_checks: Number(r.total_checks) || 0,
        down_checks: Number(r.down_checks) || 0,
      }));
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur getServiceUptimeDaily');
      return [];
    } finally {
      conn.release();
    }
  }

  // ── Service instances (registry persistant) ─────────────────────────────

  /** Charge toutes les instances depuis la DB (y compris désactivées pour que l'admin les voie) */
  async loadServiceInstances(): Promise<{ id: string; serviceType: string; endpoint: string; domain: string; location: string; enabled: boolean; serviceKeyHash: string | null }[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT id, service_type AS serviceType, endpoint, domain, location, enabled, service_key_hash AS serviceKeyHash FROM service_instances ORDER BY service_type, id`,
      );
      return (rows as any[]).map(r => ({ ...r, enabled: Boolean(r.enabled ?? 1), serviceKeyHash: r.serviceKeyHash ?? null }));
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur loadServiceInstances');
      return [];
    } finally {
      conn.release();
    }
  }

  /** Vérifie si une instance est désactivée (bloque le ré-enregistrement automatique) */
  async isInstanceDisabled(id: string): Promise<boolean> {
    if (!this.ready || !this.pool) return false;
    const conn = await this.pool.getConnection();
    try {
      const [rows] = await conn.execute<mysql.RowDataPacket[]>(
        `SELECT enabled FROM service_instances WHERE id = ?`, [id],
      );
      if ((rows as any[]).length === 0) return false;
      return !Boolean((rows as any[])[0].enabled);
    } catch {
      return false;
    } finally {
      conn.release();
    }
  }

  /** Crée ou met à jour une instance (ne touche pas au champ enabled si la ligne existe déjà) */
  async upsertServiceInstance(data: { id: string; serviceType: string; endpoint: string; domain: string; location: string }): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `INSERT INTO service_instances (id, service_type, endpoint, domain, location, enabled)
         VALUES (?, ?, ?, ?, ?, 1)
         ON DUPLICATE KEY UPDATE
           service_type = VALUES(service_type),
           endpoint     = VALUES(endpoint),
           domain       = VALUES(domain),
           location     = VALUES(location),
           updated_at   = NOW()`,
        [data.id, data.serviceType, data.endpoint, data.domain, data.location.toUpperCase()],
      );
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur upsertServiceInstance');
    } finally {
      conn.release();
    }
  }

  /** Met à jour l'endpoint d'une instance (persiste en DB) */
  async updateServiceEndpoint(id: string, endpoint: string): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `UPDATE service_instances SET endpoint = ?, updated_at = NOW() WHERE id = ?`,
        [endpoint, id],
      );
    } catch (err) {
      logger.error({ err }, 'MonitoringDB: erreur updateServiceEndpoint');
    } finally {
      conn.release();
    }
  }

  /** Active ou désactive une instance (persiste l'état) */
  async setInstanceEnabled(id: string, enabled: boolean): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `UPDATE service_instances SET enabled = ?, updated_at = NOW() WHERE id = ?`,
        [enabled ? 1 : 0, id],
      );
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur setInstanceEnabled');
    } finally {
      conn.release();
    }
  }

  /** Supprime une instance définitivement */
  async removeServiceInstance(id: string): Promise<void> {
    if (!this.ready || !this.pool) return;
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(`DELETE FROM service_instances WHERE id = ?`, [id]);
    } catch (err) {
      logger.error({ err: err }, 'MonitoringDB: erreur removeServiceInstance');
    } finally {
      conn.release();
    }
  }

  /** Stocke le hash SHA-256 de la clé de service (ne stocke jamais la clé brute) */
  async storeServiceKeyHash(id: string, rawKey: string): Promise<void> {
    if (!this.ready || !this.pool) return;
    const hash = createHash('sha256').update(rawKey).digest('hex');
    const conn = await this.pool.getConnection();
    try {
      await conn.execute(
        `UPDATE service_instances SET service_key_hash = ?, updated_at = NOW() WHERE id = ?`,
        [hash, id],
      );
    } catch (err) {
      logger.error({ err }, 'MonitoringDB: erreur storeServiceKeyHash');
    } finally {
      conn.release();
    }
  }

  isReady(): boolean {
    return this.ready;
  }
}

export const monitoringDB = new MonitoringDB();
