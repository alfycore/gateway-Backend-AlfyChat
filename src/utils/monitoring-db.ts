// ==========================================
// ALFYCHAT - MONITORING DATABASE MODULE
// Persists service health & user stats in MySQL
// ==========================================

import mysql from 'mysql2/promise';
import { logger } from './logger';

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
      logger.error('MonitoringDB: erreur d\'initialisation', err);
    }
  }

  private async createTables(): Promise<void> {
    const conn = await this.pool!.getConnection();
    try {
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
      logger.error('MonitoringDB: erreur saveServiceSnapshot', err);
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
      logger.error('MonitoringDB: erreur saveUserStats', err);
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
  async getUserStatsAggregated(period: 'hour' | 'day' | 'month'): Promise<{ label: string; avg: number; max: number; min: number }[]> {
    if (!this.ready || !this.pool) return [];
    const conn = await this.pool.getConnection();
    try {
      let query: string;
      let params: any[];

      if (period === 'hour') {
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
      logger.error('MonitoringDB: erreur prune', err);
    } finally {
      conn.release();
    }
  }

  isReady(): boolean {
    return this.ready;
  }
}

export const monitoringDB = new MonitoringDB();
