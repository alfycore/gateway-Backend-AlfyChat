// ==========================================
// ALFYCHAT — Monitoring Cycle
// ==========================================

import { PORT } from '../config/env';
import { logger } from '../utils/logger';
import { monitoringDB } from '../utils/monitoring-db';
import { serviceRegistry } from '../utils/service-registry';
import { handleStatusTransition } from './kener-client';

export const MONITORED_SERVICES: { name: string; url: string }[] = [
  { name: 'website',  url: `${process.env.FRONTEND_URL         || 'https://alfychat.app'}` },
  { name: 'users',    url: `${process.env.USERS_SERVICE_URL    || 'http://localhost:3001'}/health` },
  { name: 'messages', url: `${process.env.MESSAGES_SERVICE_URL || 'http://localhost:3002'}/health` },
  { name: 'friends',  url: `${process.env.FRIENDS_SERVICE_URL  || 'http://localhost:3003'}/health` },
  { name: 'calls',    url: `${process.env.CALLS_SERVICE_URL    || 'http://localhost:3004'}/health` },
  { name: 'servers',  url: `${process.env.SERVERS_SERVICE_URL  || 'http://localhost:3005'}/health` },
  { name: 'bots',     url: `${process.env.BOTS_SERVICE_URL     || 'http://localhost:3006'}/health` },
  { name: 'media',    url: `${process.env.MEDIA_SERVICE_URL    || 'https://media.s.backend.alfychat.app'}/health` },
];

export const MONITORING_INTERVAL_MS = parseInt(process.env.MONITORING_INTERVAL || '60000');

type ServiceStatus = 'up' | 'degraded' | 'down';

// Persist state across hot-reloads via globalThis
const g = globalThis as any;
if (!g.__gw_prevStates) g.__gw_prevStates = {} as Record<string, ServiceStatus>;
const prevStates: Record<string, ServiceStatus> = g.__gw_prevStates;

function statusIcon(s: ServiceStatus): string {
  if (s === 'up')       return '✓';
  if (s === 'degraded') return '~';
  return '✗';
}

function formatMs(ms: number | null): string {
  if (ms === null) return 'timeout';
  return `${ms}ms`;
}

/**
 * Run one health-check cycle for all monitored services + poll /metrics on
 * registered instances, then persist snapshots to DB.
 */
export async function runMonitoringCycle(
  connectedClientsSize: number,
): Promise<void> {
  const now = new Date();

  // 1. Check each service health
  const snapshots = await Promise.all(
    MONITORED_SERVICES.map(async (svc) => {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        let resp: Response;
        try {
          resp = await fetch(svc.url, { signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }
        const ms = Date.now() - start;
        const status: ServiceStatus = resp!.ok ? 'up' : 'degraded';

        // ── Transition alerts ─────────────────────────────────────────────
        const prev = prevStates[svc.name];
        if (prev && prev !== status) {
          if (status === 'up') {
            logger.info(`[Monitoring] ✓ ${svc.name} RÉCUPÉRÉ (était ${prev}) — ${ms}ms`);
          } else {
            logger.warn(`[Monitoring] ${statusIcon(status)} ${svc.name} DÉGRADÉ (HTTP ${resp!.status}) — ${ms}ms`);
          }
          handleStatusTransition(svc.name, prev, status, `HTTP ${resp!.status} en ${ms}ms`);
        }
        prevStates[svc.name] = status;

        return { service: svc.name, status, responseTimeMs: ms, statusCode: resp!.status, checkedAt: now };
      } catch (err: any) {
        const reason = err?.name === 'AbortError' ? 'timeout (5s)' : String(err?.message ?? err);

        // ── Alert on first failure or transition to down ──────────────────
        const prev = prevStates[svc.name];
        if (prev !== 'down') {
          logger.error(`[Monitoring] ✗ ${svc.name} HORS LIGNE — ${reason}`);
          handleStatusTransition(svc.name, prev, 'down', reason);
        }
        prevStates[svc.name] = 'down';

        return { service: svc.name, status: 'down' as const, responseTimeMs: null, statusCode: null, checkedAt: now };
      }
    }),
  );

  // 2. Poll /metrics of each registered instance
  const registeredInstances = serviceRegistry.getAll();
  await Promise.all(
    registeredInstances.map(async (instance) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        let resp: Response;
        try {
          resp = await fetch(`${instance.endpoint}/metrics`, { signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }
        if (!resp!.ok) return;
        const data = await resp!.json() as any;
        if (typeof data.cpuUsage === 'number' && typeof data.ramUsage === 'number') {
          serviceRegistry.heartbeat(instance.id, {
            ramUsage: data.ramUsage ?? 0,
            ramMax: data.ramMax ?? 0,
            cpuUsage: data.cpuUsage ?? 0,
            cpuMax: data.cpuMax ?? 100,
            bandwidthUsage: data.bandwidthUsage ?? 0,
            requestCount20min: data.requestCount20min ?? 0,
            responseTimeMs: data.responseTimeMs,
          });
        }
      } catch {
        // heartbeat push takes over if /metrics is unreachable — not an alert
      }
    }),
  );

  // 3. Gateway itself
  const gwStart = Date.now();
  try {
    await fetch(`http://localhost:${PORT}/health`, { signal: AbortSignal.timeout(2000) });
  } catch { /* always up if we reach here */ }
  snapshots.push({
    service: 'gateway',
    status: 'up',
    responseTimeMs: Date.now() - gwStart,
    statusCode: 200,
    checkedAt: now,
  });

  // 4. Persist to DB
  await monitoringDB.saveServiceSnapshot(snapshots);
  await monitoringDB.saveUserStats(connectedClientsSize);

  // 5. Summary log — one clean line per cycle
  const up       = snapshots.filter(s => s.status === 'up');
  const degraded = snapshots.filter(s => s.status === 'degraded');
  const down     = snapshots.filter(s => s.status === 'down');

  const parts = snapshots
    .filter(s => s.service !== 'gateway')
    .map(s => `${statusIcon(s.status)} ${s.service}${s.responseTimeMs !== null ? ` ${s.responseTimeMs}ms` : ''}`)
    .join('  ');

  const summary = `[Monitoring] ${up.length}↑ ${degraded.length}~ ${down.length}↓  |  ${parts}  |  ${connectedClientsSize} users`;

  if (down.length > 0 || degraded.length > 0) {
    logger.warn(summary);
  } else {
    logger.info(summary);
  }
}
