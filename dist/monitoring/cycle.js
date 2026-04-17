"use strict";
// ==========================================
// ALFYCHAT — Monitoring Cycle
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.MONITORING_INTERVAL_MS = exports.MONITORED_SERVICES = void 0;
exports.runMonitoringCycle = runMonitoringCycle;
const env_1 = require("../config/env");
const logger_1 = require("../utils/logger");
const monitoring_db_1 = require("../utils/monitoring-db");
const service_registry_1 = require("../utils/service-registry");
exports.MONITORED_SERVICES = [
    { name: 'website', url: `${process.env.FRONTEND_URL || 'https://alfychat.app'}` },
    { name: 'users', url: `${process.env.USERS_SERVICE_URL || 'http://localhost:3001'}/health` },
    { name: 'messages', url: `${process.env.MESSAGES_SERVICE_URL || 'http://localhost:3002'}/health` },
    { name: 'friends', url: `${process.env.FRIENDS_SERVICE_URL || 'http://localhost:3003'}/health` },
    { name: 'calls', url: `${process.env.CALLS_SERVICE_URL || 'http://localhost:3004'}/health` },
    { name: 'servers', url: `${process.env.SERVERS_SERVICE_URL || 'http://localhost:3005'}/health` },
    { name: 'bots', url: `${process.env.BOTS_SERVICE_URL || 'http://localhost:3006'}/health` },
    { name: 'media', url: `${process.env.MEDIA_SERVICE_URL || 'https://media.s.backend.alfychat.app'}/health` },
];
exports.MONITORING_INTERVAL_MS = parseInt(process.env.MONITORING_INTERVAL || '60000');
// Persist state across hot-reloads via globalThis
const g = globalThis;
if (!g.__gw_prevStates)
    g.__gw_prevStates = {};
const prevStates = g.__gw_prevStates;
function statusIcon(s) {
    if (s === 'up')
        return '✓';
    if (s === 'degraded')
        return '~';
    return '✗';
}
function formatMs(ms) {
    if (ms === null)
        return 'timeout';
    return `${ms}ms`;
}
/**
 * Run one health-check cycle for all monitored services + poll /metrics on
 * registered instances, then persist snapshots to DB.
 */
async function runMonitoringCycle(connectedClientsSize) {
    const now = new Date();
    // 1. Check each service health
    const snapshots = await Promise.all(exports.MONITORED_SERVICES.map(async (svc) => {
        const start = Date.now();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            let resp;
            try {
                resp = await fetch(svc.url, { signal: controller.signal });
            }
            finally {
                clearTimeout(timeout);
            }
            const ms = Date.now() - start;
            const status = resp.ok ? 'up' : 'degraded';
            // ── Transition alerts ─────────────────────────────────────────────
            const prev = prevStates[svc.name];
            if (prev && prev !== status) {
                if (status === 'up') {
                    logger_1.logger.info(`[Monitoring] ✓ ${svc.name} RÉCUPÉRÉ (était ${prev}) — ${ms}ms`);
                }
                else {
                    logger_1.logger.warn(`[Monitoring] ${statusIcon(status)} ${svc.name} DÉGRADÉ (HTTP ${resp.status}) — ${ms}ms`);
                }
            }
            prevStates[svc.name] = status;
            return { service: svc.name, status, responseTimeMs: ms, statusCode: resp.status, checkedAt: now };
        }
        catch (err) {
            const reason = err?.name === 'AbortError' ? 'timeout (5s)' : String(err?.message ?? err);
            // ── Alert on first failure or transition to down ──────────────────
            const prev = prevStates[svc.name];
            if (prev !== 'down') {
                logger_1.logger.error(`[Monitoring] ✗ ${svc.name} HORS LIGNE — ${reason}`);
            }
            prevStates[svc.name] = 'down';
            return { service: svc.name, status: 'down', responseTimeMs: null, statusCode: null, checkedAt: now };
        }
    }));
    // 2. Poll /metrics of each registered instance
    const registeredInstances = service_registry_1.serviceRegistry.getAll();
    await Promise.all(registeredInstances.map(async (instance) => {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 4000);
            let resp;
            try {
                resp = await fetch(`${instance.endpoint}/metrics`, { signal: controller.signal });
            }
            finally {
                clearTimeout(timeout);
            }
            if (!resp.ok)
                return;
            const data = await resp.json();
            if (typeof data.cpuUsage === 'number' && typeof data.ramUsage === 'number') {
                service_registry_1.serviceRegistry.heartbeat(instance.id, {
                    ramUsage: data.ramUsage ?? 0,
                    ramMax: data.ramMax ?? 0,
                    cpuUsage: data.cpuUsage ?? 0,
                    cpuMax: data.cpuMax ?? 100,
                    bandwidthUsage: data.bandwidthUsage ?? 0,
                    requestCount20min: data.requestCount20min ?? 0,
                    responseTimeMs: data.responseTimeMs,
                });
            }
        }
        catch {
            // heartbeat push takes over if /metrics is unreachable — not an alert
        }
    }));
    // 3. Gateway itself
    const gwStart = Date.now();
    try {
        await fetch(`http://localhost:${env_1.PORT}/health`, { signal: AbortSignal.timeout(2000) });
    }
    catch { /* always up if we reach here */ }
    snapshots.push({
        service: 'gateway',
        status: 'up',
        responseTimeMs: Date.now() - gwStart,
        statusCode: 200,
        checkedAt: now,
    });
    // 4. Persist to DB
    await monitoring_db_1.monitoringDB.saveServiceSnapshot(snapshots);
    await monitoring_db_1.monitoringDB.saveUserStats(connectedClientsSize);
    // 5. Summary log — one clean line per cycle
    const up = snapshots.filter(s => s.status === 'up');
    const degraded = snapshots.filter(s => s.status === 'degraded');
    const down = snapshots.filter(s => s.status === 'down');
    const parts = snapshots
        .filter(s => s.service !== 'gateway')
        .map(s => `${statusIcon(s.status)} ${s.service}${s.responseTimeMs !== null ? ` ${s.responseTimeMs}ms` : ''}`)
        .join('  ');
    const summary = `[Monitoring] ${up.length}↑ ${degraded.length}~ ${down.length}↓  |  ${parts}  |  ${connectedClientsSize} users`;
    if (down.length > 0 || degraded.length > 0) {
        logger_1.logger.warn(summary);
    }
    else {
        logger_1.logger.info(summary);
    }
}
//# sourceMappingURL=cycle.js.map