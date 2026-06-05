"use strict";
// ==========================================
// ALFYCHAT — LB Registry v2
// Source de vérité unique pour services et clés
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.serviceRegistry = exports.lbRegistry = void 0;
exports.generateServiceKey = generateServiceKey;
exports.hashServiceKey = hashServiceKey;
const node_crypto_1 = require("node:crypto");
const logger_1 = require("../utils/logger");
const HEARTBEAT_TIMEOUT_MS = 90_000;
const CLEANUP_INTERVAL_MS = 30_000;
const DEFAULT_SCORE = 50;
const LOCAL_RE = /^https?:\/\/(localhost|127\.0\.0\.1)/;
const IP_RE = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
function generateServiceKey() {
    const rawKey = 'sk_' + (0, node_crypto_1.randomBytes)(32).toString('base64url');
    const hash = (0, node_crypto_1.createHash)('sha256').update(rawKey).digest('hex');
    return { rawKey, hash };
}
function hashServiceKey(key) {
    return (0, node_crypto_1.createHash)('sha256').update(key).digest('hex');
}
function emptyMetrics() {
    return { cpuUsage: 0, cpuMax: 100, ramUsage: 0, ramMax: 0, bandwidthUsage: 0, requestCount20min: 0 };
}
class LBRegistry {
    entries = new Map();
    keyIndex = new Map(); // keyHash → serviceId
    cleanupTimer;
    constructor() {
        this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
        if (this.cleanupTimer.unref)
            this.cleanupTimer.unref();
    }
    // ── Key management ─────────────────────────────────────────────────────────
    addKeyHash(serviceId, keyHash) {
        for (const [h, id] of this.keyIndex) {
            if (id === serviceId) {
                this.keyIndex.delete(h);
                break;
            }
        }
        this.keyIndex.set(keyHash, serviceId);
    }
    removeKey(serviceId) {
        for (const [h, id] of this.keyIndex) {
            if (id === serviceId) {
                this.keyIndex.delete(h);
                break;
            }
        }
    }
    validateKey(rawKey) {
        return this.keyIndex.get(hashServiceKey(rawKey)) ?? null;
    }
    // ── Pre-registration (admin creates a slot) ────────────────────────────────
    preRegister(data) {
        const existing = this.entries.get(data.id);
        const now = new Date();
        const entry = {
            id: data.id,
            serviceType: data.serviceType,
            endpoint: data.endpoint ?? existing?.endpoint ?? '',
            domain: data.domain ?? existing?.domain ?? '',
            location: data.location,
            registeredAt: existing?.registeredAt ?? now,
            lastHeartbeat: existing?.lastHeartbeat ?? null,
            metrics: existing?.metrics ?? emptyMetrics(),
            status: existing?.status ?? 'offline',
            enabled: data.enabled ?? existing?.enabled ?? true,
            degraded: existing?.degraded ?? false,
            degradedReason: existing?.degradedReason,
            degradedAt: existing?.degradedAt,
            gatewayId: existing?.gatewayId,
            healthy: existing?.healthy ?? false,
            isLocal: LOCAL_RE.test(data.endpoint ?? '') || IP_RE.test(data.endpoint ?? ''),
        };
        this.entries.set(data.id, entry);
        if (data.keyHash)
            this.addKeyHash(data.id, data.keyHash);
        return entry;
    }
    // ── Live registration (microservice connects with key) ─────────────────────
    /** Enregistrement sans clé — fallback INTERNAL_SECRET (SERVICE_KEY absent). */
    registerById(serviceId, data) {
        const entry = this.entries.get(serviceId);
        if (!entry || !entry.enabled)
            return null;
        return this._applyRegistration(entry, data);
    }
    registerWithKey(rawKey, data) {
        const serviceId = this.validateKey(rawKey);
        if (!serviceId)
            return null;
        const entry = this.entries.get(serviceId);
        if (!entry || !entry.enabled)
            return null;
        return this._applyRegistration(entry, data);
    }
    _applyRegistration(entry, data) {
        const ep = data.endpoint.trim();
        entry.endpoint = ep;
        entry.domain = data.domain ?? ((() => { try {
            return new URL(ep).host;
        }
        catch {
            return ep;
        } })());
        entry.lastHeartbeat = new Date();
        entry.status = 'online';
        entry.healthy = true;
        entry.isLocal = LOCAL_RE.test(ep) || IP_RE.test(ep);
        entry.gatewayId = data.gatewayId;
        entry.degraded = false;
        entry.degradedReason = undefined;
        entry.degradedAt = undefined;
        logger_1.logger.info(`LBRegistry: "${entry.id}" (${entry.serviceType}) en ligne @ ${ep} [${entry.location}]`);
        return entry;
    }
    // ── Heartbeat ──────────────────────────────────────────────────────────────
    heartbeat(serviceId, metrics) {
        const e = this.entries.get(serviceId);
        if (!e)
            return false;
        e.lastHeartbeat = new Date();
        e.metrics = metrics;
        e.status = 'online';
        e.healthy = true;
        return true;
    }
    // ── Backward compat: register full object (used by loadInstancesFromDB) ────
    register(data) {
        return this.preRegister({
            ...data,
            keyHash: undefined,
        });
    }
    // ── Admin operations ───────────────────────────────────────────────────────
    remove(id) {
        this.removeKey(id);
        const ok = this.entries.delete(id);
        if (ok)
            logger_1.logger.info(`LBRegistry: service "${id}" supprimé`);
        return ok;
    }
    setEnabled(id, enabled) {
        const e = this.entries.get(id);
        if (!e)
            return false;
        e.enabled = enabled;
        if (!enabled) {
            e.status = 'offline';
            e.healthy = false;
        }
        logger_1.logger.info(`LBRegistry: service "${id}" ${enabled ? 'activé' : 'désactivé'}`);
        return true;
    }
    markDegraded(id, reason) {
        const e = this.entries.get(id);
        if (!e)
            return null;
        e.degraded = true;
        e.degradedAt = new Date();
        e.degradedReason = reason;
        e.status = 'degraded';
        logger_1.logger.warn(`LBRegistry: service "${id}" dégradé — ${reason}`);
        return e;
    }
    restoreInstance(id) {
        const e = this.entries.get(id);
        if (!e)
            return false;
        e.degraded = false;
        e.degradedAt = undefined;
        e.degradedReason = undefined;
        e.status = e.lastHeartbeat ? 'online' : 'offline';
        e.healthy = !!e.lastHeartbeat;
        logger_1.logger.info(`LBRegistry: service "${id}" restauré`);
        return true;
    }
    updateEndpoint(id, endpoint) {
        const e = this.entries.get(id);
        if (!e)
            return false;
        e.endpoint = endpoint;
        e.isLocal = LOCAL_RE.test(endpoint) || IP_RE.test(endpoint);
        try {
            e.domain = new URL(endpoint).host;
        }
        catch {
            e.domain = endpoint;
        }
        return true;
    }
    // ── Queries ────────────────────────────────────────────────────────────────
    getById(id) { return this.entries.get(id); }
    getAll() { return [...this.entries.values()]; }
    getDegraded() { return this.getAll().filter(e => e.degraded); }
    getInstances(serviceType, includeUnhealthy = false, includeDisabled = false) {
        return this.getAll().filter(e => e.serviceType === serviceType &&
            (includeUnhealthy || e.healthy) &&
            (includeDisabled || e.enabled) &&
            !e.degraded);
    }
    selectBest(serviceType) {
        const pool = this.getInstances(serviceType);
        if (!pool.length)
            return null;
        const remote = pool.filter(e => !e.isLocal);
        return this._pickBest(remote.length ? remote : pool);
    }
    selectBestByLocation(serviceType, loc) {
        const pool = this.getInstances(serviceType);
        if (!pool.length)
            return null;
        const remote = pool.filter(e => !e.isLocal);
        const base = remote.length ? remote : pool;
        if (loc) {
            const inRegion = base.filter(e => e.location.toUpperCase() === loc.toUpperCase());
            if (inRegion.length)
                return this._pickBest(inRegion);
        }
        return this._pickBest(base);
    }
    // ── Scoring ────────────────────────────────────────────────────────────────
    computeScore(e) {
        const { ramUsage, ramMax, cpuUsage, cpuMax, requestCount20min } = e.metrics;
        if (ramMax <= 0 && cpuMax <= 0)
            return DEFAULT_SCORE;
        const cpu = cpuMax > 0 ? Math.max(0, 1 - cpuUsage / cpuMax) : 0.5;
        const ram = ramMax > 0 ? Math.max(0, 1 - ramUsage / ramMax) : 0.5;
        const req = Math.max(0, 1 - Math.min(requestCount20min, 2000) / 2000);
        return cpu * 40 + ram * 30 + req * 30;
    }
    _pickBest(candidates) {
        return candidates.reduce((best, cur) => this.computeScore(cur) > this.computeScore(best) ? cur : best);
    }
    cleanup() {
        const now = Date.now();
        for (const e of this.entries.values()) {
            if (!e.lastHeartbeat || !e.healthy)
                continue;
            if (now - e.lastHeartbeat.getTime() > HEARTBEAT_TIMEOUT_MS) {
                e.healthy = false;
                e.status = 'offline';
                logger_1.logger.warn(`LBRegistry: "${e.id}" offline (heartbeat timeout)`);
            }
        }
    }
    destroy() { clearInterval(this.cleanupTimer); }
}
exports.lbRegistry = new LBRegistry();
exports.serviceRegistry = exports.lbRegistry;
//# sourceMappingURL=registry.js.map