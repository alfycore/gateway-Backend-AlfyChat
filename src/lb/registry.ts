// ==========================================
// ALFYCHAT — LB Registry v2
// Source de vérité unique pour services et clés
// ==========================================

import { randomBytes, createHash } from 'node:crypto';
import { logger } from '../utils/logger';

export type ServiceType =
  | 'users' | 'messages' | 'friends' | 'calls' | 'servers' | 'bots' | 'media';

export interface ServiceMetrics {
  cpuUsage: number;
  cpuMax: number;
  ramUsage: number;
  ramMax: number;
  bandwidthUsage: number;
  requestCount20min: number;
  responseTimeMs?: number;
}

export type ServiceStatus = 'online' | 'degraded' | 'offline';

export interface ServiceEntry {
  id: string;
  serviceType: ServiceType;
  endpoint: string;
  domain: string;
  location: string;
  registeredAt: Date;
  lastHeartbeat: Date | null;
  metrics: ServiceMetrics;
  status: ServiceStatus;
  enabled: boolean;
  degraded: boolean;
  degradedReason?: string;
  degradedAt?: Date;
  gatewayId?: string;
  // backward-compat with proxy.ts / helpers.ts
  healthy: boolean;
  isLocal: boolean;
}

const HEARTBEAT_TIMEOUT_MS = 90_000;
const CLEANUP_INTERVAL_MS  = 30_000;
const DEFAULT_SCORE        = 50;
const LOCAL_RE = /^https?:\/\/(localhost|127\.0\.0\.1)/;
const IP_RE    = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

export function generateServiceKey(): { rawKey: string; hash: string } {
  const rawKey = 'sk_' + randomBytes(32).toString('base64url');
  const hash   = createHash('sha256').update(rawKey).digest('hex');
  return { rawKey, hash };
}

export function hashServiceKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

function emptyMetrics(): ServiceMetrics {
  return { cpuUsage: 0, cpuMax: 100, ramUsage: 0, ramMax: 0, bandwidthUsage: 0, requestCount20min: 0 };
}

class LBRegistry {
  private entries  = new Map<string, ServiceEntry>();
  private keyIndex = new Map<string, string>(); // keyHash → serviceId
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  // ── Key management ─────────────────────────────────────────────────────────

  addKeyHash(serviceId: string, keyHash: string): void {
    for (const [h, id] of this.keyIndex) {
      if (id === serviceId) { this.keyIndex.delete(h); break; }
    }
    this.keyIndex.set(keyHash, serviceId);
  }

  removeKey(serviceId: string): void {
    for (const [h, id] of this.keyIndex) {
      if (id === serviceId) { this.keyIndex.delete(h); break; }
    }
  }

  validateKey(rawKey: string): string | null {
    return this.keyIndex.get(hashServiceKey(rawKey)) ?? null;
  }

  // ── Pre-registration (admin creates a slot) ────────────────────────────────

  preRegister(data: {
    id: string;
    serviceType: ServiceType;
    location: string;
    enabled?: boolean;
    keyHash?: string;
    endpoint?: string;
    domain?: string;
  }): ServiceEntry {
    const existing = this.entries.get(data.id);
    const now = new Date();
    const entry: ServiceEntry = {
      id:            data.id,
      serviceType:   data.serviceType,
      endpoint:      data.endpoint ?? existing?.endpoint ?? '',
      domain:        data.domain   ?? existing?.domain   ?? '',
      location:      data.location,
      registeredAt:  existing?.registeredAt ?? now,
      lastHeartbeat: existing?.lastHeartbeat ?? null,
      metrics:       existing?.metrics ?? emptyMetrics(),
      status:        existing?.status  ?? 'offline',
      enabled:       data.enabled ?? existing?.enabled ?? true,
      degraded:      existing?.degraded ?? false,
      degradedReason: existing?.degradedReason,
      degradedAt:    existing?.degradedAt,
      gatewayId:     existing?.gatewayId,
      healthy:       existing?.healthy ?? false,
      isLocal:       LOCAL_RE.test(data.endpoint ?? '') || IP_RE.test(data.endpoint ?? ''),
    };
    this.entries.set(data.id, entry);
    if (data.keyHash) this.addKeyHash(data.id, data.keyHash);
    return entry;
  }

  // ── Live registration (microservice connects with key) ─────────────────────

  /** Enregistrement sans clé — fallback INTERNAL_SECRET (SERVICE_KEY absent). */
  registerById(serviceId: string, data: {
    endpoint: string;
    domain?: string;
    gatewayId?: string;
  }): ServiceEntry | null {
    const entry = this.entries.get(serviceId);
    if (!entry || !entry.enabled) return null;
    return this._applyRegistration(entry, data);
  }

  registerWithKey(rawKey: string, data: {
    endpoint: string;
    domain?: string;
    gatewayId?: string;
  }): ServiceEntry | null {
    const serviceId = this.validateKey(rawKey);
    if (!serviceId) return null;

    const entry = this.entries.get(serviceId);
    if (!entry || !entry.enabled) return null;
    return this._applyRegistration(entry, data);
  }

  private _applyRegistration(entry: ServiceEntry, data: { endpoint: string; domain?: string; gatewayId?: string }): ServiceEntry {
    const ep = data.endpoint.trim();
    entry.endpoint      = ep;
    entry.domain        = data.domain ?? ((() => { try { return new URL(ep).host; } catch { return ep; } })());
    entry.lastHeartbeat = new Date();
    entry.status        = 'online';
    entry.healthy       = true;
    entry.isLocal       = LOCAL_RE.test(ep) || IP_RE.test(ep);
    entry.gatewayId     = data.gatewayId;
    entry.degraded      = false;
    entry.degradedReason = undefined;
    entry.degradedAt    = undefined;

    logger.info(`LBRegistry: "${entry.id}" (${entry.serviceType}) en ligne @ ${ep} [${entry.location}]`);
    return entry;
  }

  // ── Heartbeat ──────────────────────────────────────────────────────────────

  heartbeat(serviceId: string, metrics: ServiceMetrics): boolean {
    const e = this.entries.get(serviceId);
    if (!e) return false;
    e.lastHeartbeat = new Date();
    e.metrics  = metrics;
    e.status   = 'online';
    e.healthy  = true;
    return true;
  }

  // ── Backward compat: register full object (used by loadInstancesFromDB) ────

  register(data: {
    id: string;
    serviceType: ServiceType;
    endpoint: string;
    domain: string;
    location: string;
    metrics?: ServiceMetrics;
    enabled?: boolean;
  }): ServiceEntry {
    return this.preRegister({
      ...data,
      keyHash: undefined,
    });
  }

  // ── Admin operations ───────────────────────────────────────────────────────

  remove(id: string): boolean {
    this.removeKey(id);
    const ok = this.entries.delete(id);
    if (ok) logger.info(`LBRegistry: service "${id}" supprimé`);
    return ok;
  }

  setEnabled(id: string, enabled: boolean): boolean {
    const e = this.entries.get(id);
    if (!e) return false;
    e.enabled = enabled;
    if (!enabled) { e.status = 'offline'; e.healthy = false; }
    logger.info(`LBRegistry: service "${id}" ${enabled ? 'activé' : 'désactivé'}`);
    return true;
  }

  markDegraded(id: string, reason: string): ServiceEntry | null {
    const e = this.entries.get(id);
    if (!e) return null;
    e.degraded       = true;
    e.degradedAt     = new Date();
    e.degradedReason = reason;
    e.status         = 'degraded';
    logger.warn(`LBRegistry: service "${id}" dégradé — ${reason}`);
    return e;
  }

  restoreInstance(id: string): boolean {
    const e = this.entries.get(id);
    if (!e) return false;
    e.degraded       = false;
    e.degradedAt     = undefined;
    e.degradedReason = undefined;
    e.status         = e.lastHeartbeat ? 'online' : 'offline';
    e.healthy        = !!e.lastHeartbeat;
    logger.info(`LBRegistry: service "${id}" restauré`);
    return true;
  }

  updateEndpoint(id: string, endpoint: string): boolean {
    const e = this.entries.get(id);
    if (!e) return false;
    e.endpoint = endpoint;
    e.isLocal  = LOCAL_RE.test(endpoint) || IP_RE.test(endpoint);
    try { e.domain = new URL(endpoint).host; } catch { e.domain = endpoint; }
    return true;
  }

  // ── Queries ────────────────────────────────────────────────────────────────

  getById(id: string): ServiceEntry | undefined { return this.entries.get(id); }
  getAll(): ServiceEntry[] { return [...this.entries.values()]; }
  getDegraded(): ServiceEntry[] { return this.getAll().filter(e => e.degraded); }

  getInstances(
    serviceType: ServiceType,
    includeUnhealthy = false,
    includeDisabled  = false,
  ): ServiceEntry[] {
    return this.getAll().filter(e =>
      e.serviceType === serviceType &&
      (includeUnhealthy || e.healthy) &&
      (includeDisabled  || e.enabled) &&
      !e.degraded,
    );
  }

  selectBest(serviceType: ServiceType): ServiceEntry | null {
    const pool = this.getInstances(serviceType);
    if (!pool.length) return null;
    const remote = pool.filter(e => !e.isLocal);
    return this._pickBest(remote.length ? remote : pool);
  }

  selectBestByLocation(serviceType: ServiceType, loc?: string): ServiceEntry | null {
    const pool = this.getInstances(serviceType);
    if (!pool.length) return null;
    const remote = pool.filter(e => !e.isLocal);
    const base   = remote.length ? remote : pool;
    if (loc) {
      const inRegion = base.filter(e => e.location.toUpperCase() === loc.toUpperCase());
      if (inRegion.length) return this._pickBest(inRegion);
    }
    return this._pickBest(base);
  }

  // ── Scoring ────────────────────────────────────────────────────────────────

  computeScore(e: ServiceEntry): number {
    const { ramUsage, ramMax, cpuUsage, cpuMax, requestCount20min } = e.metrics;
    if (ramMax <= 0 && cpuMax <= 0) return DEFAULT_SCORE;
    const cpu = cpuMax > 0 ? Math.max(0, 1 - cpuUsage / cpuMax) : 0.5;
    const ram = ramMax > 0 ? Math.max(0, 1 - ramUsage / ramMax) : 0.5;
    const req = Math.max(0, 1 - Math.min(requestCount20min, 2000) / 2000);
    return cpu * 40 + ram * 30 + req * 30;
  }

  private _pickBest(candidates: ServiceEntry[]): ServiceEntry {
    return candidates.reduce((best, cur) =>
      this.computeScore(cur) > this.computeScore(best) ? cur : best,
    );
  }

  private cleanup(): void {
    const now = Date.now();
    for (const e of this.entries.values()) {
      if (!e.lastHeartbeat || !e.healthy) continue;
      if (now - e.lastHeartbeat.getTime() > HEARTBEAT_TIMEOUT_MS) {
        e.healthy = false;
        e.status  = 'offline';
        logger.warn(`LBRegistry: "${e.id}" offline (heartbeat timeout)`);
      }
    }
  }

  destroy(): void { clearInterval(this.cleanupTimer); }
}

export const lbRegistry = new LBRegistry();
// Backward-compat alias used by proxy.ts / helpers.ts / monitoring
export { lbRegistry as serviceRegistry };
