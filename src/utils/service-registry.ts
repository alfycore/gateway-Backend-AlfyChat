// ==========================================
// ALFYCHAT - SERVICE REGISTRY & LOAD BALANCER
// Gère les instances de microservices et distribue la charge
// ==========================================

import { logger } from './logger';

export type ServiceType =
  | 'users'
  | 'messages'
  | 'friends'
  | 'calls'
  | 'servers'
  | 'bots'
  | 'media';

export interface ServiceMetrics {
  ramUsage: number;         // octets utilisés
  ramMax: number;           // octets maximum
  cpuUsage: number;         // pourcentage 0-100
  cpuMax: number;           // toujours 100 en pratique
  bandwidthUsage: number;   // octets/s (débit sortant)
  requestCount20min: number; // requêtes sur les 20 dernières minutes
  responseTimeMs?: number;  // temps de réponse moyen (ms)
}

export interface ServiceInstance {
  id: string;               // identifiant unique, ex. "messages-eu-1"
  serviceType: ServiceType;
  endpoint: string;         // URL interne, ex. "http://1.messages.alfychat.eu:3002"
  domain: string;           // domaine public, ex. "1.messages.alfychat.eu"
  location: string;         // région géo, ex. "EU", "US", "ASIA"
  lastHeartbeat: Date;
  registeredAt: Date;
  metrics: ServiceMetrics;
  healthy: boolean;
  enabled: boolean;         // activé/désactivé par un admin (persiste en DB)
  degraded: boolean;        // dégradé : erreur 5XX détectée, suspendu jusqu'à validation admin
  degradedAt?: Date;        // date de la mise en dégradé
  degradedReason?: string;  // raison (ex: "503 Service Unavailable")
  isLocal: boolean;         // endpoint localhost/127.0.0.1 (priorité basse)
}

// Instance sans heartbeat → unhealthy après 90s
const HEARTBEAT_TIMEOUT_MS = 90_000;
// Nettoyage périodique des instances mortes
const CLEANUP_INTERVAL_MS = 30_000;

// Score par défaut quand les métriques sont nulles (service neuf)
const DEFAULT_SCORE = 50;

// Regex pour détecter les endpoints locaux ou à base d'IP brute (non autorisés en production)
const LOCAL_ENDPOINT_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/;
const IP_ENDPOINT_RE    = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

class ServiceRegistry {
  private instances = new Map<string, ServiceInstance>();
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  // ── Enregistrement ─────────────────────────────────────────────────────────

  /** Enregistre ou met à jour une instance de service */
  register(data: {
    id: string;
    serviceType: ServiceType;
    endpoint: string;
    domain: string;
    location: string;
    metrics: ServiceMetrics;
    enabled?: boolean;
  }): ServiceInstance {
    const existing = this.instances.get(data.id);
    const now = new Date();

    const instance: ServiceInstance = {
      ...data,
      lastHeartbeat: now,
      registeredAt: existing?.registeredAt ?? now,
      healthy: true,
      // Conserver l'état enabled existant si non fourni (évite d'écraser un disable admin)
      enabled: data.enabled !== undefined ? data.enabled : (existing?.enabled ?? true),
      // Ne pas réinitialiser degraded au register — seul un admin peut le faire via restoreInstance()
      degraded: existing?.degraded ?? false,
      degradedAt: existing?.degradedAt,
      degradedReason: existing?.degradedReason,
      isLocal: LOCAL_ENDPOINT_RE.test(data.endpoint) || IP_ENDPOINT_RE.test(data.endpoint),
    };

    this.instances.set(data.id, instance);
    logger.info(
      `ServiceRegistry: instance enregistrée — ${data.id} (${data.serviceType}) @ ${data.endpoint} [${data.location}]${instance.isLocal ? ' [LOCAL]' : ''}${!instance.enabled ? ' [DÉSACTIVÉE]' : ''}`,
    );
    return instance;
  }

  /** Met à jour les métriques d'une instance (heartbeat périodique) */
  heartbeat(id: string, metrics: ServiceMetrics): boolean {
    const instance = this.instances.get(id);
    if (!instance) return false;

    instance.lastHeartbeat = new Date();
    instance.metrics = metrics;
    instance.healthy = true;
    return true;
  }

  /** Retire manuellement une instance */
  remove(id: string): boolean {
    const deleted = this.instances.delete(id);
    if (deleted) logger.info(`ServiceRegistry: instance supprimée — ${id}`);
    return deleted;
  }

  /** Marque une instance comme dégradée (erreur 5XX) — la sort du pool de trafic jusqu'à validation admin */
  markDegraded(id: string, reason: string): ServiceInstance | null {
    const instance = this.instances.get(id);
    if (!instance) return null;
    instance.degraded = true;
    instance.degradedAt = new Date();
    instance.degradedReason = reason;
    logger.warn(`ServiceRegistry: instance DÉGRADÉE — ${id} (${reason})`);
    return instance;
  }

  /** Restaure une instance dégradée (validation admin) */
  restoreInstance(id: string): boolean {
    const instance = this.instances.get(id);
    if (!instance) return false;
    instance.degraded = false;
    instance.degradedAt = undefined;
    instance.degradedReason = undefined;
    instance.healthy = true;
    logger.info(`ServiceRegistry: instance RESTAURÉE — ${id}`);
    return true;
  }

  /** Retourne toutes les instances dégradées */
  getDegraded(): ServiceInstance[] {
    return [...this.instances.values()].filter((i) => i.degraded);
  }

  /** Active ou désactive une instance (sans la supprimer) */
  setEnabled(id: string, enabled: boolean): boolean {
    const instance = this.instances.get(id);
    if (!instance) return false;
    instance.enabled = enabled;
    logger.info(`ServiceRegistry: instance ${id} ${enabled ? 'activée' : 'désactivée'}`);
    return true;
  }

  /** Met à jour l'endpoint (URL) d'une instance existante */
  updateEndpoint(id: string, endpoint: string): boolean {
    const instance = this.instances.get(id);
    if (!instance) return false;
    instance.endpoint = endpoint;
    instance.isLocal = LOCAL_ENDPOINT_RE.test(endpoint) || IP_ENDPOINT_RE.test(endpoint);
    logger.info(`ServiceRegistry: endpoint de "${id}" mis à jour → ${endpoint}`);
    return true;
  }

  // ── Sélection ──────────────────────────────────────────────────────────────

  /** Retourne toutes les instances d'un type de service */
  getInstances(serviceType: ServiceType, includeUnhealthy = false, includeDisabled = false): ServiceInstance[] {
    return [...this.instances.values()].filter(
      (i) =>
        i.serviceType === serviceType &&
        (includeUnhealthy || i.healthy) &&
        (includeDisabled || i.enabled) &&
        !i.degraded,
    );
  }

  /**
   * Sélectionne la meilleure instance disponible.
   * Préfère les instances non-localhost aux instances locales.
   */
  selectBest(serviceType: ServiceType): ServiceInstance | null {
    const candidates = this.getInstances(serviceType);
    if (candidates.length === 0) return null;

    const remote = candidates.filter((i) => !i.isLocal);
    return this.pickBestFrom(remote.length > 0 ? remote : candidates);
  }

  /**
   * Sélectionne la meilleure instance en préférant une région donnée.
   * Préfère les instances non-localhost.
   * Fallback sur toutes les régions si aucune instance disponible dans la région demandée.
   */
  selectBestByLocation(serviceType: ServiceType, preferredLocation?: string): ServiceInstance | null {
    const candidates = this.getInstances(serviceType);
    if (candidates.length === 0) return null;

    // Toujours préférer les instances non-localhost
    const remote = candidates.filter((i) => !i.isLocal);
    const pool = remote.length > 0 ? remote : candidates;

    if (preferredLocation) {
      const inRegion = pool.filter(
        (i) => i.location.toUpperCase() === preferredLocation.toUpperCase(),
      );
      if (inRegion.length > 0) return this.pickBestFrom(inRegion);
    }

    return this.pickBestFrom(pool);
  }

  /** Trouve une instance par son ID (toutes régions, même unhealthy/disabled) */
  getById(id: string): ServiceInstance | undefined {
    return this.instances.get(id);
  }

  /** Retourne toutes les instances connues (y compris désactivées, pour l'admin) */
  getAll(): ServiceInstance[] {
    return [...this.instances.values()];
  }

  // ── Scoring ────────────────────────────────────────────────────────────────

  /**
   * Score de charge : plus haut = moins chargé.
   * Pondération : CPU 40%, RAM 30%, requêtes 20min 30%
   * Plage : 0–100
   */
  computeScore(instance: ServiceInstance): number {
    const { ramUsage, ramMax, cpuUsage, cpuMax, requestCount20min } = instance.metrics;

    if (ramMax <= 0 && cpuMax <= 0) return DEFAULT_SCORE;

    const cpuScore = cpuMax > 0 ? Math.max(0, 1 - cpuUsage / cpuMax) : 0.5;
    const ramScore = ramMax > 0 ? Math.max(0, 1 - ramUsage / ramMax) : 0.5;
    const reqScore = Math.max(0, 1 - Math.min(requestCount20min, 2000) / 2000);

    return (cpuScore * 40 + ramScore * 30 + reqScore * 30);
  }

  // ── Cleanup ────────────────────────────────────────────────────────────────

  private pickBestFrom(candidates: ServiceInstance[]): ServiceInstance {
    return candidates.reduce((best, current) =>
      this.computeScore(current) > this.computeScore(best) ? current : best,
    );
  }

  /** Marque les instances sans heartbeat récent comme unhealthy */
  private cleanup(): void {
    const now = Date.now();
    for (const [, instance] of this.instances) {
      const elapsed = now - instance.lastHeartbeat.getTime();
      if (elapsed > HEARTBEAT_TIMEOUT_MS && instance.healthy) {
        instance.healthy = false;
        logger.warn(
          `ServiceRegistry: instance hors-ligne — ${instance.id} (${Math.round(elapsed / 1000)}s sans heartbeat)`,
        );
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}

// Singleton global partagé par tout le gateway
export const serviceRegistry = new ServiceRegistry();
