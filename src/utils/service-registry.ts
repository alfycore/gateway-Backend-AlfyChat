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
}

// Instance sans heartbeat → unhealthy après 90s
const HEARTBEAT_TIMEOUT_MS = 90_000;
// Nettoyage périodique des instances mortes
const CLEANUP_INTERVAL_MS = 30_000;

// Score par défaut quand les métriques sont nulles (service neuf)
const DEFAULT_SCORE = 50;

class ServiceRegistry {
  private instances = new Map<string, ServiceInstance>();
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
    // Éviter que ce timer bloque la fermeture du process
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
  }): ServiceInstance {
    const existing = this.instances.get(data.id);
    const now = new Date();

    const instance: ServiceInstance = {
      ...data,
      lastHeartbeat: now,
      registeredAt: existing?.registeredAt ?? now,
      healthy: true,
    };

    this.instances.set(data.id, instance);
    logger.info(
      `ServiceRegistry: instance enregistrée — ${data.id} (${data.serviceType}) @ ${data.endpoint} [${data.location}]`,
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

  // ── Sélection ──────────────────────────────────────────────────────────────

  /** Retourne toutes les instances saines d'un type de service */
  getInstances(serviceType: ServiceType, includeUnhealthy = false): ServiceInstance[] {
    return [...this.instances.values()].filter(
      (i) => i.serviceType === serviceType && (includeUnhealthy || i.healthy),
    );
  }

  /** Sélectionne la meilleure instance (score le plus élevé = moins chargée) */
  selectBest(serviceType: ServiceType): ServiceInstance | null {
    const candidates = this.getInstances(serviceType);
    if (candidates.length === 0) return null;
    return this.pickBestFrom(candidates);
  }

  /**
   * Sélectionne la meilleure instance en préférant une région donnée.
   * Fallback sur toutes les régions si aucune instance disponible dans la région demandée.
   */
  selectBestByLocation(serviceType: ServiceType, preferredLocation?: string): ServiceInstance | null {
    const candidates = this.getInstances(serviceType);
    if (candidates.length === 0) return null;

    if (preferredLocation) {
      const inRegion = candidates.filter(
        (i) => i.location.toUpperCase() === preferredLocation.toUpperCase(),
      );
      if (inRegion.length > 0) return this.pickBestFrom(inRegion);
    }

    return this.pickBestFrom(candidates);
  }

  /** Trouve une instance par son ID (toutes régions, même unhealthy) */
  getById(id: string): ServiceInstance | undefined {
    return this.instances.get(id);
  }

  /** Retourne toutes les instances connues */
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
    // Normalise sur 2000 requêtes/20min comme maximum raisonnable
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
