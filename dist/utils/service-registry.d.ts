export type ServiceType = 'users' | 'messages' | 'friends' | 'calls' | 'servers' | 'bots' | 'media';
export interface ServiceMetrics {
    ramUsage: number;
    ramMax: number;
    cpuUsage: number;
    cpuMax: number;
    bandwidthUsage: number;
    requestCount20min: number;
    responseTimeMs?: number;
}
export interface ServiceInstance {
    id: string;
    serviceType: ServiceType;
    endpoint: string;
    domain: string;
    location: string;
    lastHeartbeat: Date;
    registeredAt: Date;
    metrics: ServiceMetrics;
    healthy: boolean;
    enabled: boolean;
    degraded: boolean;
    degradedAt?: Date;
    degradedReason?: string;
    isLocal: boolean;
}
declare class ServiceRegistry {
    private instances;
    private cleanupTimer;
    constructor();
    /** Enregistre ou met à jour une instance de service */
    register(data: {
        id: string;
        serviceType: ServiceType;
        endpoint: string;
        domain: string;
        location: string;
        metrics: ServiceMetrics;
        enabled?: boolean;
    }): ServiceInstance;
    /** Met à jour les métriques d'une instance (heartbeat périodique) */
    heartbeat(id: string, metrics: ServiceMetrics): boolean;
    /** Retire manuellement une instance */
    remove(id: string): boolean;
    /** Marque une instance comme dégradée (erreur 5XX) — la sort du pool de trafic jusqu'à validation admin */
    markDegraded(id: string, reason: string): ServiceInstance | null;
    /** Restaure une instance dégradée (validation admin) */
    restoreInstance(id: string): boolean;
    /** Retourne toutes les instances dégradées */
    getDegraded(): ServiceInstance[];
    /** Active ou désactive une instance (sans la supprimer) */
    setEnabled(id: string, enabled: boolean): boolean;
    /** Retourne toutes les instances d'un type de service */
    getInstances(serviceType: ServiceType, includeUnhealthy?: boolean, includeDisabled?: boolean): ServiceInstance[];
    /**
     * Sélectionne la meilleure instance disponible.
     * Préfère les instances non-localhost aux instances locales.
     */
    selectBest(serviceType: ServiceType): ServiceInstance | null;
    /**
     * Sélectionne la meilleure instance en préférant une région donnée.
     * Préfère les instances non-localhost.
     * Fallback sur toutes les régions si aucune instance disponible dans la région demandée.
     */
    selectBestByLocation(serviceType: ServiceType, preferredLocation?: string): ServiceInstance | null;
    /** Trouve une instance par son ID (toutes régions, même unhealthy/disabled) */
    getById(id: string): ServiceInstance | undefined;
    /** Retourne toutes les instances connues (y compris désactivées, pour l'admin) */
    getAll(): ServiceInstance[];
    /**
     * Score de charge : plus haut = moins chargé.
     * Pondération : CPU 40%, RAM 30%, requêtes 20min 30%
     * Plage : 0–100
     */
    computeScore(instance: ServiceInstance): number;
    private pickBestFrom;
    /** Marque les instances sans heartbeat récent comme unhealthy */
    private cleanup;
    destroy(): void;
}
export declare const serviceRegistry: ServiceRegistry;
export {};
//# sourceMappingURL=service-registry.d.ts.map