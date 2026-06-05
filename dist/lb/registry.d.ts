export type ServiceType = 'users' | 'messages' | 'friends' | 'calls' | 'servers' | 'bots' | 'media';
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
    healthy: boolean;
    isLocal: boolean;
}
export declare function generateServiceKey(): {
    rawKey: string;
    hash: string;
};
export declare function hashServiceKey(key: string): string;
declare class LBRegistry {
    private entries;
    private keyIndex;
    private cleanupTimer;
    constructor();
    addKeyHash(serviceId: string, keyHash: string): void;
    removeKey(serviceId: string): void;
    validateKey(rawKey: string): string | null;
    preRegister(data: {
        id: string;
        serviceType: ServiceType;
        location: string;
        enabled?: boolean;
        keyHash?: string;
        endpoint?: string;
        domain?: string;
    }): ServiceEntry;
    /** Enregistrement sans clé — fallback INTERNAL_SECRET (SERVICE_KEY absent). */
    registerById(serviceId: string, data: {
        endpoint: string;
        domain?: string;
        gatewayId?: string;
    }): ServiceEntry | null;
    registerWithKey(rawKey: string, data: {
        endpoint: string;
        domain?: string;
        gatewayId?: string;
    }): ServiceEntry | null;
    private _applyRegistration;
    heartbeat(serviceId: string, metrics: ServiceMetrics): boolean;
    register(data: {
        id: string;
        serviceType: ServiceType;
        endpoint: string;
        domain: string;
        location: string;
        metrics?: ServiceMetrics;
        enabled?: boolean;
    }): ServiceEntry;
    remove(id: string): boolean;
    setEnabled(id: string, enabled: boolean): boolean;
    markDegraded(id: string, reason: string): ServiceEntry | null;
    restoreInstance(id: string): boolean;
    updateEndpoint(id: string, endpoint: string): boolean;
    getById(id: string): ServiceEntry | undefined;
    getAll(): ServiceEntry[];
    getDegraded(): ServiceEntry[];
    getInstances(serviceType: ServiceType, includeUnhealthy?: boolean, includeDisabled?: boolean): ServiceEntry[];
    selectBest(serviceType: ServiceType): ServiceEntry | null;
    selectBestByLocation(serviceType: ServiceType, loc?: string): ServiceEntry | null;
    computeScore(e: ServiceEntry): number;
    private _pickBest;
    private cleanup;
    destroy(): void;
}
export declare const lbRegistry: LBRegistry;
export { lbRegistry as serviceRegistry };
//# sourceMappingURL=registry.d.ts.map