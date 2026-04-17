export type IncidentSeverity = 'info' | 'warning' | 'critical';
export type IncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved';
export interface Incident {
    id: number;
    title: string;
    message: string | null;
    severity: IncidentSeverity;
    services: string | null;
    status: IncidentStatus;
    created_by: string | null;
    created_at: string;
    updated_at: string;
    resolved_at: string | null;
}
export interface ServiceUptimeDay {
    date: string;
    uptime_pct: number;
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
declare class MonitoringDB {
    private pool;
    private ready;
    init(): Promise<void>;
    private createTables;
    saveServiceSnapshot(snapshots: ServiceSnapshot[]): Promise<void>;
    saveUserStats(connectedUsers: number): Promise<void>;
    /** Returns latest status per service */
    getLatestServiceStatus(): Promise<ServiceHistory[]>;
    /** Returns service history for the last N hours (default 24) */
    getServiceHistory(service: string, hours?: number): Promise<ServiceHistory[]>;
    /** Returns user stats for the last N hours (default 24) */
    getUserStatsHistory(hours?: number): Promise<UserStatsHistory[]>;
    /** Peak connected users in the last N hours */
    getPeakUsers(hours?: number): Promise<number>;
    /**
     * Aggregated user stats by period.
     * - 'hour'  → one point per hour, last 24 hours  (AVG connected_users per hour)
     * - 'day'   → one point per day,  last 30 days   (AVG connected_users per day)
     * - 'month' → one point per month, last 12 months (AVG connected_users per month)
     */
    getUserStatsAggregated(period: '30min' | '10min' | 'hour' | 'day' | 'month'): Promise<{
        label: string;
        avg: number;
        max: number;
        min: number;
    }[]>;
    /** Prune old monitoring data (older than N days) */
    prune(days?: number): Promise<void>;
    getIncidents(includeResolved?: boolean): Promise<Incident[]>;
    createIncident(data: {
        title: string;
        message?: string;
        severity: IncidentSeverity;
        services?: string[];
        status?: IncidentStatus;
        createdBy?: string;
    }): Promise<number | null>;
    updateIncident(id: number, data: {
        title?: string;
        message?: string;
        severity?: IncidentSeverity;
        services?: string[];
        status?: IncidentStatus;
    }): Promise<boolean>;
    deleteIncident(id: number): Promise<boolean>;
    getServiceUptimeDaily(service: string, days?: number): Promise<ServiceUptimeDay[]>;
    /** Charge toutes les instances depuis la DB (y compris désactivées pour que l'admin les voie) */
    loadServiceInstances(): Promise<{
        id: string;
        serviceType: string;
        endpoint: string;
        domain: string;
        location: string;
        enabled: boolean;
        serviceKeyHash: string | null;
    }[]>;
    /** Vérifie si une instance est désactivée (bloque le ré-enregistrement automatique) */
    isInstanceDisabled(id: string): Promise<boolean>;
    /** Crée ou met à jour une instance (ne touche pas au champ enabled si la ligne existe déjà) */
    upsertServiceInstance(data: {
        id: string;
        serviceType: string;
        endpoint: string;
        domain: string;
        location: string;
    }): Promise<void>;
    /** Active ou désactive une instance (persiste l'état) */
    setInstanceEnabled(id: string, enabled: boolean): Promise<void>;
    /** Supprime une instance définitivement */
    removeServiceInstance(id: string): Promise<void>;
    /** Stocke le hash SHA-256 de la clé de service (ne stocke jamais la clé brute) */
    storeServiceKeyHash(id: string, rawKey: string): Promise<void>;
    isReady(): boolean;
}
export declare const monitoringDB: MonitoringDB;
export {};
//# sourceMappingURL=monitoring-db.d.ts.map