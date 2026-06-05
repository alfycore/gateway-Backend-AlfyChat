type ServiceStatus = 'up' | 'degraded' | 'down';
export interface KenerMonitorImpact {
    monitor_tag: string;
    impact: 'UP' | 'DOWN' | 'DEGRADED';
}
export interface KenerIncident {
    id: number;
    title: string;
    start_date_time: number;
    end_date_time: number | null;
    state: string;
    status: string;
    incident_type: string;
    incident_source: string;
    monitors: KenerMonitorImpact[];
}
export declare const KENER_ENABLED: boolean;
export declare const SERVICE_TO_KENER_TAG: Record<string, string>;
export declare function createIncident(args: {
    title: string;
    monitorTag: string;
    impact: 'DOWN' | 'DEGRADED';
    startTs: number;
}): Promise<KenerIncident>;
/** State transitions are done via comments (INVESTIGATING → IDENTIFIED → MONITORING → RESOLVED). */
export declare function addIncidentComment(incidentId: number, state: 'INVESTIGATING' | 'IDENTIFIED' | 'MONITORING' | 'RESOLVED', comment: string): Promise<void>;
export declare function setIncidentEnd(incidentId: number, endTs: number): Promise<void>;
/**
 * Called by the monitoring cycle on each observed status transition.
 * Opens an incident on up→degraded/down and resolves it on any→up.
 */
export declare function handleStatusTransition(service: string, prev: ServiceStatus | undefined, next: ServiceStatus, reason?: string): Promise<void>;
export {};
//# sourceMappingURL=kener-client.d.ts.map