export declare const MONITORED_SERVICES: {
    name: string;
    url: string;
}[];
export declare const MONITORING_INTERVAL_MS: number;
/**
 * Run one health-check cycle for all monitored services + poll /metrics on
 * registered instances, then persist snapshots to DB.
 */
export declare function runMonitoringCycle(connectedClientsSize: number): Promise<void>;
//# sourceMappingURL=cycle.d.ts.map