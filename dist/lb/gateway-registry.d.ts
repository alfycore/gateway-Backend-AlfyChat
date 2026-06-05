export interface GatewayEntry {
    id: string;
    name: string;
    url: string;
    enabled: boolean;
    registeredAt: Date;
    lastSeen: Date;
    isSelf: boolean;
}
declare class GatewayRegistry {
    private gateways;
    register(data: {
        id: string;
        name: string;
        url: string;
        enabled?: boolean;
        isSelf?: boolean;
    }): GatewayEntry;
    touch(id: string): void;
    remove(id: string): boolean;
    setEnabled(id: string, enabled: boolean): boolean;
    update(id: string, data: {
        name?: string;
        url?: string;
    }): boolean;
    getAll(): GatewayEntry[];
    getById(id: string): GatewayEntry | undefined;
    isOnline(id: string, timeoutMs?: number): boolean;
}
export declare const gatewayRegistry: GatewayRegistry;
export {};
//# sourceMappingURL=gateway-registry.d.ts.map