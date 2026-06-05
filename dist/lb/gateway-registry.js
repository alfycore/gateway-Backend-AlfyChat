"use strict";
// ==========================================
// ALFYCHAT — Gateway Registry
// Gère les instances de gateway (multi-gateway)
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.gatewayRegistry = void 0;
const logger_1 = require("../utils/logger");
class GatewayRegistry {
    gateways = new Map();
    register(data) {
        const existing = this.gateways.get(data.id);
        const now = new Date();
        const entry = {
            id: data.id,
            name: data.name,
            url: data.url,
            enabled: data.enabled ?? true,
            registeredAt: existing?.registeredAt ?? now,
            lastSeen: now,
            isSelf: data.isSelf ?? false,
        };
        this.gateways.set(data.id, entry);
        logger_1.logger.info(`GatewayRegistry: gateway "${data.id}" (${data.name}) @ ${data.url}${data.isSelf ? ' [SELF]' : ''}`);
        return entry;
    }
    touch(id) {
        const g = this.gateways.get(id);
        if (g)
            g.lastSeen = new Date();
    }
    remove(id) {
        const ok = this.gateways.delete(id);
        if (ok)
            logger_1.logger.info(`GatewayRegistry: gateway "${id}" supprimé`);
        return ok;
    }
    setEnabled(id, enabled) {
        const g = this.gateways.get(id);
        if (!g)
            return false;
        g.enabled = enabled;
        return true;
    }
    update(id, data) {
        const g = this.gateways.get(id);
        if (!g)
            return false;
        if (data.name !== undefined)
            g.name = data.name;
        if (data.url !== undefined)
            g.url = data.url;
        return true;
    }
    getAll() { return [...this.gateways.values()]; }
    getById(id) { return this.gateways.get(id); }
    isOnline(id, timeoutMs = 120_000) {
        const g = this.gateways.get(id);
        if (!g)
            return false;
        return Date.now() - g.lastSeen.getTime() < timeoutMs;
    }
}
exports.gatewayRegistry = new GatewayRegistry();
//# sourceMappingURL=gateway-registry.js.map