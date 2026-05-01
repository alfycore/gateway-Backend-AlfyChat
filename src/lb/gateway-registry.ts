// ==========================================
// ALFYCHAT — Gateway Registry
// Gère les instances de gateway (multi-gateway)
// ==========================================

import { logger } from '../utils/logger';

export interface GatewayEntry {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  registeredAt: Date;
  lastSeen: Date;
  isSelf: boolean;
}

class GatewayRegistry {
  private gateways = new Map<string, GatewayEntry>();

  register(data: {
    id: string;
    name: string;
    url: string;
    enabled?: boolean;
    isSelf?: boolean;
  }): GatewayEntry {
    const existing = this.gateways.get(data.id);
    const now = new Date();
    const entry: GatewayEntry = {
      id:           data.id,
      name:         data.name,
      url:          data.url,
      enabled:      data.enabled ?? true,
      registeredAt: existing?.registeredAt ?? now,
      lastSeen:     now,
      isSelf:       data.isSelf ?? false,
    };
    this.gateways.set(data.id, entry);
    logger.info(`GatewayRegistry: gateway "${data.id}" (${data.name}) @ ${data.url}${data.isSelf ? ' [SELF]' : ''}`);
    return entry;
  }

  touch(id: string): void {
    const g = this.gateways.get(id);
    if (g) g.lastSeen = new Date();
  }

  remove(id: string): boolean {
    const ok = this.gateways.delete(id);
    if (ok) logger.info(`GatewayRegistry: gateway "${id}" supprimé`);
    return ok;
  }

  setEnabled(id: string, enabled: boolean): boolean {
    const g = this.gateways.get(id);
    if (!g) return false;
    g.enabled = enabled;
    return true;
  }

  update(id: string, data: { name?: string; url?: string }): boolean {
    const g = this.gateways.get(id);
    if (!g) return false;
    if (data.name !== undefined) g.name = data.name;
    if (data.url  !== undefined) g.url  = data.url;
    return true;
  }

  getAll(): GatewayEntry[] { return [...this.gateways.values()]; }
  getById(id: string): GatewayEntry | undefined { return this.gateways.get(id); }

  isOnline(id: string, timeoutMs = 120_000): boolean {
    const g = this.gateways.get(id);
    if (!g) return false;
    return Date.now() - g.lastSeen.getTime() < timeoutMs;
  }
}

export const gatewayRegistry = new GatewayRegistry();
