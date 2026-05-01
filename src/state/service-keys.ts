// ==========================================
// ALFYCHAT — Service Keys (shim backward-compat)
// La logique réelle est dans lb/registry.ts
// ==========================================

import { lbRegistry, generateServiceKey as _gen, hashServiceKey } from '../lb/registry';
import { INTERNAL_SECRET } from '../config/env';

export { generateServiceKey } from '../lb/registry';

// Shim : les IDs bannis/autorisés sont maintenant gérés par enabled flag dans le registry.
// On garde ces Sets pour le code legacy dans internal.routes.ts / index.ts.
export const bannedServiceIds  = new Set<string>();
export const allowedServiceIds = new Set<string>();

/**
 * Proxy Map qui délègue à lbRegistry.addKeyHash().
 * Utilisé dans index.ts : serviceKeyHashes.set(id, hash)
 */
export const serviceKeyHashes: Map<string, string> = new Proxy(new Map<string, string>(), {
  get(target, prop) {
    if (prop === 'set') {
      return (id: string, hash: string) => {
        lbRegistry.addKeyHash(id, hash);
        return target.set(id, hash);
      };
    }
    const v = (target as any)[prop];
    return typeof v === 'function' ? v.bind(target) : v;
  },
});

/** Valide la clé ou le secret d'un service. */
export function validateServiceSecret(id: string, secret: string): boolean {
  if (!secret) return false;
  if (secret.startsWith('sk_')) {
    return lbRegistry.validateKey(secret) === id;
  }
  return secret === INTERNAL_SECRET;
}
