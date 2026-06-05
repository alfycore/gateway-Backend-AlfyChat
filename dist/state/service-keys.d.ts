export { generateServiceKey } from '../lb/registry';
export declare const bannedServiceIds: Set<string>;
export declare const allowedServiceIds: Set<string>;
/**
 * Proxy Map qui délègue à lbRegistry.addKeyHash().
 * Utilisé dans index.ts : serviceKeyHashes.set(id, hash)
 */
export declare const serviceKeyHashes: Map<string, string>;
/** Valide la clé ou le secret d'un service. */
export declare function validateServiceSecret(id: string, secret: string): boolean;
//# sourceMappingURL=service-keys.d.ts.map