"use strict";
// ==========================================
// ALFYCHAT — Service Keys (shim backward-compat)
// La logique réelle est dans lb/registry.ts
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.serviceKeyHashes = exports.allowedServiceIds = exports.bannedServiceIds = exports.generateServiceKey = void 0;
exports.validateServiceSecret = validateServiceSecret;
const registry_1 = require("../lb/registry");
const env_1 = require("../config/env");
var registry_2 = require("../lb/registry");
Object.defineProperty(exports, "generateServiceKey", { enumerable: true, get: function () { return registry_2.generateServiceKey; } });
// Shim : les IDs bannis/autorisés sont maintenant gérés par enabled flag dans le registry.
// On garde ces Sets pour le code legacy dans internal.routes.ts / index.ts.
exports.bannedServiceIds = new Set();
exports.allowedServiceIds = new Set();
/**
 * Proxy Map qui délègue à lbRegistry.addKeyHash().
 * Utilisé dans index.ts : serviceKeyHashes.set(id, hash)
 */
exports.serviceKeyHashes = new Proxy(new Map(), {
    get(target, prop) {
        if (prop === 'set') {
            return (id, hash) => {
                registry_1.lbRegistry.addKeyHash(id, hash);
                return target.set(id, hash);
            };
        }
        const v = target[prop];
        return typeof v === 'function' ? v.bind(target) : v;
    },
});
/** Valide la clé ou le secret d'un service. */
function validateServiceSecret(id, secret) {
    if (!secret)
        return false;
    if (secret.startsWith('sk_')) {
        return registry_1.lbRegistry.validateKey(secret) === id;
    }
    return secret === env_1.INTERNAL_SECRET;
}
//# sourceMappingURL=service-keys.js.map