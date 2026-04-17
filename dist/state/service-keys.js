"use strict";
// ==========================================
// ALFYCHAT — Service Key Management
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.allowedServiceIds = exports.bannedServiceIds = exports.serviceKeyHashes = void 0;
exports.generateServiceKey = generateServiceKey;
exports.validateServiceSecret = validateServiceSecret;
const node_crypto_1 = require("node:crypto");
const env_1 = require("../config/env");
/** Map<serviceId, sha256(rawKey)> — loaded from DB at startup */
exports.serviceKeyHashes = new Map();
/** Blacklist of instances disabled/deleted by an admin */
exports.bannedServiceIds = new Set();
/** Whitelist of IDs authorised to register (pre-registered by an admin) */
exports.allowedServiceIds = new Set();
/** Generate a unique service key and its SHA-256 hash */
function generateServiceKey() {
    const rawKey = 'sc_' + (0, node_crypto_1.randomBytes)(32).toString('base64url');
    const hash = (0, node_crypto_1.createHash)('sha256').update(rawKey).digest('hex');
    return { rawKey, hash };
}
/** Validate a service secret against stored hash or INTERNAL_SECRET fallback */
function validateServiceSecret(id, secret) {
    const storedHash = exports.serviceKeyHashes.get(id);
    if (storedHash) {
        const provided = (0, node_crypto_1.createHash)('sha256').update(secret).digest('hex');
        return provided === storedHash;
    }
    return secret === env_1.INTERNAL_SECRET;
}
//# sourceMappingURL=service-keys.js.map