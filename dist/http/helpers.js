"use strict";
// ==========================================
// ALFYCHAT — HTTP Utility Functions
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getClientIP = getClientIP;
exports.extractUserIdFromJWT = extractUserIdFromJWT;
exports.safeJson = safeJson;
exports.getServiceUrl = getServiceUrl;
exports.rewriteNodePath = rewriteNodePath;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const env_1 = require("../config/env");
const service_registry_1 = require("../utils/service-registry");
/** Extract client IP, trusting X-Forwarded-For only from known proxies */
function getClientIP(req) {
    const remoteAddr = req.socket.remoteAddress || '0.0.0.0';
    if (env_1.TRUSTED_PROXIES.has(remoteAddr)) {
        const forwarded = req.headers['x-forwarded-for'];
        if (typeof forwarded === 'string')
            return forwarded.split(',')[0].trim();
    }
    return remoteAddr;
}
/** Decode userId from Authorization header (no throw) */
function extractUserIdFromJWT(authHeader) {
    if (!authHeader?.startsWith('Bearer '))
        return null;
    try {
        const token = authHeader.substring(7);
        const decoded = jsonwebtoken_1.default.verify(token, env_1.JWT_SECRET);
        return decoded.userId || decoded.id || null;
    }
    catch {
        return null;
    }
}
/** Parse JSON safely — returns null if body is empty or not valid JSON */
async function safeJson(response) {
    const text = await response.text();
    if (!text)
        return null;
    try {
        return JSON.parse(text);
    }
    catch {
        return null;
    }
}
/**
 * Best-effort service URL via registry. Falls back to env-var URL.
 * In dev, always returns the fallback (.env / localhost).
 */
function getServiceUrl(serviceType, fallback) {
    if (env_1.IS_DEV)
        return fallback;
    const best = service_registry_1.serviceRegistry.selectBest(serviceType);
    if (!best)
        return fallback;
    const isLocalEndpoint = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(best.endpoint);
    if (isLocalEndpoint || env_1.IP_ENDPOINT_RE.test(best.endpoint))
        return fallback;
    return best.endpoint;
}
/** Rewrite Express URL for a server-node: /api/servers/:id/X → /X */
function rewriteNodePath(req, serverId) {
    const fullPath = req.originalUrl.split('?')[0];
    const query = req.originalUrl.includes('?') ? '?' + req.originalUrl.split('?')[1] : '';
    const prefix = `/api/servers/${serverId}`;
    let subPath = fullPath.startsWith(prefix) ? fullPath.slice(prefix.length) : fullPath;
    // /channels/:chId/messages?... → /messages?channelId=:chId&...
    const msgMatch = subPath.match(/^\/channels\/([^/]+)\/messages$/);
    if (msgMatch) {
        const channelId = msgMatch[1];
        const sep = query ? query + '&' : '?';
        return `/messages${sep}channelId=${channelId}`;
    }
    return (subPath || '/') + query;
}
//# sourceMappingURL=helpers.js.map