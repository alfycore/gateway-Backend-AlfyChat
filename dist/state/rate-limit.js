"use strict";
// ==========================================
// ALFYCHAT — WS Message & Join Rate Limiting
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.JOIN_RATE_MAX = exports.JOIN_RATE_WINDOW = exports.serverJoinRateLimit = exports.MSG_RATE_MAX = exports.MSG_RATE_WINDOW = exports.messageRateLimit = void 0;
exports.checkServerJoinRate = checkServerJoinRate;
/** userId → array of timestamps (last N messages) */
exports.messageRateLimit = new Map();
exports.MSG_RATE_WINDOW = 10000; // 10 seconds
exports.MSG_RATE_MAX = 10; // max 10 messages per window
/** SERVER_JOIN / SERVER_LEAVE rate limit */
exports.serverJoinRateLimit = new Map();
exports.JOIN_RATE_WINDOW = 60000; // 60 seconds
exports.JOIN_RATE_MAX = 5; // max 5 join/leave per minute
function checkServerJoinRate(userId) {
    const now = Date.now();
    const timestamps = exports.serverJoinRateLimit.get(userId) || [];
    const recent = timestamps.filter(t => now - t < exports.JOIN_RATE_WINDOW);
    if (recent.length >= exports.JOIN_RATE_MAX)
        return false;
    recent.push(now);
    exports.serverJoinRateLimit.set(userId, recent);
    return true;
}
//# sourceMappingURL=rate-limit.js.map