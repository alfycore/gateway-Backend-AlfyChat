"use strict";
// ==========================================
// ALFYCHAT — Block Status Cache
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.isDmBlocked = isDmBlocked;
exports.invalidateBlockCache = invalidateBlockCache;
const env_1 = require("../config/env");
const blockStatusCache = new Map();
const BLOCK_CACHE_TTL = 60_000; // 60 s
function blockCacheKey(u1, u2) {
    const swapped = u1 > u2;
    return { key: swapped ? `${u2}:${u1}` : `${u1}:${u2}`, swapped };
}
/** Check if DM is blocked between two users (cached) */
async function isDmBlocked(senderId, recipientId) {
    const { key, swapped } = blockCacheKey(senderId, recipientId);
    const now = Date.now();
    const cached = blockStatusCache.get(key);
    if (cached && cached.expiresAt > now) {
        return cached.aBlockedB || cached.bBlockedA;
    }
    try {
        const res = await fetch(`${env_1.FRIENDS_URL}/friends/${senderId}/block-status/${recipientId}`, {
            method: 'GET',
        });
        if (!res.ok)
            return false;
        const data = await res.json();
        const aBlockedB = swapped ? !!data.theyBlockedMe : !!data.iBlockedThem;
        const bBlockedA = swapped ? !!data.iBlockedThem : !!data.theyBlockedMe;
        blockStatusCache.set(key, { aBlockedB, bBlockedA, expiresAt: now + BLOCK_CACHE_TTL });
        return aBlockedB || bBlockedA;
    }
    catch {
        return false;
    }
}
/** Invalidate block cache when a block/unblock event occurs */
function invalidateBlockCache(u1, u2) {
    const { key } = blockCacheKey(u1, u2);
    blockStatusCache.delete(key);
}
//# sourceMappingURL=block-cache.js.map