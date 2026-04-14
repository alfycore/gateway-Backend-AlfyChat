// ==========================================
// ALFYCHAT — Block Status Cache
// ==========================================

import { FRIENDS_URL } from '../config/env';

interface BlockCacheEntry {
  aBlockedB: boolean;
  bBlockedA: boolean;
  expiresAt: number;
}

const blockStatusCache = new Map<string, BlockCacheEntry>();
const BLOCK_CACHE_TTL = 60_000; // 60 s

function blockCacheKey(u1: string, u2: string): { key: string; swapped: boolean } {
  const swapped = u1 > u2;
  return { key: swapped ? `${u2}:${u1}` : `${u1}:${u2}`, swapped };
}

/** Check if DM is blocked between two users (cached) */
export async function isDmBlocked(senderId: string, recipientId: string): Promise<boolean> {
  const { key, swapped } = blockCacheKey(senderId, recipientId);
  const now = Date.now();
  const cached = blockStatusCache.get(key);
  if (cached && cached.expiresAt > now) {
    return cached.aBlockedB || cached.bBlockedA;
  }
  try {
    const res = await fetch(`${FRIENDS_URL}/friends/${senderId}/block-status/${recipientId}`, {
      method: 'GET',
    });
    if (!res.ok) return false;
    const data = await res.json() as { iBlockedThem?: boolean; theyBlockedMe?: boolean };
    const aBlockedB = swapped ? !!data.theyBlockedMe : !!data.iBlockedThem;
    const bBlockedA = swapped ? !!data.iBlockedThem : !!data.theyBlockedMe;
    blockStatusCache.set(key, { aBlockedB, bBlockedA, expiresAt: now + BLOCK_CACHE_TTL });
    return aBlockedB || bBlockedA;
  } catch {
    return false;
  }
}

/** Invalidate block cache when a block/unblock event occurs */
export function invalidateBlockCache(u1: string, u2: string) {
  const { key } = blockCacheKey(u1, u2);
  blockStatusCache.delete(key);
}
