// ==========================================
// ALFYCHAT — Service Key Management
// ==========================================

import { randomBytes, createHash } from 'node:crypto';
import { INTERNAL_SECRET } from '../config/env';

/** Map<serviceId, sha256(rawKey)> — loaded from DB at startup */
export const serviceKeyHashes = new Map<string, string>();

/** Blacklist of instances disabled/deleted by an admin */
export const bannedServiceIds = new Set<string>();

/** Whitelist of IDs authorised to register (pre-registered by an admin) */
export const allowedServiceIds = new Set<string>();

/** Generate a unique service key and its SHA-256 hash */
export function generateServiceKey(): { rawKey: string; hash: string } {
  const rawKey = 'sc_' + randomBytes(32).toString('base64url');
  const hash   = createHash('sha256').update(rawKey).digest('hex');
  return { rawKey, hash };
}

/** Validate a service secret against stored hash or INTERNAL_SECRET fallback */
export function validateServiceSecret(id: string, secret: string): boolean {
  const storedHash = serviceKeyHashes.get(id);
  if (storedHash) {
    const provided = createHash('sha256').update(secret).digest('hex');
    return provided === storedHash;
  }
  return secret === INTERNAL_SECRET;
}
