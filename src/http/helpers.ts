// ==========================================
// ALFYCHAT — HTTP Utility Functions
// ==========================================

import express from 'express';
import jwt from 'jsonwebtoken';
import { JWT_SECRET, TRUSTED_PROXIES, IS_DEV, IP_ENDPOINT_RE } from '../config/env';
import { serviceRegistry, ServiceType } from '../utils/service-registry';

/** Extract client IP, trusting X-Forwarded-For only from known proxies */
export function getClientIP(req: express.Request): string {
  const remoteAddr = req.socket.remoteAddress || '0.0.0.0';
  if (TRUSTED_PROXIES.has(remoteAddr)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  }
  return remoteAddr;
}

/** Decode userId from Authorization header (no throw) */
export function extractUserIdFromJWT(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    return decoded.userId || decoded.id || null;
  } catch {
    return null;
  }
}

/** Parse JSON safely — returns null if body is empty or not valid JSON */
export async function safeJson(response: Response): Promise<any> {
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

/**
 * Best-effort service URL via registry. Falls back to env-var URL.
 * In dev, always returns the fallback (.env / localhost).
 */
export function getServiceUrl(serviceType: ServiceType, fallback: string): string {
  if (IS_DEV) return fallback;
  const best = serviceRegistry.selectBest(serviceType);
  if (!best) return fallback;
  const isLocalEndpoint = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(best.endpoint);
  if (isLocalEndpoint || IP_ENDPOINT_RE.test(best.endpoint)) return fallback;
  return best.endpoint;
}

/** Rewrite Express URL for a server-node: /api/servers/:id/X → /X */
export function rewriteNodePath(req: express.Request, serverId: string): string {
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
