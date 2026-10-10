// ==========================================
// ALFYCHAT — HTTP Utility Functions
// ==========================================

import express from 'express';
import jwt from 'jsonwebtoken';
import { createHmac } from 'crypto';
import { JWT_SECRET, TRUSTED_PROXIES, IS_PRODUCTION, INTERNAL_SECRET } from '../config/env';
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

/**
 * En-têtes transmis aux microservices pour leur donner l'IP réelle du client.
 *
 * Sans eux, les services ne voyaient que l'IP du gateway : le limiteur du
 * service users (100 req / 15 min sur /auth) était partagé par TOUTE la
 * plateforme — une centaine d'échecs de connexion bloquaient tout le monde —
 * et l'IP affichée dans « Sessions actives » / la connexion par QR était celle
 * du gateway. L'IP est signée : un appel direct au service ne peut pas la forger.
 */
export function clientIpHeaders(req: express.Request): Record<string, string> {
  const ip = getClientIP(req);
  return {
    'x-client-ip': ip,
    'x-client-ip-sig': createHmac('sha256', INTERNAL_SECRET).update(`client-ip:${ip}`).digest('hex'),
  };
}

/** Decode userId from Authorization header (no throw) */
export function extractUserIdFromJWT(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as any;
    if (decoded?.type && decoded.type !== 'access') return null;
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
 * Chemin de la requête SANS préfixe de version (`/api/v1/x` → `/api/x`).
 *
 * `apiVersionMiddleware` réécrit `req.url` mais pas `req.originalUrl` : le proxy,
 * qui recopiait `originalUrl`, transmettait `/v1/...` aux services — toutes les
 * routes `/api/v1/*` finissaient en 404.
 */
export function apiPath(req: express.Request): string {
  return req.originalUrl.replace(/^\/api\/v\d+(?=\/|\?|$)/i, '/api');
}

/**
 * Résout l'URL d'un service.
 * - Dev / test : retourne directement le fallback (.env / localhost).
 * - Production : retourne l'endpoint du meilleur nœud LB.
 *                Si le LB n'a aucune instance saine → '' (→ 503 côté appelant).
 */
export function getServiceUrl(serviceType: ServiceType, fallback: string): string {
  if (!IS_PRODUCTION) return fallback;
  const best = serviceRegistry.selectBest(serviceType);
  return best?.endpoint ?? '';
}

/** Rewrite Express URL for a server-node: /api/servers/:id/X → /X */
export function rewriteNodePath(req: express.Request, serverId: string): string {
  const original = apiPath(req);
  const fullPath = original.split('?')[0];
  const query = original.includes('?') ? '?' + original.split('?')[1] : '';
  const prefix = `/api/servers/${serverId}`;
  let subPath = fullPath.startsWith(prefix) ? fullPath.slice(prefix.length) : fullPath;

  // /channels/:chId/messages?... → /messages?channelId=:chId&...
  const msgMatch = subPath.match(/^\/channels\/([^/]+)\/messages$/);
  if (msgMatch) {
    const channelId = msgMatch[1];
    const sep = query ? query + '&' : '?';
    return `/messages${sep}channelId=${encodeURIComponent(channelId)}`;
  }

  return (subPath || '/') + query;
}

// ── Fichiers fournis par les utilisateurs ──────────────────────────────────
// Ces fichiers sont re-servis depuis le domaine de l'API. Un document HTML ou
// un script téléversé était renvoyé avec son Content-Type d'origine et sans
// `Content-Disposition` : du HTML/JS exécutable sur le domaine officiel.

const INLINE_SAFE_TYPES = /^(image\/(png|jpe?g|gif|webp|avif)|video\/(mp4|webm|ogg)|audio\/(mpeg|ogg|webm|wav|mp4|x-wav)|application\/pdf)(;|$)/i;

/** Pose des en-têtes de téléchargement sûrs pour un fichier utilisateur. */
export function setSafeFileHeaders(res: express.Response, contentType: string | null | undefined): void {
  const ct = (contentType || 'application/octet-stream').trim();
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox");
  if (INLINE_SAFE_TYPES.test(ct)) {
    res.setHeader('Content-Type', ct);
  } else {
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment');
  }
}

/** Segment de chemin de fichier acceptable (nom de fichier ou dossier, sans `..`). */
export function isSafeFileSegment(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/.test(value) && !value.includes('..');
}
