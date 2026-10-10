// ==========================================
// ALFYCHAT — WS Message & Join Rate Limiting
// ==========================================
// Les compteurs WebSocket vivaient dans des `Map` locales au process, jamais
// purgées : fuite mémoire lente, et contournement trivial en se reconnectant
// sur une autre instance du gateway. Les limites qui protègent réellement
// (messages) passent désormais par Redis ; les autres restent locales mais
// sont balayées périodiquement.

import { RateLimiterRedis } from 'rate-limiter-flexible';
import { runtime } from './runtime';

// ── Fenêtre glissante en mémoire (secours + limites non critiques) ──────────

interface Window {
  windowMs: number;
  max: number;
  hits: Map<string, number[]>;
}

const windows: Window[] = [];

function createWindow(windowMs: number, max: number): Window {
  const w: Window = { windowMs, max, hits: new Map() };
  windows.push(w);
  return w;
}

function consume(w: Window, key: string): boolean {
  const now = Date.now();
  const recent = (w.hits.get(key) || []).filter((t) => now - t < w.windowMs);
  if (recent.length >= w.max) {
    w.hits.set(key, recent);
    return false;
  }
  recent.push(now);
  w.hits.set(key, recent);
  return true;
}

// Balayage : sans lui, chaque utilisateur ayant écrit une fois gardait une
// entrée à vie dans la Map.
const SWEEP_INTERVAL_MS = 5 * 60_000;
{
  const g = globalThis as any;
  if (g.__gw_rateLimitSweep) clearInterval(g.__gw_rateLimitSweep);
  g.__gw_rateLimitSweep = setInterval(() => {
    const now = Date.now();
    for (const w of windows) {
      for (const [key, timestamps] of w.hits) {
        if (timestamps.length === 0 || now - timestamps[timestamps.length - 1] > w.windowMs) {
          w.hits.delete(key);
        }
      }
    }
  }, SWEEP_INTERVAL_MS);
  (g.__gw_rateLimitSweep as NodeJS.Timeout).unref?.();
}

// ── Messages (Redis — partagé entre instances) ──────────────────────────────

export const MSG_RATE_WINDOW = 10; // secondes
export const MSG_RATE_MAX = 10;    // max 10 messages par fenêtre

let _msgLimiter: RateLimiterRedis | null = null;
const msgFallback = createWindow(MSG_RATE_WINDOW * 1000, MSG_RATE_MAX);

function getMessageLimiter(): RateLimiterRedis | null {
  if (_msgLimiter) return _msgLimiter;
  const client = runtime.redis?.getRawClient?.();
  if (!client) return null;
  _msgLimiter = new RateLimiterRedis({
    storeClient: client,
    keyPrefix: 'rl_ws_msg',
    points: MSG_RATE_MAX,
    duration: MSG_RATE_WINDOW,
  });
  return _msgLimiter;
}

/**
 * Autorise (ou non) un envoi/édition de message pour cet utilisateur.
 * Redis si disponible — sinon repli local, pour ne jamais bloquer le chat
 * si Redis est momentanément indisponible.
 */
export async function checkMessageRate(userId: string): Promise<boolean> {
  const limiter = getMessageLimiter();
  if (!limiter) return consume(msgFallback, userId);
  try {
    await limiter.consume(userId);
    return true;
  } catch (res: any) {
    // `consume` rejette avec un RateLimiterRes quand la limite est atteinte,
    // et avec une vraie Error si Redis est en panne : dans ce cas, laisser passer.
    if (res instanceof Error) return true;
    return false;
  }
}

// ── SERVER_JOIN / SERVER_LEAVE ─────────────────────────────────────────────

export const JOIN_RATE_WINDOW = 60_000;
export const JOIN_RATE_MAX = 5;
const joinWindow = createWindow(JOIN_RATE_WINDOW, JOIN_RATE_MAX);

export function checkServerJoinRate(userId: string): boolean {
  return consume(joinWindow, userId);
}

// ── INVITE_VERIFY — anti-énumération de codes d'invitation ─────────────────

export const INVITE_VERIFY_WINDOW = 60_000;
export const INVITE_VERIFY_MAX = 20;
const inviteWindow = createWindow(INVITE_VERIFY_WINDOW, INVITE_VERIFY_MAX);

export function checkInviteVerifyRate(userId: string): boolean {
  return consume(inviteWindow, userId);
}

// ── Débit par socket (tous événements) ─────────────────────────────────────
// Fenêtre fixe par socket, en mémoire : la socket vit sur une seule instance,
// le compteur aussi. Deux paliers : un plafond général, et un plafond serré
// pour les événements qui déclenchent des appels HTTP coûteux ou notifient
// des tiers.

const SOCKET_WINDOW_MS = 10_000;
const SOCKET_MAX_EVENTS = 150;      // tous événements confondus / 10 s
const SOCKET_MAX_EXPENSIVE = 20;    // événements coûteux / 10 s

const EXPENSIVE_EVENTS = new Set([
  'CALL_INITIATE', 'CALL_INITIATE_GROUP', 'CALL_INITIATE_SERVER', 'CALL_JOIN', 'CALL_ACCEPT',
  'CALL_REJECT', 'CALL_END', 'CALL_REJOIN',
  'FRIEND_REQUEST', 'FRIEND_ACCEPT',
  'GROUP_CREATE', 'GROUP_UPDATE', 'GROUP_DELETE', 'GROUP_LEAVE',
  'INVITE_CREATE', 'INVITE_DELETE', 'INVITE_LIST',
  'GET_BULK_PRESENCE', 'MEMBER_LIST', 'ROLE_LIST',
  'e2ee:history-request', 'e2ee:history-response',
  'DM_ARCHIVE_REQUEST', 'DM_ARCHIVE_PEER_RESPONSE', 'DM_ARCHIVE_CONFIRM', 'DM_ARCHIVE_STATUS',
  'CHANNEL_CREATE', 'CHANNEL_UPDATE', 'CHANNEL_DELETE', 'CHANNEL_PERMS_SET',
  'ROLE_CREATE', 'ROLE_UPDATE', 'ROLE_DELETE', 'MEMBER_UPDATE', 'MEMBER_KICK', 'MEMBER_BAN',
  'SERVER_UPDATE_NODE', 'PROFILE_UPDATE', 'CHANGE_USERNAME', 'SFU_CREATE_TRANSPORT',
]);

interface SocketLike {
  use(fn: (packet: unknown[], next: (err?: Error) => void) => void): unknown;
}

export function attachSocketRateLimit(socket: SocketLike): void {
  let windowStart = Date.now();
  let total = 0;
  let expensive = 0;
  socket.use((packet, next) => {
    const now = Date.now();
    if (now - windowStart > SOCKET_WINDOW_MS) {
      windowStart = now;
      total = 0;
      expensive = 0;
    }
    total++;
    const event = Array.isArray(packet) ? String(packet[0]) : '';
    if (EXPENSIVE_EVENTS.has(event)) expensive++;
    if (total > SOCKET_MAX_EVENTS || expensive > SOCKET_MAX_EXPENSIVE) {
      next(new Error('RATE_LIMITED'));
      return;
    }
    next();
  });
}

// ── Enregistrement de server-node ──────────────────────────────────────────
// Créer un serveur écrit 5 lignes en base : à brider même pour un compte valide.

export const NODE_REGISTER_WINDOW = 10 * 60_000; // 10 min
export const NODE_REGISTER_MAX = 3;
const nodeRegisterWindow = createWindow(NODE_REGISTER_WINDOW, NODE_REGISTER_MAX);

export function checkNodeRegisterRate(userId: string): boolean {
  return consume(nodeRegisterWindow, userId);
}
