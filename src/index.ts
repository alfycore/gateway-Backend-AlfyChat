// ==========================================
// ALFYCHAT - GATEWAY WEBSOCKET
// Point d'entrée unique pour toutes les communications temps réel
// ==========================================

import express from 'express';
import path from 'path';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from 'node:crypto';
import { GatewayEvent, GatewayEventType, User } from './types/gateway';
import { logger } from './utils/logger';
import { RedisClient } from './utils/redis';
import { ServiceProxy } from './services/proxy';
import { monitoringDB } from './utils/monitoring-db';
import { serviceRegistry, ServiceType } from './utils/service-registry';
import {
  validateProfile, validateGroupInput, validateServerInput, validateChannelInput, validateChannelReorder,
  validateRoleInput, validateMemberUpdate, validateMessageContent, validateInviteInput,
  validateTags,
} from './utils/validation';
import {
  JWT_SECRET, IS_PRODUCTION, IS_DEV, PORT, allowedOrigins,
  USERS_URL, MESSAGES_URL, FRIENDS_URL, CALLS_URL, SERVERS_URL, BOTS_URL, MEDIA_URL,
  SERVERHOSTING_URL, SUBSCRIPTIONS_URL, INTERNAL_SECRET,
  RATE_LIMIT_ANON, RATE_LIMIT_USER, RATE_LIMIT_ADMIN, RATE_LIMIT_WINDOW,
  RATE_LIMIT_AUTH_POINTS, RATE_LIMIT_AUTH_WINDOW, AUTH_BRUTEFORCE_PATHS, AUTH_BRUTEFORCE_REGEX,
  TRUSTED_PROXIES, IP_ENDPOINT_RE,
} from './config/env';
import {
  getClientIP, extractUserIdFromJWT, safeJson, getServiceUrl, rewriteNodePath,
} from './http/helpers';
import {
  proxyRequest, proxyToNode, proxyToNodeMultipart, proxyMultipartToService, proxyToMedia, proxyRawWebhook,
} from './http/proxy';
import { apiVersionMiddleware } from './http/api-version';
import {
  serviceKeyHashes, bannedServiceIds, allowedServiceIds,
  generateServiceKey, validateServiceSecret,
} from './state/service-keys';
import { requireAdmin } from './monitoring/admin-guard';
import { runMonitoringCycle, MONITORING_INTERVAL_MS } from './monitoring/cycle';
import { anomalyMiddleware, attachAnomalyWsHooks } from './monitoring/anomaly';
import { connectedClients, connectedNodes, voiceChannels, userVoiceChannel, voiceChannelStatus, type VoiceParticipant as VoicePresence } from './state/connections';
import type { VoiceParticipant } from './state/connections';
import { isDmBlocked, invalidateBlockCache } from './state/block-cache';
import { checkMessageRate, checkServerJoinRate, checkInviteVerifyRate, checkNodeRegisterRate, attachSocketRateLimit } from './state/rate-limit';
import { validateNodeEndpoint, deriveNodeSecret, safeSecretEqual } from './utils/node-endpoint';
import { PERM, ALL_PERMS_MASK, KICK_ANY, BAN_ANY } from './utils/permissions';
import { runtime } from './state/runtime';
import { forwardToNode, getNodeSocket } from './services/forward';
import { registerInternalRoutes } from './http/internal.routes';
import { registerLBRoutes } from './http/lb.routes';
import { registerAdminRoutes } from './http/admin.routes';
import { registerSfuHandlers, broadcastQualityUpdate, GROUP_SFU_THRESHOLD } from './handlers/sfu.handler';
import { gatewayRegistry } from './lb/gateway-registry';
import { registerFriendsRoutes } from './http/friends.routes';
import { registerServersRoutes } from './http/servers.routes';
import { registerMediaRoutes } from './http/media.routes';
import { registerHealthRoutes } from './http/health.routes';
import { registerStatsRoutes } from './http/stats.routes';
import { registerBootstrapRoutes } from './http/bootstrap.routes';
import { createAdapter } from '@socket.io/redis-adapter';
import { RateLimiterRedis } from 'rate-limiter-flexible';

const app = express();
const httpServer = createServer(app);

/**
 * Webhooks entrants (POST /api/servers/webhooks/:id/:token) : appelés par des
 * scripts, des CI… et des pages web. Le jeton dans l'URL est le seul secret
 * (comme chez Discord), aucun cookie n'est lu : le CORS y est ouvert à toute
 * origine. Posé AVANT le CORS global, qui refusait le préflight (403).
 */
const WEBHOOK_PATH = /^\/api\/servers\/webhooks\/[^/]+\/[^/]+\/?$/;
app.use((req, res, next) => {
  if (!WEBHOOK_PATH.test(req.path)) return next();
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Expose-Headers', 'Retry-After');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const corsOptions = {
  origin: (origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void) => {
    // Autoriser les requêtes sans origin (apps natives, Postman…)
    if (!origin) return cb(null, true);
    // Autoriser localhost sur n'importe quel port UNIQUEMENT en dev
    // (évite qu'un attaquant local puisse cibler un déploiement prod)
    if (!IS_PRODUCTION && /^http:\/\/localhost(:\d+)?$/.test(origin)) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    // Ne pas passer une Error — Express supprimerait les headers CORS de la réponse.
    // Retourner false déclenche un rejet 403 avec les headers CORS présents.
    cb(null, false);
  },
  credentials: true,
};

// Préflight explicite : doit précéder tous les autres middlewares
app.options('*', cors(corsOptions));
app.use(cors(corsOptions));
// Bloquer explicitement les origines non autorisées APRÈS que cors() a posé les headers
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  const origin = req.headers.origin as string | undefined;
  if (
    origin &&
    IS_PRODUCTION &&
    !allowedOrigins.includes(origin) &&
    !/^http:\/\/localhost(:\d+)?$/.test(origin) &&
    !WEBHOOK_PATH.test(req.path)
  ) {
    logger.warn(`CORS: origine non autorisée — ${origin}`);
    return res.status(403).json({ error: 'Origine non autorisée' });
  }
  next();
});
// Helmet + CSP stricte en prod. Les uploads (media) restent accessibles cross-origin.
app.use(helmet({
  contentSecurityPolicy: IS_PRODUCTION ? {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:", "blob:", "https:"],
      "media-src": ["'self'", "blob:", "https:"],
      "connect-src": ["'self'", "https:", "wss:"],
      "frame-ancestors": ["'none'"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "upgrade-insecure-requests": [],
    },
  } : false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: IS_PRODUCTION ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
}));

// Chemins ambigus refusés d'emblée : segments `.`/`..` (en clair ou encodés) et
// séparateurs encodés. Le proxy recopie l'URL vers les microservices et `fetch`
// normalise les segments `%2e%2e` : `/api/users/%2e%2e/auth/login` atteignait
// le login en contournant le limiteur anti-brute-force, et chaque préfixe
// donnait accès à toutes les routes du service derrière.
app.use((req, res, next) => {
  const rawPath = (req.originalUrl || req.url).split('?')[0];
  if (/%2e|%2f|%5c|\\/i.test(rawPath) || /(^|\/)\.{1,2}(\/|$)/.test(rawPath)) {
    return res.status(400).json({ error: 'Chemin invalide' });
  }
  next();
});

// Versioning API : strip /api/vN → /api, expose req.apiVersion + header X-API-Version.
// Doit s'exécuter avant tout middleware/route dépendant de req.path.
app.use(apiVersionMiddleware);

// ============ RATE LIMITING & IP BAN (HTTP) ============
let redis: RedisClient;

// Limiters rate-limiter-flexible (initialisés après connexion Redis)
let _rlAnon:  RateLimiterRedis | null = null;
let _rlUser:  RateLimiterRedis | null = null;
let _rlAdmin: RateLimiterRedis | null = null;
// Brute-force protection : login / register / 2FA / reset-password — 10 tentatives / 15 min / IP
let _rlAuth:  RateLimiterRedis | null = null;



// Middleware : bloquer les IP bannies
app.use(async (req, res, next) => {
  if (!redis) return next();
  const ip = getClientIP(req);
  try {
    if (await redis.isIPBanned(ip)) {
      logger.warn(`IP bannie bloquée: ${ip} — ${req.method} ${req.path}`);
      return res.status(403).json({ error: 'Accès interdit' });
    }
  } catch {
    // En cas d'erreur Redis, laisser passer
  }
  next();
});

// Middleware : rate limiting HTTP modulaire (anon / user / admin) — rate-limiter-flexible
app.use(async (req, res, next) => {
  if (!_rlAnon) return next(); // attend l'init Redis
  const ip = getClientIP(req);
  let limiter = _rlAnon;
  let limitMax = RATE_LIMIT_ANON;
  let key = ip;
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as any;
      const userId = decoded.userId || decoded.id;
      const role: string = decoded.role || 'user';
      if (userId) {
        key = userId;
        if (role === 'admin' || role === 'moderator') {
          limiter = _rlAdmin!;
          limitMax = RATE_LIMIT_ADMIN;
        } else {
          limiter = _rlUser!;
          limitMax = RATE_LIMIT_USER;
        }
      }
    } catch { /* token invalide → rester sur la limite anon */ }
  }
  try {
    const result = await limiter.consume(key);
    res.setHeader('X-RateLimit-Limit', String(limitMax));
    res.setHeader('X-RateLimit-Remaining', String(result.remainingPoints));
    next();
  } catch (rateLimitRes: any) {
    redis?.incrementRateLimitBlocked().catch(() => {});
    logger.warn(`Rate limit HTTP dépassé: ${key}`);
    const retryAfter = rateLimitRes?.msBeforeNext ? Math.ceil(rateLimitRes.msBeforeNext / 1000) : 1;
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Trop de requêtes, réessayez plus tard' });
  }
});

// Ne pas parser le JSON sur /api/media/* (multipart/form-data) ni les uploads multipart vers les nodes,
// ni sur les webhooks de paiement (la signature porte sur le corps BRUT).
app.use((req, res, next) => {
  if (req.path.startsWith('/api/media')) return next();
  if (req.path.toLowerCase().startsWith('/api/subscriptions/webhooks/')) return next();
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data') && req.path.startsWith('/api/servers/')) return next();
  express.json({ limit: '2mb' })(req, res, next);
});

// Détection d'anomalies : enregistre les stats de chaque requête après la réponse
app.use(anomalyMiddleware);

// ============ ROUTES API REST (PROXY) ============

// ⚠️  Rate limit brute-force dédié sur les endpoints sensibles d'authentification.
// Clé = IP (les attaques viennent rarement d'un compte authentifié).
app.use(async (req, res, next) => {
  if (!_rlAuth) return next();
  if (req.method !== 'POST' && req.method !== 'PATCH' && req.method !== 'PUT') return next();
  // Express route sans tenir compte de la casse ni du `/` final : on normalise
  // de la même façon avant de comparer.
  const p = req.path.toLowerCase().replace(/\/+$/, '');
  const hit =
    AUTH_BRUTEFORCE_PATHS.some((bp) => p === bp || p.startsWith(bp + '/'))
    || AUTH_BRUTEFORCE_REGEX.some((re) => re.test(p));
  if (!hit) return next();
  const ip = getClientIP(req);
  try {
    await _rlAuth.consume(ip);
    next();
  } catch (rateLimitRes: any) {
    redis?.incrementRateLimitBlocked().catch(() => {});
    logger.warn(`Brute-force bloqué sur ${req.path} depuis ${ip}`);
    const retryAfter = rateLimitRes?.msBeforeNext ? Math.ceil(rateLimitRes.msBeforeNext / 1000) : 60;
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Trop de tentatives. Réessayez dans quelques minutes.' });
  }
});

// Routes Auth & Users
app.all('/api/auth/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL, 'users'));
app.all('/api/users/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL, 'users'));
app.all('/api/users', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL, 'users'));
app.all('/api/rgpd/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL, 'users'));

// ============ ROUTE MODULES ============
// Amorçage : doit précéder les proxys génériques.
registerBootstrapRoutes(app);
registerInternalRoutes(app);
registerLBRoutes(app);
registerStatsRoutes(app);

registerAdminRoutes(app);

// Routes Messages
app.all('/api/messages/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/messages', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/conversations/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/conversations', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/archive/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/archive', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/notifications/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
app.all('/api/notifications', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL, 'messages'));
registerFriendsRoutes(app);

// Routes Calls
app.all('/api/calls/*', (req, res) => proxyRequest(getServiceUrl('calls', CALLS_URL), req, res, CALLS_URL, 'calls'));
app.all('/api/calls', (req, res) => proxyRequest(getServiceUrl('calls', CALLS_URL), req, res, CALLS_URL, 'calls'));
// ── Hook claim-admin : après succès, sync le server-node sans restart ──────────
// Doit être déclaré AVANT registerServersRoutes pour prendre la priorité Express.
app.post('/api/servers/:serverId/claim-admin', async (req: express.Request, res: express.Response) => {
  const { serverId } = req.params;
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!isId(serverId)) return res.status(400).json({ error: 'serverId invalide' });
  if (!userId) return res.status(401).json({ error: 'Authentification requise' });
  try {
    const serversBase = getServiceUrl('servers', SERVERS_URL);
    const response = await fetch(`${serversBase}/servers/${serverId}/claim-admin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
      body: JSON.stringify({ ...req.body, userId, ownerId: userId }),
      signal: AbortSignal.timeout(15_000),
    });
    const data = await safeJson(response) ?? { error: 'Réponse vide' };
    if (!response.ok) return res.status(response.status).json(data);

    // Sync le server-node sans bloquer la réponse
    if (userId && connectedNodes.has(serverId)) {
      (async () => {
        try {
          // 1. Mettre à jour ownerId dans serverSelf du node
          await forwardToNode(serverId, 'SERVER_UPDATE', { ownerId: userId }, 5_000);
          // 2. Broadcaster SERVER_UPDATE à tous les clients du serveur
          runtime.io.to(`server:${serverId}`).emit('SERVER_UPDATE', {
            type: 'SERVER_UPDATE',
            payload: { id: serverId, ownerId: userId },
            timestamp: new Date(),
          });
        } catch {
          // Node hors-ligne ou timeout → sera pris en compte au prochain démarrage du node
        }
      })();
    }

    res.json(data);
  } catch (err: any) {
    logger.error({ err }, 'Erreur claim-admin gateway hook:');
    res.status(502).json({ error: 'Service indisponible' });
  }
});

// ── Webhook entrant : débit borné + diffusion en direct ──────────────────────
// Le service servers persiste le message ; il ne parle pas aux sockets, donc
// le message n'apparaissait qu'au rechargement du salon. La passerelle le
// diffuse au salon dès la réponse. Débit : 5 messages / 2 s par webhook
// (l'ordre de grandeur de Discord), au-delà 429 + Retry-After.
const WEBHOOK_BURST = 5;
const WEBHOOK_WINDOW_MS = 2_000;
const webhookHits = new Map<string, number[]>();
app.post('/api/servers/webhooks/:webhookId/:token', async (req: express.Request, res: express.Response) => {
  const { webhookId, token } = req.params;
  if (!isId(webhookId) || !/^[A-Za-z0-9]{16,128}$/.test(token)) {
    return res.status(401).json({ error: 'Webhook invalide', code: 'WEBHOOK_INVALID' });
  }

  const now = Date.now();
  const hits = (webhookHits.get(webhookId) ?? []).filter((t) => now - t < WEBHOOK_WINDOW_MS);
  if (hits.length >= WEBHOOK_BURST) {
    const retryAfterMs = WEBHOOK_WINDOW_MS - (now - hits[0]);
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
    webhookHits.set(webhookId, hits);
    return res.status(429).json({ error: 'Trop de messages — ralentis', code: 'RATE_LIMITED', retryAfterMs });
  }
  hits.push(now);
  webhookHits.set(webhookId, hits);
  if (webhookHits.size > 10_000) webhookHits.clear(); // borne mémoire (fenêtres de 2 s)

  try {
    const base = getServiceUrl('servers', SERVERS_URL);
    const response = await fetch(`${base}/servers/webhooks/${encodeURIComponent(webhookId)}/${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body ?? {}),
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await safeJson(response)) ?? { error: 'Réponse vide' };
    if (!response.ok) return res.status(response.status).json(data);

    const message = data as { serverId?: unknown; channelId?: unknown };
    if (isId(message.serverId) && isId(message.channelId)) {
      runtime.io.to(chRoom(message.serverId, message.channelId)).emit('SERVER_MESSAGE_NEW', {
        type: 'SERVER_MESSAGE_NEW',
        payload: data,
        timestamp: new Date(),
      });
    }
    res.status(201).json(data);
  } catch (err: any) {
    logger.error({ err }, 'Erreur webhook entrant:');
    res.status(502).json({ error: 'Service indisponible' });
  }
});
registerServersRoutes(app);
// Routes OAuth2 (avant /api/bots pour éviter les conflits de pattern)
app.all('/api/oauth2/*', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
app.all('/api/oauth2', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
// Routes Bots
app.all('/api/bots/*', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
app.all('/api/bots', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
// Routes Hébergement serveurs (ServerHosting)
// Corps brut + en-têtes de signature relayés tels quels : réencoder le JSON et
// perdre `stripe-signature` rendait toute vérification de webhook impossible.
app.all('/api/subscriptions/webhooks/*', (req, res) => proxyRawWebhook(SUBSCRIPTIONS_URL, req, res));
app.all('/api/hosting/*', (req, res) => proxyRequest(SERVERHOSTING_URL, req, res));
app.all('/api/hosting', (req, res) => proxyRequest(SERVERHOSTING_URL, req, res));
// Routes Abonnements & Paiements
app.all('/api/subscriptions/plans*', (req, res) => proxyRequest(SUBSCRIPTIONS_URL, req, res));
app.all('/api/subscriptions/checkout/*', (req, res) => proxyRequest(SUBSCRIPTIONS_URL, req, res));
app.all('/api/subscriptions/*', (req, res) => proxyRequest(SUBSCRIPTIONS_URL, req, res));
app.all('/api/subscriptions', (req, res) => proxyRequest(SUBSCRIPTIONS_URL, req, res));
registerMediaRoutes(app);
registerHealthRoutes(app);

// Socket.IO Server
const io = new Server(httpServer, {
  cors: corsOptions,
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Redis pour la synchronisation multi-instances
redis = new RedisClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD,
});

// Populate runtime context so extracted modules can access io / redis
runtime.io = io;
runtime.redis = redis;

// ── Endpoint interne : le media-server notifie le gateway d'un changement de tier qualité ──
// Cet endpoint est appelé par le media-server (pas par les clients WebSocket)
app.post('/internal/call-quality', express.json(), (req, res) => {
  if (!safeSecretEqual(req.headers['x-internal-secret'] as string | undefined, INTERNAL_SECRET)) {
    return res.status(401).json({ error: 'Accès interne requis' });
  }
  const { callId, tier, participantCount, tierParams } = req.body ?? {};
  if (!isId(callId) || tier === undefined) {
    return res.status(400).json({ error: 'callId et tier requis' });
  }
  broadcastQualityUpdate(io, callId, tier, participantCount, tierParams);
  res.json({ success: true });
});

// ── Endpoint interne : le service users applique une sanction en direct ──
// Un ban/kick doit couper la session immédiatement, sans attendre l'expiration du JWT.
app.post('/internal/moderation/enforce', express.json(), (req, res) => {
  if (!safeSecretEqual(req.headers['x-internal-secret'] as string | undefined, INTERNAL_SECRET)) {
    return res.status(401).json({ error: 'Accès interne requis' });
  }
  const { userId, type, reason, expiresAt } = req.body ?? {};
  if (!isUuid(userId) || !type) {
    return res.status(400).json({ error: 'userId et type requis' });
  }

  // Le cache mémoire doit être purgé, sinon un mute mettrait 30 s à s'appliquer
  moderationCache.delete(userId);

  if (type === 'ban' || type === 'kick') {
    io.to(`user:${userId}`).emit('MODERATION_ENFORCED', { type, reason, expiresAt });
    // Laisser le temps à l'event de partir avant de couper les sockets
    setTimeout(() => io.in(`user:${userId}`).disconnectSockets(true), 250);
  } else {
    io.to(`user:${userId}`).emit('MODERATION_ENFORCED', { type, reason, expiresAt });
  }

  logger.warn(`[MODÉRATION] ${type} appliqué en direct sur ${userId}`);
  res.json({ success: true });
});

// ── Endpoint interne : révocation de sessions (changement de mot de passe,
// « déconnecter tous les appareils », réutilisation d'un refresh token). Les
// sockets ouvertes survivaient jusqu'ici à toute révocation.
app.post('/internal/users/disconnect', express.json(), (req, res) => {
  if (!safeSecretEqual(req.headers['x-internal-secret'] as string | undefined, INTERNAL_SECRET)) {
    return res.status(401).json({ error: 'Accès interne requis' });
  }
  const { userId } = req.body ?? {};
  if (!isUuid(userId)) return res.status(400).json({ error: 'userId requis' });
  io.to(`user:${userId}`).emit('SESSION_REVOKED', { reason: 'sessions_revoked' });
  setTimeout(() => io.in(`user:${userId}`).disconnectSockets(true), 250);
  res.json({ success: true });
});

// Adaptateur Redis pour Socket.IO (scaling multi-instances)
const _ioRedisPub = redis.getRawClient();
const _ioRedisSub = _ioRedisPub.duplicate();
io.adapter(createAdapter(_ioRedisPub, _ioRedisSub));
logger.info('Socket.IO: Redis adapter initialisé (multi-instances)');

// Initialisation des rate limiters (rate-limiter-flexible + Redis sliding window)
_rlAnon  = new RateLimiterRedis({ storeClient: redis.getRawClient(), keyPrefix: 'rl_anon',  points: RATE_LIMIT_ANON,  duration: RATE_LIMIT_WINDOW });
_rlUser  = new RateLimiterRedis({ storeClient: redis.getRawClient(), keyPrefix: 'rl_user',  points: RATE_LIMIT_USER,  duration: RATE_LIMIT_WINDOW });
_rlAdmin = new RateLimiterRedis({ storeClient: redis.getRawClient(), keyPrefix: 'rl_admin', points: RATE_LIMIT_ADMIN, duration: RATE_LIMIT_WINDOW });
_rlAuth  = new RateLimiterRedis({ storeClient: redis.getRawClient(), keyPrefix: 'rl_auth',  points: RATE_LIMIT_AUTH_POINTS, duration: RATE_LIMIT_AUTH_WINDOW });
logger.info('Rate limiters initialisés (rate-limiter-flexible)');

// Proxy vers les microservices
const serviceProxy = new ServiceProxy({
  users: process.env.USERS_SERVICE_URL || 'http://localhost:3001',
  messages: process.env.MESSAGES_SERVICE_URL || 'http://localhost:3002',
  friends: process.env.FRIENDS_SERVICE_URL || 'http://localhost:3003',
  calls: process.env.CALLS_SERVICE_URL || 'http://localhost:3004',
  servers: process.env.SERVERS_SERVICE_URL || 'http://localhost:3005',
  bots: process.env.BOTS_SERVICE_URL || 'http://localhost:3006',
  mediaServer: process.env.MEDIA_SERVER_URL || 'http://localhost:3010',
});

// ============ TYPES ============

interface AuthenticatedSocket extends Socket {
  userId?: string;
  sessionId?: string;
  user?: User;
  /** Statut de modération résolu à la connexion (ban déjà refusé ici) */
  moderation?: ModerationStatus;
}

interface ModerationStatus {
  banned: boolean;
  bannedUntil: string | null;
  banReason: string | null;
  muted: boolean;
  mutedUntil: string | null;
  muteReason: string | null;
  warnings: number;
}

// ============ MIDDLEWARE D'AUTHENTIFICATION ============

io.use(async (socket: AuthenticatedSocket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return next(new Error('Token d\'authentification requis'));
    }

    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as { userId: string; type?: string };
    if (!isUuid(decoded?.userId) || (decoded.type && decoded.type !== 'access')) {
      return next(new Error('Token invalide'));
    }

    // Vérifier l'utilisateur et son statut de modération via le service users.
    // Fail-closed : si le statut de modération ne peut pas être lu, la
    // connexion est refusée — sinon une panne du service users suffisait à
    // rouvrir le temps réel à tous les comptes bannis.
    const [user, moderation] = await Promise.all([
      serviceProxy.users.getUser(decoded.userId) as Promise<User | null>,
      serviceProxy.users.getModerationStatus(decoded.userId).catch(() => undefined),
    ]);

    if (!user) {
      return next(new Error('Utilisateur non trouvé'));
    }
    if (moderation === undefined) {
      return next(new Error('Vérification du compte impossible pour le moment. Réessayez dans quelques instants.'));
    }

    // Compte banni → connexion refusée
    if (moderation?.banned) {
      const until = moderation.bannedUntil
        ? ` jusqu'au ${new Date(moderation.bannedUntil).toLocaleString('fr-FR')}`
        : ' définitivement';
      logger.warn(`Connexion WS refusée — compte banni: ${decoded.userId}`);
      const err = new Error(`Ce compte est banni${until}. Motif : ${moderation.banReason ?? 'non précisé'}`);
      (err as any).data = { banned: true, bannedUntil: moderation.bannedUntil };
      return next(err);
    }

    socket.userId = decoded.userId;
    socket.sessionId = uuidv4();
    socket.user = user;
    socket.moderation = moderation ?? undefined;

    // Détection d'anomalies WS — suit les événements non-triviaux après auth
    attachAnomalyWsHooks(socket, decoded.userId);

    // Limitation de débit par socket, tous événements confondus, plus un
    // plafond serré sur les événements coûteux (appels, groupes, invitations,
    // demandes d'ami, présence en masse, E2EE…). Seuls les messages avaient
    // une limite : le reste permettait d'inonder les microservices.
    attachSocketRateLimit(socket);

    next();
  } catch (error) {
    logger.error({ err: error }, 'Erreur d\'authentification WebSocket:');
    next(new Error('Token invalide'));
  }
});

// ============ MODÉRATION — MUTE GLOBAL ============

/** Cache mémoire du statut de modération : évite un appel HTTP par message */
const moderationCache = new Map<string, { status: ModerationStatus | null; fetchedAt: number }>();
const MODERATION_CACHE_TTL = 30_000;

/**
 * Retourne le mute actif d'un utilisateur, ou null s'il peut écrire.
 * Une sanction prise en cours de session s'applique en moins de 30 s.
 */
async function getActiveMute(userId: string): Promise<{ until: string | null; reason: string | null } | null> {
  const cached = moderationCache.get(userId);
  let status = cached?.status ?? null;

  if (!cached || Date.now() - cached.fetchedAt > MODERATION_CACHE_TTL) {
    status = await serviceProxy.users.getModerationStatus(userId).catch(() => cached?.status ?? null);
    moderationCache.set(userId, { status, fetchedAt: Date.now() });
  }

  if (!status?.muted) return null;
  return { until: status.mutedUntil, reason: status.muteReason };
}

/** Message affichable expliquant la réduction au silence */
function muteMessage(mute: { until: string | null; reason: string | null }): string {
  const until = mute.until
    ? `jusqu'au ${new Date(mute.until).toLocaleString('fr-FR')}`
    : 'de façon permanente';
  return `Vous êtes réduit au silence ${until}. Motif : ${mute.reason ?? 'non précisé'}`;
}

// ============ GESTION DES CONNEXIONS ============

/** Plafond de mentions notifiées par message (anti-amplification). */
const MAX_MENTIONS = 20;

/**
 * Envoie les MENTION_NOTIFY aux utilisateurs mentionnés dans un message de salon serveur.
 * - Si l'utilisateur est en ligne → event temps réel
 * - Si hors ligne → DB + Redis (récupéré à la reconnexion via PENDING_PINGS)
 */
async function handleServerMentions(opts: {
  mentionedUserIds: unknown;
  senderId: string;
  senderName: string;
  senderAvatar: string | null;
  channelId: string;
  serverId: string;
  channelName?: string;
  content: string;
}) {
  const { mentionedUserIds, senderId, senderName, senderAvatar, channelId, serverId, channelName, content } = opts;
  // La liste vient du client : identifiants valides, dédupliqués, plafonnés, et
  // limités aux membres du serveur. Sans ce filtre, n'importe qui pouvait
  // notifier (et pousser une notification push à) n'importe quel compte.
  const candidates: string[] = Array.isArray(mentionedUserIds)
    ? [...new Set((mentionedUserIds as unknown[]).filter(isUuid))]
        .filter((id) => id !== senderId)
        .slice(0, MAX_MENTIONS)
    : [];
  if (candidates.length === 0) return;
  const membership = await Promise.all(
    candidates.map((id) => checkServerPermission(id, serverId, PERM.READ).catch(() => false)),
  );
  const ids = candidates.filter((_, i) => membership[i]);
  if (ids.length === 0) return;

  const convKey = `channel:${channelId}`;
  const preview = content?.substring(0, 80) ?? '';

  for (const mentionedId of ids) {
    const mentionPayload = {
      type: 'MENTION_NOTIFY',
      payload: {
        conversationKey: convKey,
        channelId,
        serverId,
        senderId,
        senderName,
        senderAvatar,
        channelName: channelName ?? null,
        preview,
        notificationType: 'mention' as const,
      },
      timestamp: new Date(),
    };
    try {
      const isOnline = await redis.isUserOnline(mentionedId);
      if (isOnline) {
        io.to(`user:${mentionedId}`).emit('MENTION_NOTIFY', mentionPayload);
      } else {
        redis.addPendingPing(mentionedId, convKey, senderName).catch(() => {});
        serviceProxy.messages.saveNotification(mentionedId, convKey, senderName, senderId, 'mention', channelName).catch(() => {});
      }
    } catch { /* ne pas bloquer l'envoi si la vérification échoue */ }
  }
}

/**
 * L'utilisateur participe-t-il à cette conversation ?
 *
 * Les DM ont un identifiant déterministe `dm_<uuidA>_<uuidB>` (triés) : on le
 * décompose et on vérifie l'appartenance exacte — un `includes()` sur la chaîne
 * accepterait un identifiant forgé contenant l'UUID ailleurs. Les groupes sont
 * vérifiés auprès du service messages, avec un cache Redis court : sans lui, un
 * aller-retour HTTP par message annulerait le gain de la livraison optimiste.
 */
const CONV_ACCESS_TTL = 120; // secondes
const DM_ID_RE = /^dm_([0-9a-f-]{36})_([0-9a-f-]{36})$/i;

async function hasConversationAccess(userId: string, conversationId: unknown): Promise<boolean> {
  if (typeof conversationId !== 'string' || !conversationId) return false;

  if (conversationId.startsWith('dm_')) {
    const m = DM_ID_RE.exec(conversationId);
    if (!m) return false;
    return m[1] === userId || m[2] === userId;
  }

  const cacheKey = `convacc:${conversationId}:${userId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached === '1') return true;
    if (cached === '0') return false;
  } catch { /* cache indisponible — on interroge le service */ }

  let allowed = false;
  try {
    allowed = await serviceProxy.messages.isParticipant(conversationId, userId);
  } catch {
    // Échec technique → refuser. Un contrôle qui ne peut pas s'exécuter ne
    // doit jamais laisser passer.
    return false;
  }
  // Les refus sont mis en cache moins longtemps : un ajout à un groupe doit
  // devenir effectif rapidement.
  redis.set(cacheKey, allowed ? '1' : '0', allowed ? CONV_ACCESS_TTL : 10).catch(() => {});
  return allowed;
}

/** Purge le cache d'accès d'une conversation (ajout/retrait de participant). */
function invalidateConversationAccess(conversationId: string, userId?: string): void {
  if (userId) {
    redis.del(`convacc:${conversationId}:${userId}`).catch(() => {});
    return;
  }
  redis.deleteByPattern(`convacc:${conversationId}:*`).catch(() => {});
}

// ── Identifiants venant du client ────────────────────────────────────────────
// Tout identifiant reçu d'un socket est validé AVANT d'être utilisé dans un nom
// de room, une clé Redis ou une URL interne.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

function isId(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

/** Les deux participants d'un identifiant de MP `dm_<a>_<b>`, ou null s'il est mal formé. */
function parseDmId(conversationId: unknown): [string, string] | null {
  if (typeof conversationId !== 'string') return null;
  const m = DM_ID_RE.exec(conversationId);
  return m ? [m[1], m[2]] : null;
}

/** L'autre participant d'un MP, ou null si `userId` n'en fait pas partie. */
function dmPeer(conversationId: unknown, userId: string): string | null {
  const ids = parseDmId(conversationId);
  if (!ids) return null;
  if (ids[0] === userId) return ids[1];
  if (ids[1] === userId) return ids[0];
  return null;
}

function dmIdFor(a: string, b: string): string {
  const [x, y] = [a, b].sort();
  return `dm_${x}_${y}`;
}

/**
 * Room Socket.IO d'un salon de serveur, NAMESPACÉE par serveur.
 *
 * L'ancienne room `channel:<channelId>` était globale : rejoindre le salon d'un
 * autre serveur suffisait à en recevoir les messages (CHANNEL_JOIN ne vérifiait
 * que l'appartenance au serveur passé en paramètre, et un node malveillant
 * pouvait renvoyer des identifiants de salons étrangers dans CHANNEL_LIST).
 * Avec le serverId dans le nom, un salon revendiqué à tort ne reçoit jamais
 * que les diffusions de son propre serveur.
 */
function chRoom(serverId: string, channelId: string): string {
  return `ch:${serverId}:${channelId}`;
}

/**
 * Permissions cumulées d'un utilisateur sur un serveur, via l'endpoint dédié du
 * microservice servers (un entier, calculé en SQL) et mises en cache Redis.
 *
 * Le calcul reposait avant sur trois appels HTTP par vérification — dont un
 * `getServer` qui rapatriait la liste complète des membres jointe à `users`, et
 * un `getMembers` qui la retéléchargeait — soit des milliers de lignes JSON à
 * CHAQUE message envoyé. Le cache est invalidé sur tout changement de rôle ou
 * de membre (voir `invalidateServerPerms`).
 */
const PERM_CACHE_TTL = 60; // secondes

async function getUserPermBits(userId: string, serverId: string): Promise<{ isOwner: boolean; perms: number }> {
  const cacheKey = `perm:${serverId}:${userId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      const parsed = JSON.parse(cached) as { isOwner: boolean; perms: number };
      if (typeof parsed?.perms === 'number') return parsed;
    }
  } catch { /* cache indisponible — on recalcule */ }

  let result: { isOwner: boolean; perms: number } = { isOwner: false, perms: 0 };
  try {
    const raw = await serviceProxy.servers.getMemberPermissions(serverId, userId);
    const perms = Number(raw?.permissions);
    result = {
      isOwner: raw?.isOwner === true,
      perms: Number.isFinite(perms) ? (perms & ALL_PERMS_MASK) : 0,
    };
    if (result.isOwner) result.perms = ALL_PERMS_MASK;
    // ADMIN implique tout.
    if (result.perms & PERM.ADMIN) result.perms = ALL_PERMS_MASK;
  } catch (err) {
    logger.warn({ err }, `getUserPermBits: échec du calcul pour ${userId}@${serverId}`);
    // Échec technique → aucun droit. Un contrôle d'autorisation qui ne peut pas
    // s'exécuter doit refuser, jamais laisser passer.
    return { isOwner: false, perms: 0 };
  }

  redis.set(cacheKey, JSON.stringify(result), PERM_CACHE_TTL).catch(() => {});
  return result;
}

/** Purge le cache de permissions d'un serveur (un membre précis, ou tous). */
function invalidateServerPerms(serverId: string, userId?: string): void {
  if (userId) {
    redis.del(`perm:${serverId}:${userId}`).catch(() => {});
    redis.deleteByPattern(`perm:${serverId}:${userId}:ch:*`).catch(() => {});
    return;
  }
  // Changement de rôle → tous les membres du serveur sont concernés.
  redis.deleteByPattern(`perm:${serverId}:*`).catch(() => {});
}

// ── Confidentialité (préférences du destinataire) ───────────────────────────
// Les réglages « qui peut m'écrire » et « afficher mon statut » étaient
// enregistrés mais jamais appliqués côté serveur.

type DmMode = 'everyone' | 'friends' | 'none';

function normalizeDmMode(value: unknown): DmMode {
  if (value === 'none') return 'none';
  if (value === 'friends' || value === false) return 'friends';
  return 'everyone';
}

const PRIVACY_CACHE_TTL = 60; // secondes

async function getPrivacyPrefs(userId: string): Promise<{ dmMode: DmMode; showOnline: boolean } | null> {
  const cacheKey = `privacy:${userId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);
  } catch { /* cache indisponible */ }
  let prefs: { dmMode: DmMode; showOnline: boolean };
  try {
    const raw: any = await serviceProxy.users.getPreferences(userId);
    prefs = {
      dmMode: normalizeDmMode(raw?.privacyAllowDmMode ?? raw?.privacyAllowDm),
      showOnline: raw?.privacyShowOnline !== false,
    };
  } catch (err: any) {
    // Pas de ligne de préférences = réglages par défaut. Toute autre erreur :
    // on ne sait pas → null, et l'appelant refuse (fail-closed).
    if (err?.statusCode !== 404) return null;
    prefs = { dmMode: 'everyone', showOnline: true };
  }
  redis.set(cacheKey, JSON.stringify(prefs), PRIVACY_CACHE_TTL).catch(() => {});
  return prefs;
}

/** `senderId` peut-il ouvrir/écrire un MP à `recipientId` selon les réglages de ce dernier ? */
async function canDirectMessage(senderId: string, recipientId: string): Promise<boolean> {
  const cacheKey = `dmok:${senderId}:${recipientId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached === '1') return true;
    if (cached === '0') return false;
  } catch { /* cache indisponible */ }
  const prefs = await getPrivacyPrefs(recipientId);
  if (!prefs) return false; // préférences illisibles → refus, non mis en cache
  let allowed: boolean;
  if (prefs.dmMode === 'everyone') allowed = true;
  else if (prefs.dmMode === 'none') allowed = false;
  else {
    const friends = await serviceProxy.friends.getFriends(recipientId).catch(() => [] as any[]);
    allowed = friends.some((f: any) => (f?.id ?? f?.friendId) === senderId);
  }
  redis.set(cacheKey, allowed ? '1' : '0', PRIVACY_CACHE_TTL).catch(() => {});
  return allowed;
}

/** Le statut en ligne de cet utilisateur doit-il être masqué aux autres ? */
async function isPresenceHidden(userId: string): Promise<boolean> {
  const prefs = await getPrivacyPrefs(userId);
  return prefs ? !prefs.showOnline : false;
}

/**
 * Vérifie qu'un utilisateur détient TOUS les bits demandés sur un serveur.
 * Le propriétaire et ADMIN passent tout.
 */
async function checkServerPermission(
  userId: string,
  serverId: string,
  requiredPerms: number,
): Promise<boolean> {
  if (!serverId || !userId) return false;
  const { isOwner, perms } = await getUserPermBits(userId, serverId);
  if (isOwner) return true;
  return (perms & requiredPerms) === requiredPerms;
}

/** Variante « au moins un des bits » — pour les paires historiques KICK/KICK_MEMBERS. */
async function checkServerPermissionAny(
  userId: string,
  serverId: string,
  anyOfPerms: number,
): Promise<boolean> {
  if (!serverId || !userId) return false;
  const { isOwner, perms } = await getUserPermBits(userId, serverId);
  if (isOwner) return true;
  return (perms & anyOfPerms) !== 0;
}

/**
 * Bits d'un membre DANS un salon (surcharges de permissions appliquées).
 * Les serveurs auto-hébergés gèrent leurs surcharges sur leur node : on s'en
 * tient alors aux droits du serveur, comme avant.
 */
async function getChannelPermBits(userId: string, serverId: string, channelId: string): Promise<{ isOwner: boolean; perms: number }> {
  if (!isId(channelId) || connectedNodes.has(serverId)) return getUserPermBits(userId, serverId);
  const cacheKey = `perm:${serverId}:${userId}:ch:${channelId}`;
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      const parsed = JSON.parse(cached) as { isOwner: boolean; perms: number };
      if (typeof parsed?.perms === 'number') return parsed;
    }
  } catch { /* cache indisponible — on recalcule */ }

  let result: { isOwner: boolean; perms: number } = { isOwner: false, perms: 0 };
  try {
    const raw = await serviceProxy.servers.getMemberPermissions(serverId, userId, channelId);
    const perms = Number(raw?.permissions);
    result = { isOwner: raw?.isOwner === true, perms: Number.isFinite(perms) ? (perms & ALL_PERMS_MASK) : 0 };
    if (result.isOwner || (result.perms & PERM.ADMIN)) result.perms = ALL_PERMS_MASK;
  } catch (err) {
    logger.warn({ err }, `getChannelPermBits: échec du calcul pour ${userId}@${serverId}#${channelId}`);
    // Échec technique → aucun droit (fail-closed).
    return { isOwner: false, perms: 0 };
  }
  redis.set(cacheKey, JSON.stringify(result), PERM_CACHE_TTL).catch(() => {});
  return result;
}

/** TOUS les bits demandés, évalués dans le salon. */
async function checkChannelPermission(userId: string, serverId: string, channelId: string, requiredPerms: number): Promise<boolean> {
  if (!serverId || !userId) return false;
  const { isOwner, perms } = await getChannelPermBits(userId, serverId, channelId);
  if (isOwner) return true;
  return (perms & requiredPerms) === requiredPerms;
}

// ── Métadonnées de salon (mode lent, limite vocale) ─────────────────────────
interface ChannelMeta { id: string; type: string; name: string; slowMode: number; userLimit: number }
const channelMetaCache = new Map<string, { at: number; byId: Map<string, ChannelMeta> }>();
const CHANNEL_META_TTL_MS = 30_000;

async function getChannelMeta(serverId: string, channelId: string): Promise<ChannelMeta | null> {
  if (!isId(serverId) || !isId(channelId)) return null;
  let entry = channelMetaCache.get(serverId);
  if (!entry || Date.now() - entry.at > CHANNEL_META_TTL_MS || !entry.byId.has(channelId)) {
    try {
      let list: any[] = [];
      try {
        const result = await forwardToNode(serverId, 'CHANNEL_LIST', {}, 5_000);
        list = result?.channels ?? [];
      } catch {
        list = (await serviceProxy.servers.getServerChannels(serverId)) ?? [];
      }
      entry = {
        at: Date.now(),
        byId: new Map(list.filter((c: any) => isId(c?.id)).map((c: any) => [c.id as string, {
          id: c.id,
          type: String(c.type ?? 'text'),
          name: String(c.name ?? ''),
          slowMode: Math.max(0, Number(c.slowMode ?? c.slow_mode ?? 0) || 0),
          userLimit: Math.max(0, Number(c.userLimit ?? c.user_limit ?? 0) || 0),
        }])),
      };
      channelMetaCache.set(serverId, entry);
    } catch {
      return null;
    }
  }
  return entry.byId.get(channelId) ?? null;
}

function invalidateChannelMeta(serverId: string): void {
  channelMetaCache.delete(serverId);
  redis.del(`nodechans:${serverId}`).catch(() => {});
}

// ── Rooms de salons : recalcul après un changement de permissions ──────────
//
// Les messages d'un salon ne partent qu'aux sockets de sa room. Quand une
// surcharge, un rôle ou les rôles d'un membre changent, la liste des salons
// visibles change : on la recalcule par membre (une requête par membre
// connecté), on ajuste les rooms, puis on demande aux clients de recharger
// leur liste de salons.
const channelResyncTimers = new Map<string, ReturnType<typeof setTimeout>>();

function scheduleChannelResync(serverId: string, onlyUserId?: string): void {
  if (!isId(serverId) || connectedNodes.has(serverId)) return;
  const key = onlyUserId ? `${serverId}:${onlyUserId}` : serverId;
  const previous = channelResyncTimers.get(key);
  if (previous) clearTimeout(previous);
  channelResyncTimers.set(key, setTimeout(() => {
    channelResyncTimers.delete(key);
    resyncChannelRooms(serverId, onlyUserId).catch((err) => logger.warn({ err }, `resyncChannelRooms ${serverId}`));
  }, 400));
}

async function resyncChannelRooms(serverId: string, onlyUserId?: string): Promise<void> {
  const sockets = await io.in(onlyUserId ? `user:${onlyUserId}` : `server:${serverId}`).fetchSockets();
  const byUser = new Map<string, typeof sockets>();
  for (const s of sockets) {
    const uid = (s as any).userId as string | undefined;
    if (!uid || !s.rooms.has(`server:${serverId}`)) continue;
    const list = byUser.get(uid) ?? [];
    list.push(s);
    byUser.set(uid, list);
  }
  const prefix = `ch:${serverId}:`;
  for (const [uid, list] of byUser) {
    let visible: string[];
    try {
      const channels = (await serviceProxy.servers.getServerChannels(serverId, uid)) ?? [];
      visible = channels.map((c: any) => c?.id).filter((id: unknown): id is string => isId(id));
    } catch {
      continue; // en cas d'échec, on ne retire rien
    }
    const wanted = new Set(visible.map((id) => chRoom(serverId, id)));
    for (const s of list) {
      for (const room of s.rooms) if (room.startsWith(prefix) && !wanted.has(room)) s.leave(room);
      for (const room of wanted) if (!s.rooms.has(room)) s.join(room);
    }
  }
  const target = onlyUserId ? `user:${onlyUserId}` : `server:${serverId}`;
  io.to(target).emit('CHANNELS_INVALIDATE', { type: 'CHANNELS_INVALIDATE', payload: { serverId }, timestamp: new Date() });
}

/** Après une écriture de surcharge : caches, rooms et clients. */
function afterOverridesChanged(serverId: string, channelId: string): void {
  invalidateServerPerms(serverId);
  scheduleChannelResync(serverId);
  io.to(`server:${serverId}`).emit('CHANNEL_PERMS_UPDATE', {
    type: 'CHANNEL_PERMS_UPDATE',
    payload: { serverId, channelId },
    timestamp: new Date(),
  });
}

/**
 * Diffuse un salon créé/modifié. Un salon soumis à des surcharges n'est jamais
 * diffusé tel quel à tout le serveur (son nom fuirait) : chacun recharge sa
 * liste filtrée à la place.
 */
async function announceChannel(serverId: string, channel: any, event: 'CHANNEL_CREATE' | 'CHANNEL_UPDATE'): Promise<void> {
  if (!channel?.id) return;
  let restricted = false;
  try {
    const own = await serviceProxy.servers.getChannelOverrides(serverId, channel.id);
    restricted = (own?.overrides?.length ?? 0) > 0;
    if (!restricted && channel.parentId) {
      const parent = await serviceProxy.servers.getChannelOverrides(serverId, channel.parentId);
      restricted = (parent?.overrides?.length ?? 0) > 0;
    }
  } catch {
    restricted = true; // doute → on ne diffuse pas le nom
  }
  if (restricted) {
    scheduleChannelResync(serverId);
    return;
  }
  if (event === 'CHANNEL_CREATE') io.in(`server:${serverId}`).socketsJoin(chRoom(serverId, channel.id));
  io.to(`server:${serverId}`).emit(event, {
    type: event,
    payload: { ...channel, serverId },
    timestamp: new Date(),
  });
}


/**
 * Un modérateur ne peut agir que sur un membre dont les permissions sont
 * incluses dans les siennes : sans cela, un simple modérateur pouvait expulser
 * un administrateur — ou le propriétaire.
 */
async function canActOnMember(actorId: string, targetUserId: string, serverId: string): Promise<boolean> {
  if (actorId === targetUserId) return false;
  const actor = await getUserPermBits(actorId, serverId);
  if (actor.isOwner) return true;
  const target = await getUserPermBits(targetUserId, serverId);
  if (target.isOwner) return false;
  return (target.perms & ~actor.perms) === 0;
}

/** Forme publique d'un participant vocal (sans socketId). */
function publicVoiceParticipant(p: VoicePresence) {
  return {
    userId: p.userId,
    username: p.username,
    displayName: p.displayName ?? p.username,
    avatarUrl: p.avatarUrl,
    muted: p.muted,
    deafened: p.deafened,
    video: Boolean(p.video),
    streaming: Boolean(p.streaming),
    serverMuted: Boolean(p.serverMuted),
    serverDeafened: Boolean(p.serverDeafened),
    joinedAt: p.joinedAt ?? null,
  };
}

/** Diffuse l'état complet d'un salon vocal à tout le serveur (liste des salons). */
function broadcastVoiceState(serverId: string, channelId: string) {
  const participants = voiceChannels.get(channelId);
  io.to(`server:${serverId}`).emit('VOICE_STATE_UPDATE', {
    channelId,
    serverId,
    participants: participants ? Array.from(participants.values()).map(publicVoiceParticipant) : [],
    status: voiceChannelStatus.get(channelId) ?? null,
  });
}

/**
 * Retire un utilisateur de la présence vocale d'un salon. Le statut du salon
 * est éphémère, comme sur Discord : il disparaît quand le salon se vide.
 */
function removeVoiceParticipant(userId: string, channelId: string) {
  const participants = voiceChannels.get(channelId);
  const participant = participants?.get(userId);
  if (!participants || !participant) {
    if (userVoiceChannel.get(userId) === channelId) userVoiceChannel.delete(userId);
    return;
  }
  participants.delete(userId);
  if (userVoiceChannel.get(userId) === channelId) userVoiceChannel.delete(userId);
  io.in(participant.socketId).socketsLeave(`voice:${channelId}`);
  if (participants.size === 0) {
    voiceChannels.delete(channelId);
    voiceChannelStatus.delete(channelId);
  }
  io.to(`voice:${channelId}`).emit('VOICE_USER_LEFT', { channelId, userId });
  broadcastVoiceState(participant.serverId, channelId);
  logger.info(`User ${userId} left voice channel ${channelId}`);
}

/**
 * Retire l'utilisateur de son salon vocal — seulement si c'est CETTE socket qui
 * y est connectée : la fermeture d'un autre onglet ne doit pas le sortir du vocal.
 */
function leaveVoiceChannel(userId: string, socket: AuthenticatedSocket) {
  const channelId = userVoiceChannel.get(userId);
  if (!channelId) return;
  const participant = voiceChannels.get(channelId)?.get(userId);
  if (participant && participant.socketId !== socket.id) return;
  removeVoiceParticipant(userId, channelId);
}

io.on('connection', async (socket: AuthenticatedSocket) => {
  const { userId, sessionId, user } = socket;
  const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
  
  if (!userId || !sessionId || !user) {
    socket.disconnect();
    return;
  }

  // Les gestionnaires ne sont posés qu'après l'initialisation (rooms, présence,
  // notifications). Socket.IO jette sans bruit tout évènement qui n'a pas encore
  // d'écouteur : les premières requêtes du client (infos serveur, salons,
  // membres, état vocal…) se perdaient et n'expiraient qu'au bout de 10 s.
  // Les paquets reçus d'ici là attendent, puis sont distribués normalement.
  let releaseHandlers: () => void = () => {};
  const handlersReady = new Promise<void>((resolve) => { releaseHandlers = resolve; });
  socket.use((_packet, next) => { void handlersReady.then(() => next()); });

  logger.info(`Connexion: ${user.username} (${userId})`);

  // Enregistrer la connexion
  connectedClients.set(socket.id, {
    socketId: socket.id,
    userId,
    sessionId,
    connectedAt: new Date(),
  });

  // Mettre à jour le statut en ligne dans Redis
  await redis.setUserOnline(userId, socket.id);
  
  // Stocker la session
  await redis.setSession(userId, sessionId, {
    socketId: socket.id,
    connectedAt: new Date(),
  });

  // Rejoindre les rooms personnelles
  socket.join(`user:${userId}`);
  
  // Vérifier que le socket a bien rejoint la room
  const userRooms = Array.from(socket.rooms);
  logger.info(`Socket ${socket.id} rooms après join: [${userRooms.join(', ')}]`);

  // Les trois jonctions (MP, groupes, serveurs) sont indépendantes : elles
  // partent en parallèle au lieu de s'enchaîner. La liste d'amis est gardée
  // pour annoncer la présence (elle était masquée par un tableau vide).
  let friendList: any[] = [];

  const joinDmRooms = async () => {
    try {
      const friends = await serviceProxy.friends.getFriends(userId);
      if (friends && Array.isArray(friends)) {
        friendList = friends;
        for (const friend of friends) {
          const sortedIds = [userId, friend.id].sort();
          const dmConversationId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
          socket.join(`conversation:${dmConversationId}`);
        }
      }
    } catch (error) {
      logger.warn({ err: error }, 'Erreur join des rooms DM');
    }
  };

  const joinGroupRooms = async () => {
    try {
      const groupConversations = await serviceProxy.messages.getConversations(userId);
      if (groupConversations && Array.isArray(groupConversations)) {
        let groupCount = 0;
        for (const conv of groupConversations) {
          const convId = conv.id || conv.conversationId;
          if (convId && !String(convId).startsWith('dm_')) {
            socket.join(`conversation:${convId}`);
            groupCount++;
          }
        }
        if (groupCount > 0) logger.info(`${user.username} auto-joined ${groupCount} group conversation rooms`);
      }
    } catch (error) {
      logger.warn({ err: error }, 'Erreur join des rooms de groupe');
    }
  };

  const joinServerRooms = async () => {
    try {
      // ── Chemin rapide : restaurer depuis le cache Redis (évite NOT_A_CHANNEL_MEMBER au redémarrage) ──
      try {
        const cached = await redis.getUserRooms(userId);
        if (cached) {
          for (const sid of cached.serverIds) if (isId(sid)) socket.join(`server:${sid}`);
          // Format courant : "<serverId>:<channelId>". Les anciennes entrées
          // (channelId seul) sont ignorées — le chemin lent les reconstruit.
          for (const key of cached.channelIds) {
            const [sid, cid] = String(key).split(':');
            if (isId(sid) && isId(cid)) socket.join(chRoom(sid, cid));
          }
          logger.info(`${user.username} restored ${cached.serverIds.length} servers + ${cached.channelIds.length} channels from Redis cache`);
        }
      } catch { /* non bloquant */ }

      // ── Chemin lent : rafraîchir depuis les microservices (met à jour le cache) ──
      const userServers = await serviceProxy.servers.getUserServers(userId, token);
      if (userServers && Array.isArray(userServers)) {
        const allServerIds: string[] = [];
        const allChannelIds: string[] = [];

        await Promise.all(userServers.map(async (srv: any) => {
          const sid = srv.id || srv.server_id;
          if (!isId(sid)) return;
          socket.join(`server:${sid}`);
          allServerIds.push(sid);

          // Notifier le node (fire-and-forget, non bloquant)
          forwardToNode(sid, 'MEMBER_JOIN', {
            userId,
            username: user.username,
            displayName: user.displayName || user.username,
            avatarUrl: user.avatarUrl || null,
          }).catch(() => {});

          // Charger les channels (attendu pour éviter la race condition)
          try {
            let channels: any[] = [];
            try {
              // userId : le node ne renvoie que les salons visibles par ce membre.
              const chResult = await forwardToNode(sid, 'CHANNEL_LIST', { userId });
              channels = chResult?.channels || [];
            } catch {
              // Liste filtrée par permissions : un salon privé n'est pas rejoint.
              channels = (await serviceProxy.servers.getServerChannels(sid, userId)) || [];
            }
            for (const ch of channels) {
              if (!isId(ch?.id)) continue;
              socket.join(chRoom(sid, ch.id));
              allChannelIds.push(`${sid}:${ch.id}`);
            }
          } catch { /* ignore */ }
        }));

        // Persister en Redis pour la prochaine reconnexion
        redis.saveUserRooms(userId, allServerIds, allChannelIds).catch(() => {});
        logger.info(`${user.username} auto-joined ${allServerIds.length} server rooms, ${allChannelIds.length} channel rooms`);
      }
    } catch (error) {
      logger.warn({ err: error }, 'Erreur join des rooms serveur');
    }
  };

  await Promise.all([joinDmRooms(), joinGroupRooms(), joinServerRooms()]);

  // Données initiales simplifiées (pour éviter les erreurs 404)
  const servers: any[] = [];
  const friends: any[] = [];
  const conversations: any[] = [];

  // Envoyer l'événement READY
  emitToSocket(socket, 'READY', {
    user,
    sessionId,
    servers,
    friends,
    conversations,
  });

  // Vérifier si un appel est en attente pour cet utilisateur (arrivée tardive < 60s)
  try {
    const pendingCall = await redis.get(`pending_call:user:${userId}`);
    if (pendingCall) {
      const callData = JSON.parse(pendingCall);
      socket.emit('CALL_INCOMING', callData);
      logger.info(`Appel en attente re-émis à l'utilisateur tardif ${userId} (call ${callData?.payload?.id || '?'})`);
    }
  } catch { /* non bloquant */ }

  // Restaurer la présence depuis Redis (survit 24h après déconnexion) ou fallback DB
  const restoredPresence = await redis.getPresence(userId);
  const chosenStatus = restoredPresence?.chosenStatus
    ?? (user.status && user.status !== 'offline' ? user.status : 'online');
  const restoredEmoji = restoredPresence?.emoji ?? null;
  const restoredText = restoredPresence?.text ?? (user as any).customStatus ?? null;

  await redis.setPresence(userId, {
    status: chosenStatus,
    chosenStatus,
    emoji: restoredEmoji,
    text: restoredText,
    lastActivity: Date.now(),
  });

  // Informer la socket connectée de son propre statut restauré
  socket.emit('PRESENCE_RESTORED', {
    type: 'PRESENCE_RESTORED',
    payload: { status: chosenStatus, emoji: restoredEmoji, text: restoredText },
    timestamp: new Date(),
  });

  // Amis, contacts de MP et membres des serveurs en commun.
  broadcastPresenceUpdate(userId, chosenStatus, friendList, restoredText, restoredEmoji);

  // Envoyer les pings en attente (messages reçus hors ligne) — DB + Redis.
  // En arrière-plan : rien n'en dépend pour poser les gestionnaires.
  void (async () => {
  try {
    // 1. Notifications persistantes en DB (source de vérité)
    let dbNotifications: Record<string, { count: number; senderName: string; type?: string; channelName?: string }> = {};
    try {
      dbNotifications = (await serviceProxy.messages.getNotifications(userId, token)) as Record<string, { count: number; senderName: string; type?: string; channelName?: string }>;
    } catch { /* non bloquant */ }

    // 2. Compat. Redis (fusionne avec DB)
    const redisPings = await redis.getPendingPings(userId);
    const merged: Record<string, { count: number; senderName: string; type?: string; channelName?: string }> = { ...redisPings };
    for (const [convId, notif] of Object.entries(dbNotifications)) {
      if (!merged[convId]) {
        merged[convId] = notif;
      } else {
        merged[convId] = {
          count: Math.max(merged[convId].count, notif.count),
          senderName: notif.senderName || merged[convId].senderName,
          // Conserver le type 'mention' si présent (priorité sur 'message')
          type: notif.type === 'mention' ? 'mention' : (merged[convId].type ?? notif.type),
          channelName: notif.channelName || merged[convId].channelName,
        };
      }
    }

    if (Object.keys(merged).length > 0) {
      socket.emit('PENDING_PINGS', {
        type: 'PENDING_PINGS',
        payload: merged,
        timestamp: new Date(),
      });
      // Nettoyer Redis (la DB est purgée via PATCH /notifications/read côté client)
      await redis.clearPendingPings(userId);
    }
  } catch { /* non bloquant */ }
  })();

  // Map des suppressions en attente : messageId → userId
  // Utilisée quand l'utilisateur supprime un message avant que l'écriture DB soit terminée.
  const pendingDeletions = new Map<string, string>();

  // Demandes d'archive DM en attente d'une réponse de pair : requestId → timer.
  // Sans cela, le setTimeout de secours n'était jamais annulé et envoyait
  // systématiquement une réponse « timeout » vide 10 s après CHAQUE demande,
  // écrasant le résultat qu'un pair venait de fournir. Le pair répond depuis sa
  // propre socket (potentiellement une autre instance du gateway) : le marqueur
  // « répondu » passe donc par Redis, la map locale ne sert qu'au nettoyage.
  const pendingArchiveRequests = new Map<string, NodeJS.Timeout>();

  // ============ GESTIONNAIRES D'ÉVÉNEMENTS ============

  // Heartbeat
  socket.on('HEARTBEAT', (data?: { active?: boolean }) => {
    const isActive = data?.active !== false;
    if (isActive) {
      redis.touchActivity(userId).catch(() => {});
      // Si l'utilisateur était passé en auto-idle → restaurer son statut choisi.
      // On restaure dès que l'absence est automatique (autoIdle), ou — pour les
      // anciens enregistrements sans ce flag — quand le choix reste 'online'.
      redis.getPresence(userId).then(async (p) => {
        if (p && p.status === 'idle' && (p.autoIdle || p.chosenStatus === 'online')) {
          const restored = p.chosenStatus && p.chosenStatus !== 'idle' ? p.chosenStatus : 'online';
          await redis.setPresence(userId, { ...p, status: restored, autoIdle: false, lastActivity: Date.now() });
          const restoreFriends = await serviceProxy.friends.getFriends(userId);
          broadcastPresenceUpdate(userId, restored, restoreFriends, p.text, p.emoji);
        }
      }).catch(() => {});
    }
    emitToSocket(socket, 'HEARTBEAT_ACK', { timestamp: Date.now() });
  });

  // Synchronisation de lecture multi-appareils
  // Quand un appareil lit une conversation, on le propage aux autres sessions du même user
  socket.on('MARK_READ', (data: { key?: string }) => {
    const key = data?.key;
    if (!key || typeof key !== 'string') return;
    // Diffuser à tous les autres sockets de cet utilisateur (pas à l'émetteur)
    socket.to(`user:${userId}`).emit('NOTIFICATION_SYNC', { key });
  });

  // Synchronisation des préférences multi-appareils (relay simple)
  socket.on('PREFERENCES_UPDATE', (data: unknown) => {
    socket.to(`user:${userId}`).emit('PREFERENCES_UPDATE', data);
  });

  // Messages
  // Alias historique de `message:send`. Il ne passait ni par le rate limit, ni
  // par le contrôle de mute, ni par le contrôle de blocage : on lui applique
  // désormais les mêmes barrières.
  socket.on('MESSAGE_CREATE', async (data) => {
    try {
      if (!(await checkMessageRate(userId))) {
        emitError(socket, 'MESSAGE_CREATE_ERROR', new Error('RATE_LIMITED'));
        return;
      }
      if (!(await hasConversationAccess(userId, data?.conversationId))) {
        emitError(socket, 'MESSAGE_CREATE_ERROR', new Error('FORBIDDEN'));
        return;
      }
      const mute = await getActiveMute(userId);
      if (mute) {
        emitError(socket, 'MESSAGE_CREATE_ERROR', new Error(muteMessage(mute)));
        return;
      }
      const peer = dmPeer(data?.conversationId, userId);
      if (peer) {
        if (await isDmBlocked(userId, peer)) {
          emitError(socket, 'MESSAGE_CREATE_ERROR', new Error('BLOCKED'));
          return;
        }
        if (!(await canDirectMessage(userId, peer))) {
          emitError(socket, 'MESSAGE_CREATE_ERROR', new Error('DM_NOT_ALLOWED'));
          return;
        }
      }
      const v = validateMessageContent(data?.content, data?.attachments, data?.e2eeType);
      // Charge utile reconstruite champ par champ : le spread de `data`
      // transmettait au service tout ce que le client ajoutait (id imposé…).
      const message = await serviceProxy.messages.createMessage({
        conversationId: data.conversationId,
        content: v.content,
        senderId: userId,
        ...(typeof data.senderContent === 'string' && data.senderContent.length <= 131072 ? { senderContent: data.senderContent } : {}),
        ...(data.e2eeType === 1 || data.e2eeType === 3 ? { e2eeType: data.e2eeType } : {}),
        ...(isUuid(data.replyToId) ? { replyToId: data.replyToId } : {}),
      });

      // Diffuser aux participants
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_CREATE', {
        type: 'MESSAGE_CREATE',
        payload: message,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_CREATE_ERROR', error);
    }
  });

  // Alias pour message:send (compatibilité client) — livraison optimiste <2ms
  socket.on('message:send', async (data) => {
    try {
      // ── Rate limiting (Redis — partagé entre instances du gateway) ──
      if (!(await checkMessageRate(userId))) {
        socket.emit('message:error', { error: 'RATE_LIMITED', message: 'Trop de messages envoyés. Calme-toi !' });
        return;
      }

      // ── Mute global (modération plateforme) ──
      const mute = await getActiveMute(userId);
      if (mute) {
        socket.emit('message:error', { error: 'MUTED', message: muteMessage(mute) });
        return;
      }

      // ── Validation contenu ──
      try {
        const v = validateMessageContent(data?.content, data?.attachments, data?.e2eeType);
        data = { ...data, content: v.content, ...(v.attachments ? { attachments: v.attachments } : {}) };
      } catch (err: any) {
        socket.emit('message:error', { error: 'INVALID', message: err.message });
        return;
      }

      // ── Champs annexes ──
      if (data.senderContent !== undefined && (typeof data.senderContent !== 'string' || data.senderContent.length > 131072)) {
        socket.emit('message:error', { error: 'INVALID', message: 'senderContent invalide' });
        return;
      }
      if (data.replyToId !== undefined && data.replyToId !== null && !isUuid(data.replyToId)) {
        socket.emit('message:error', { error: 'INVALID', message: 'replyToId invalide' });
        return;
      }

      // ── Construire le conversationId ──
      // `recipientId` et `conversationId` étaient indépendants : on pouvait
      // écrire dans une conversation et faire livrer (et notifier en push) le
      // message à un tiers quelconque. Pour un MP, le destinataire est DÉRIVÉ
      // de la conversation, jamais l'inverse.
      let conversationId: string = data.conversationId || data.channelId;
      if (data.recipientId !== undefined && data.recipientId !== null) {
        if (!isUuid(data.recipientId) || data.recipientId === userId) {
          socket.emit('message:error', { error: 'INVALID', message: 'Destinataire invalide' });
          return;
        }
        const expected = dmIdFor(userId, data.recipientId);
        if (conversationId && conversationId !== expected) {
          socket.emit('message:error', { error: 'FORBIDDEN', message: 'Conversation et destinataire incohérents.' });
          return;
        }
        conversationId = expected;
      } else if (typeof conversationId === 'string' && conversationId.startsWith('dm_')) {
        const peer = dmPeer(conversationId, userId);
        if (peer) data = { ...data, recipientId: peer };
      }

      // ── Blocage + confidentialité (MP uniquement) ──
      if (data.recipientId) {
        const blocked = await isDmBlocked(userId, data.recipientId);
        if (blocked) {
          socket.emit('message:error', { error: 'BLOCKED', message: 'Vous ne pouvez pas envoyer de message à cet utilisateur.' });
          return;
        }
        if (!(await canDirectMessage(userId, data.recipientId))) {
          socket.emit('message:error', { error: 'DM_NOT_ALLOWED', message: 'Cet utilisateur n\'accepte pas les messages privés de votre part.' });
          return;
        }
      }

      // ── Contrôle d'accès à la conversation ──
      // `conversationId` vient du client. Sans ce test, un `socket.join()` sur
      // un identifiant arbitraire suffisait à s'abonner à n'importe quel groupe
      // (écoute permanente) et à y diffuser un message forgé — la persistance
      // échouait, mais l'affichage temps réel, lui, partait quand même.
      if (!(await hasConversationAccess(userId, conversationId))) {
        socket.emit('message:error', { error: 'FORBIDDEN', message: 'Vous ne participez pas à cette conversation.' });
        return;
      }

      // ── ÉTAPE 1 : Générer l'ID côté gateway, construire le payload IMMÉDIATEMENT ──
      const messageId = uuidv4();
      const messageForClient = {
        id: messageId,
        conversationId,
        groupId: (!data.recipientId && !conversationId.startsWith('dm_')) ? conversationId : undefined,
        senderId: userId,
        content: data.content,
        senderContent: data.senderContent,
        e2eeType: data.e2eeType,
        recipientId: data.recipientId,
        replyToId: data.replyToId,
        createdAt: new Date().toISOString(),
        isEdited: false,
        reactions: [],
        sender: {
          id: userId,
          username: user.username,
          displayName: user.displayName || user.username,
          avatarUrl: user.avatarUrl || null,
        },
      };

      // ── ÉTAPE 2 : Rejoindre la room et broadcaster AVANT l'écriture DB ──
      socket.join(`conversation:${conversationId}`);
      io.to(`conversation:${conversationId}`).emit('message:new', messageForClient);

      // Filet de sécurité DM : envoyer à user:B UNIQUEMENT si le destinataire
      // n'est PAS déjà dans la conversation room (évite le doublon car l'utilisateur
      // rejoint toutes ses rooms DM au connect).
      if (data.recipientId) {
        const convRoom = io.sockets.adapter.rooms.get(`conversation:${conversationId}`);
        const recipientUserRoom = io.sockets.adapter.rooms.get(`user:${data.recipientId}`);
        let recipientAlreadyInConvRoom = false;
        if (convRoom && recipientUserRoom) {
          for (const sid of recipientUserRoom) {
            if (convRoom.has(sid)) { recipientAlreadyInConvRoom = true; break; }
          }
        }
        if (!recipientAlreadyInConvRoom) {
          io.to(`user:${data.recipientId}`).emit('message:new', messageForClient);
          // Notifier le destinataire qu'une nouvelle conversation existe (sidebar mise à jour sans refresh)
          io.to(`user:${data.recipientId}`).emit('CONVERSATION_CREATE', {
            id: conversationId,
            type: 'dm',
            recipientId: userId,
            recipientName: user.displayName || user.username,
            recipientAvatar: user.avatarUrl || null,
          });

          // Destinataire hors-ligne → push notification
          if (!recipientUserRoom || recipientUserRoom.size === 0) {
            const preview = data.content && !data.content.startsWith('ecdh:')
              ? (data.content.length > 80 ? data.content.slice(0, 80) + '…' : data.content)
              : '📎 Nouveau message';
            serviceProxy.users.sendPushNotification({
              userId: data.recipientId,
              title: user.displayName || user.username,
              body: preview,
              url: `/channels/me/${userId}`,
              type: 'message',
              conversationKey: userId,
            });
          }
        }

        // Filet de sécurité SENDER : envoyer à tous les autres appareils de l'expéditeur
        // (ex: mobile connecté avec le même compte) s'ils ne sont pas déjà dans la room.
        const senderUserRoom = io.sockets.adapter.rooms.get(`user:${userId}`);
        if (senderUserRoom) {
          for (const sid of senderUserRoom) {
            if (sid !== socket.id && !convRoom?.has(sid)) {
              io.to(sid).emit('message:new', messageForClient);
            }
          }
        }
        // Notifier l'expéditeur qu'une conversation existe désormais, pour que
        // SA PROPRE liste de MP se mette à jour sans refresh.
        // L'ancien `senderUserRoom.size > 1` ne le faisait que si un 2e appareil
        // était connecté (ex: mobile) : dans le cas normal — un seul onglet —
        // celui qui vient d'envoyer le tout premier message à quelqu'un ne
        // voyait donc jamais apparaître la conversation dans sa propre sidebar.
        if (senderUserRoom) {
          serviceProxy.users.getUser(data.recipientId).then((recipientUser: any) => {
            io.to(`user:${userId}`).emit('CONVERSATION_CREATE', {
              id: conversationId,
              type: 'dm',
              recipientId: data.recipientId,
              recipientName: recipientUser?.displayName || recipientUser?.username || '',
              recipientAvatar: recipientUser?.avatarUrl || null,
            });
          }).catch(() => {});
        }
      }

      // Groupe hors-ligne → push notification pour chaque participant absent de la room
      if (!data.recipientId && !conversationId.startsWith('dm_')) {
        const convRoom = io.sockets.adapter.rooms.get(`conversation:${conversationId}`);
        const senderName = user.displayName || user.username;
        const preview = data.content && !(data.content as string).startsWith('ecdh:')
          ? ((data.content as string).length > 80 ? (data.content as string).slice(0, 80) + '…' : data.content as string)
          : '📎 Nouveau message';
        serviceProxy.messages.getConversationParticipants(conversationId).then((result: any) => {
          const participants: Array<{ userId: string }> = result?.participants ?? result ?? [];
          for (const p of participants) {
            if (p.userId === userId) continue;
            const participantRoom = io.sockets.adapter.rooms.get(`user:${p.userId}`);
            if (!participantRoom || participantRoom.size === 0) {
              serviceProxy.users.sendPushNotification({
                userId: p.userId,
                title: senderName,
                body: preview,
                url: `/channels/me/${conversationId}`,
                type: 'message',
                conversationKey: conversationId,
              });
            }
          }
        }).catch(() => {});
      }

      // ── ÉTAPE 3 : Confirmer à l'expéditeur IMMÉDIATEMENT ──
      socket.emit('message:sent', { success: true, message: messageForClient });

      // ── ÉTAPE 4 : Écriture DB en arrière-plan (fire-and-forget) ──
      serviceProxy.messages.createMessage({
        id: messageId,
        conversationId,
        content: data.content as string,
        senderId: userId,
        senderContent: data.senderContent as string | undefined,
        e2eeType: data.e2eeType as number | undefined,
        replyToId: data.replyToId as string | undefined,
      }).then(async (message: any) => {
        // Suppression différée : si l'utilisateur a supprimé ce message pendant l'écriture DB,
        // relancer la suppression maintenant que le message est en base.
        if (pendingDeletions.has(messageId)) {
          const deleteUserId = pendingDeletions.get(messageId)!;
          pendingDeletions.delete(messageId);
          serviceProxy.messages.deleteMessage(messageId, deleteUserId).catch(() => {});
        }
        // Archive DM si quota atteint
        if (message?.archiveEvent) {
          io.to(`conversation:${conversationId}`).emit('DM_ARCHIVE_PUSH', {
            type: 'DM_ARCHIVE_PUSH',
            payload: message.archiveEvent,
            timestamp: new Date(),
          });
        }
        // Ping hors ligne (non bloquant) — stocké en DB ET Redis pour persistance
        if (data.recipientId) {
          redis.isUserOnline(data.recipientId as string)
            .then((isOnline: boolean) => {
              if (!isOnline) {
                const senderName = user.displayName || user.username;
                // Redis (compat. legacy)
                redis.addPendingPing(
                  data.recipientId as string,
                  conversationId,
                  senderName,
                ).catch(() => {});
                // DB (persistance durable)
                serviceProxy.messages.saveNotification(
                  data.recipientId as string,
                  conversationId,
                  senderName,
                ).catch(() => {});
              }
            }).catch(() => {});
        }

        // Mentions dans les messages de groupe (@username → mentionedUserIds).
        // Uniquement des participants de la conversation, plafonnées : la
        // liste vient du client et déclenchait des push vers n'importe qui.
        const requestedMentions: string[] = Array.isArray(data.mentionedUserIds)
          ? [...new Set((data.mentionedUserIds as unknown[]).filter(isUuid))]
              .filter((id) => id !== userId)
              .slice(0, MAX_MENTIONS)
          : [];
        let mentionedUserIds: string[] = [];
        if (requestedMentions.length > 0) {
          if (data.recipientId) {
            mentionedUserIds = requestedMentions.filter((id) => id === data.recipientId);
          } else {
            const result: any = await serviceProxy.messages.getConversationParticipants(conversationId).catch(() => null);
            const list: Array<{ userId: string }> = result?.participants ?? (Array.isArray(result) ? result : []);
            const allowed = new Set(list.map((p) => p.userId));
            mentionedUserIds = requestedMentions.filter((id) => allowed.has(id));
          }
        }
        if (mentionedUserIds.length > 0) {
          const senderName = user.displayName || user.username;
          for (const mentionedId of mentionedUserIds) {
            const mentionPayload = {
              type: 'MENTION_NOTIFY',
              payload: {
                conversationId,
                senderId: userId,
                senderName,
                senderAvatar: user.avatarUrl || null,
                preview: (data.content as string)?.substring(0, 80) ?? '',
                notificationType: 'mention' as const,
              },
              timestamp: new Date(),
            };
            redis.isUserOnline(mentionedId).then((isOnline: boolean) => {
              if (isOnline) {
                io.to(`user:${mentionedId}`).emit('MENTION_NOTIFY', mentionPayload);
              } else {
                redis.addPendingPing(mentionedId, conversationId, senderName).catch(() => {});
                serviceProxy.messages.saveNotification(mentionedId, conversationId, senderName, userId, 'mention').catch(() => {});
                serviceProxy.users.sendPushNotification({
                  userId: mentionedId,
                  title: `${senderName} vous a mentionné`,
                  body: mentionPayload.payload.preview || 'Nouvelle mention',
                  url: `/channels/me`,
                  type: 'mention',
                  conversationKey: conversationId,
                });
              }
            }).catch(() => {});
          }
        }
      }).catch((err: Error) => {
        // La DB a échoué : notifier l'expéditeur pour afficher une erreur sur le message
        logger.error({ err, messageId }, 'Échec écriture DB du message');
        // Pas de `err.message` au client : il contenait le corps brut de la
        // réponse du microservice (détails internes).
        socket.emit('message:failed', {
          messageId,
          error: 'Échec de la sauvegarde — veuillez réessayer',
        });
      });

    } catch (error) {
      logger.error({ err: error }, 'Erreur message:send');
      socket.emit('message:error', { error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  socket.on('MESSAGE_UPDATE', async (data) => {
    try {
      if (!(await hasConversationAccess(userId, data?.conversationId))) {
        emitError(socket, 'MESSAGE_UPDATE_ERROR', new Error('FORBIDDEN'));
        return;
      }
      const v = validateMessageContent(data?.content, undefined, data?.e2eeType);
      const message = await serviceProxy.messages.updateMessage(data.messageId, v.content, userId);
      
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_UPDATE', {
        type: 'MESSAGE_UPDATE',
        payload: message,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_UPDATE_ERROR', error);
    }
  });

  // Alias message:edit (compatibilité client)
  socket.on('message:edit', async (data: { messageId: string; content: string; senderContent?: string; e2eeType?: number; conversationId?: string }) => {
    try {
      // ── Rate limiting (même compteur que message:send) ──
      if (!(await checkMessageRate(userId))) {
        socket.emit('message:edit-error', { messageId: data?.messageId, error: 'RATE_LIMITED' });
        return;
      }

      const v = validateMessageContent(data?.content, undefined, data?.e2eeType);
      const updated = await serviceProxy.messages.updateMessage(data.messageId, v.content, userId, data.senderContent, data.e2eeType) as any;
      if (!updated) {
        socket.emit('message:edit-error', { messageId: data.messageId, error: 'Message non trouvé ou non autorisé' });
        return;
      }
      const conversationId = updated.conversationId;
      io.to(`conversation:${conversationId}`).emit('message:edited', {
        messageId: updated.id,
        content: updated.content,
        updatedAt: updated.updatedAt,
        isEdited: true,
      });
    } catch (error) {
      logger.error({ err: error }, 'Erreur édition message');
      socket.emit('message:edit-error', { messageId: data?.messageId, error: error instanceof Error ? error.message : 'Erreur interne' });
    }
  });

  socket.on('MESSAGE_DELETE', async (data) => {
    try {
      if (!(await hasConversationAccess(userId, data?.conversationId))) {
        emitError(socket, 'MESSAGE_DELETE_ERROR', new Error('FORBIDDEN'));
        return;
      }
      await serviceProxy.messages.deleteMessage(data.messageId, userId);
      
      io.to(`conversation:${data.conversationId}`).emit('MESSAGE_DELETE', {
        type: 'MESSAGE_DELETE',
        payload: { messageId: data.messageId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MESSAGE_DELETE_ERROR', error);
    }
  });

  // Alias message:delete (compatibilité client)
  socket.on('message:delete', async (data: { messageId: string; conversationId?: string }) => {
    // La room venait du client et l'event partait quoi qu'il arrive : on
    // pouvait faire disparaître le message d'autrui chez tous les participants
    // d'une conversation à laquelle on n'appartient même pas.
    if (data.conversationId && !(await hasConversationAccess(userId, data.conversationId))) {
      socket.emit('message:error', { error: 'FORBIDDEN' });
      return;
    }
    const room = data.conversationId ? `conversation:${data.conversationId}` : `user:${userId}`;
    try {
      await serviceProxy.messages.deleteMessage(data.messageId, userId);
    } catch (error: any) {
      const status = error?.statusCode as number | undefined;
      if (status === 404) {
        // Message pas encore en base (écriture fire-and-forget en cours) — différer.
        pendingDeletions.set(data.messageId, userId);
        logger.info({ messageId: data.messageId }, 'Suppression différée (message pas encore en base)');
      } else {
        // Service temporairement indisponible après retries — planifier un second essai.
        logger.warn({ messageId: data.messageId, err: error?.message }, 'Suppression échouée, nouvel essai planifié');
        setTimeout(() => {
          serviceProxy.messages.deleteMessage(data.messageId, userId).catch((retryErr) => {
            logger.error({ messageId: data.messageId, err: retryErr?.message }, 'Nouvel essai de suppression échoué');
          });
        }, 3_000);
      }
    }
    // Toujours émettre de façon optimiste — le client a déjà retiré le message localement.
    io.to(room).emit('message:deleted', { messageId: data.messageId });
    socket.emit('message:deleted', { messageId: data.messageId });
  });

  // Rejoindre une conversation (DM ou channel)
  socket.on('conversation:join', async (data) => {
    const { conversationId, recipientId } = data;

    let roomId: string | undefined;

    if (!conversationId && recipientId) {
      // Chemin DM sûr : le room ID est dérivé de userId + recipientId
      if (!isUuid(recipientId)) {
        socket.emit('conversation:join:error', { error: 'Destinataire invalide' });
        return;
      }
      roomId = dmIdFor(userId, recipientId);
    } else if (conversationId) {
      // Vérifier que l'utilisateur est bien participant avant de joindre
      if (typeof conversationId === 'string' && conversationId.startsWith('dm_')) {
        // Décomposition stricte : `includes(userId)` acceptait un identifiant
        // forgé contenant l'UUID n'importe où.
        if (!dmPeer(conversationId, userId)) {
          socket.emit('conversation:join:error', { error: 'Accès non autorisé' });
          return;
        }
        roomId = conversationId;
      } else if (!isId(conversationId)) {
        socket.emit('conversation:join:error', { error: 'Accès non autorisé' });
        return;
      } else {
        // Conversation UUID — vérifier via le service messages
        try {
          const isParticipant = await serviceProxy.messages.isParticipant(conversationId, userId);
          if (!isParticipant) {
            socket.emit('conversation:join:error', { error: 'Accès non autorisé' });
            return;
          }
        } catch {
          socket.emit('conversation:join:error', { error: 'Impossible de vérifier l\'accès' });
          return;
        }
        roomId = conversationId;
      }
    }

    if (roomId) {
      await socket.join(`conversation:${roomId}`);
      socket.emit('conversation:joined', { conversationId: roomId });
      // Informer l'utilisateur d'un appel de groupe actif en cours
      if (!roomId.startsWith('dm_')) {
        try {
          const activeCallRaw = await redis.get(`call:active:group:${roomId}`);
          if (activeCallRaw) {
            socket.emit('CALL_ACTIVE', JSON.parse(activeCallRaw));
          }
        } catch { /* non bloquant */ }
      }
    }
  });

  // ── E2EE history recovery: relay request & response between DM participants ──
  // User A lost keys → asks User B to re-encrypt the conversation history
  //
  // L'identifiant de conversation n'était contrôlé que par `includes(userId)` :
  // un identifiant forgé `dm_<B>_<C>_<attaquant>` passait, et le client de B
  // ré-chiffrait alors tout son historique avec C à destination de
  // l'attaquant. Désormais : identifiant de MP strict, le destinataire est
  // l'AUTRE participant, et une réponse n'est relayée que si une demande
  // correspondante est en attente (marqueur Redis à usage unique).
  const E2EE_HISTORY_TTL = 120; // secondes
  socket.on('e2ee:history-request', async (data: { recipientId?: unknown; conversationId?: unknown }) => {
    const peer = dmPeer(data?.conversationId, userId);
    if (!peer || data?.recipientId !== peer) return;
    if (await isDmBlocked(userId, peer)) return;
    // Vérifier si le destinataire est connecté (même source que le bandeau d'ami)
    const isRecipientOnline = await redis.isUserOnline(peer);
    if (!isRecipientOnline) {
      // Destinataire hors ligne → notifier l'expéditeur immédiatement
      socket.emit('e2ee:history-error', { reason: 'recipient_offline', conversationId: data.conversationId });
      return;
    }
    await redis.set(`e2eehist:${data.conversationId}:${userId}:${peer}`, '1', E2EE_HISTORY_TTL).catch(() => {});
    logger.info(`[E2EE] History request from ${userId} to ${peer} for ${data.conversationId}`);
    io.to(`user:${peer}`).emit('e2ee:history-request', {
      requesterId: userId,
      conversationId: data.conversationId,
    });
  });

  // User B responds with re-encrypted messages
  socket.on('e2ee:history-response', async (data: {
    requesterId?: unknown;
    conversationId?: unknown;
    messages?: unknown;
  }) => {
    const peer = dmPeer(data?.conversationId, userId);
    if (!peer || data?.requesterId !== peer || !Array.isArray(data?.messages)) return;
    // La demande doit exister et n'est honorée qu'une fois.
    const pendingKey = `e2eehist:${data.conversationId}:${peer}:${userId}`;
    const pending = await redis.get(pendingKey).catch(() => null);
    if (!pending) {
      logger.warn(`[E2EE] Réponse d'historique non sollicitée de ${userId} vers ${peer} — ignorée`);
      return;
    }
    await redis.del(pendingKey).catch(() => {});
    // Cap at 500 messages per response to prevent abuse
    const msgs = (data.messages as any[]).slice(0, 500).map((m) => ({
      id: typeof m?.id === 'string' ? m.id : undefined,
      content: typeof m?.content === 'string' ? m.content.slice(0, 131072) : '',
      senderId: m?.senderId === userId || m?.senderId === peer ? m.senderId : userId,
      createdAt: m?.createdAt ?? null,
    })).filter((m) => !!m.id);
    logger.info(`[E2EE] History response from ${userId} to ${peer}: ${msgs.length} messages`);
    io.to(`user:${peer}`).emit('e2ee:history-response', {
      responderId: userId,
      conversationId: data.conversationId,
      messages: msgs,
    });
  });

  // Indicateur de frappe
  socket.on('TYPING_START', async (data) => {
    if (!(await hasConversationAccess(userId, data?.conversationId))) return;
    await redis.setTyping(data.conversationId, userId);
    
    socket.to(`conversation:${data.conversationId}`).emit('TYPING_START', {
      type: 'TYPING_START',
      payload: { userId, conversationId: data.conversationId },
      timestamp: new Date(),
    });
  });

  socket.on('TYPING_STOP', async (data) => {
    if (!(await hasConversationAccess(userId, data?.conversationId))) return;
    await redis.removeTyping(data.conversationId, userId);
    
    socket.to(`conversation:${data.conversationId}`).emit('TYPING_STOP', {
      type: 'TYPING_STOP',
      payload: { userId, conversationId: data.conversationId },
      timestamp: new Date(),
    });
  });

  // Réactions
  socket.on('REACTION_ADD', async (data) => {
    try {
      if (!(await hasConversationAccess(userId, data?.conversationId))) {
        emitError(socket, 'REACTION_ERROR', new Error('FORBIDDEN'));
        return;
      }
      await serviceProxy.messages.addReaction(data.messageId, userId, data.emoji);
      
      io.to(`conversation:${data.conversationId}`).emit('REACTION_ADD', {
        type: 'REACTION_ADD',
        payload: { messageId: data.messageId, userId, emoji: data.emoji },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  socket.on('REACTION_REMOVE', async (data) => {
    try {
      if (!(await hasConversationAccess(userId, data?.conversationId))) {
        emitError(socket, 'REACTION_ERROR', new Error('FORBIDDEN'));
        return;
      }
      await serviceProxy.messages.removeReaction(data.messageId, userId, data.emoji);
      
      io.to(`conversation:${data.conversationId}`).emit('REACTION_REMOVE', {
        type: 'REACTION_REMOVE',
        payload: { messageId: data.messageId, userId, emoji: data.emoji },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  // ============ SYSTÈME HYBRIDE DM - ARCHIVAGE P2P ============

  // Client confirme avoir reçu et stocké les messages archivés
  socket.on('DM_ARCHIVE_CONFIRM', async (data) => {
    try {
      const { conversationId, archiveLogId } = data;
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      
      const result = await serviceProxy.messages.confirmArchive(conversationId, archiveLogId, token);
      
      socket.emit('DM_ARCHIVE_CONFIRM_ACK', {
        type: 'DM_ARCHIVE_CONFIRM_ACK',
        payload: result,
        timestamp: new Date(),
      });

      logger.info(`📦 Confirmation archive DM de ${userId} pour ${conversationId}`);
    } catch (error) {
      emitError(socket, 'DM_ARCHIVE_ERROR', error);
    }
  });

  // Client demande un message archivé (ancien, pas en DB serveur)
  socket.on('DM_ARCHIVE_REQUEST', async (data) => {
    try {
      const { conversationId, messageId, beforeDate } = data ?? {};
      const limit = Math.min(Math.max(Number(data?.limit) || 50, 1), 200);
      // Aucun contrôle auparavant : n'importe quel compte diffusait une demande
      // dans la room d'une conversation tierce, et les clients des
      // participants y répondaient automatiquement avec leurs archives.
      if (!(await hasConversationAccess(userId, conversationId))) {
        emitError(socket, 'DM_ARCHIVE_ERROR', new Error('FORBIDDEN'));
        return;
      }
      if (messageId !== undefined && messageId !== null && !isId(messageId)) {
        emitError(socket, 'DM_ARCHIVE_ERROR', new Error('INVALID_ID'));
        return;
      }
      const requestId = uuidv4();
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      // Demande en attente : seule une réponse à CETTE demande, pour CETTE
      // conversation, sera relayée — et uniquement à son auteur.
      await redis.set(`dmarchreq:${requestId}`, JSON.stringify({ requesterId: userId, conversationId }), 60).catch(() => {});

      // 1. Chercher dans le cache Redis
      if (messageId) {
        const cached = await serviceProxy.messages.getCachedArchivedMessage(messageId, token) as any;
        if (cached?.source === 'cache' && cached.message) {
          socket.emit('DM_ARCHIVE_RESPONSE', {
            type: 'DM_ARCHIVE_RESPONSE',
            payload: {
              conversationId,
              messages: [cached.message],
              fromPeerId: 'server_cache',
              requestId,
            },
            timestamp: new Date(),
          });
          return;
        }
      }

      // 2. Pas en cache → demander aux peers online de cette conversation
      socket.to(`conversation:${conversationId}`).emit('DM_ARCHIVE_PEER_REQUEST', {
        type: 'DM_ARCHIVE_PEER_REQUEST',
        payload: {
          requestId,
          conversationId,
          messageId,
          beforeDate,
          limit: limit || 50,
          requesterId: userId,
        },
        timestamp: new Date(),
      });

      // Timeout: si aucun pair n'a répondu en 10 s, notifier le client
      const archiveTimer = setTimeout(async () => {
        pendingArchiveRequests.delete(requestId);
        const answered = await redis.get(`dmarch:${requestId}`).catch(() => null);
        if (answered) return; // un pair a déjà fourni les messages
        socket.emit('DM_ARCHIVE_RESPONSE', {
          type: 'DM_ARCHIVE_RESPONSE',
          payload: {
            conversationId,
            messages: [],
            fromPeerId: 'timeout',
            requestId,
            error: 'Aucun peer en ligne avec ce message',
          },
          timestamp: new Date(),
        });
      }, 10000);
      pendingArchiveRequests.set(requestId, archiveTimer);

      logger.info(`🔍 Demande archive DM: ${userId} cherche msg dans ${conversationId}`);
    } catch (error) {
      emitError(socket, 'DM_ARCHIVE_ERROR', error);
    }
  });

  // Peer répond avec des messages archivés qu'il possède localement
  socket.on('DM_ARCHIVE_PEER_RESPONSE', async (data) => {
    try {
      const { requestId, messages } = data ?? {};

      // La réponse doit correspondre à une demande en attente : le demandeur et
      // la conversation viennent de cette demande, jamais du payload du pair.
      // Avant, un `requesterId` arbitraire recevait les messages, et un
      // conversationId hors `dm_` n'était pas contrôlé du tout (empoisonnement
      // du cache d'archives).
      if (!isUuid(requestId)) return;
      const pendingRaw = await redis.get(`dmarchreq:${requestId}`).catch(() => null);
      if (!pendingRaw) return;
      let pending: { requesterId: string; conversationId: string };
      try { pending = JSON.parse(pendingRaw); } catch { return; }
      const { requesterId, conversationId } = pending;
      if (requesterId === userId || !(await hasConversationAccess(userId, conversationId))) {
        logger.warn(`DM_ARCHIVE_PEER_RESPONSE rejeté: ${userId} n'est pas participant de ${conversationId}`);
        return;
      }

      // Le pair qui répond n'est pas une source de vérité : on force le
      // senderId sur son identité authentifiée. Le `.map()` précédent portait
      // ce commentaire mais recopiait l'objet à l'identique — la protection
      // annoncée n'existait pas, et ces messages étaient ensuite mis en cache
      // Redis puis servis au demandeur.
      const ARCHIVE_PEER_MAX = 200;
      const sanitizedMessages = (Array.isArray(messages) ? messages : [])
        .slice(0, ARCHIVE_PEER_MAX)
        .map((m: any) => ({
          id: typeof m?.id === 'string' ? m.id : undefined,
          conversationId,
          senderId: userId,
          content: typeof m?.content === 'string' ? m.content.slice(0, 131072) : '',
          createdAt: m?.createdAt ?? null,
        }))
        .filter((m: any) => !!m.id);

      // Mettre en cache Redis les messages récupérés (24h)
      if (sanitizedMessages.length > 0) {
        try {
          await serviceProxy.messages.cacheArchivedMessages(sanitizedMessages);
        } catch (e) {
          logger.warn({ err: e }, 'Erreur cache messages archivés:');
        }
      }

      // Marquer la demande comme servie : le repli « timeout » de l'autre
      // socket (éventuellement sur une autre instance) le lira avant d'émettre.
      if (requestId) await redis.set(`dmarch:${requestId}`, '1', 30).catch(() => {});

      // Renvoyer au client demandeur
      io.to(`user:${requesterId}`).emit('DM_ARCHIVE_RESPONSE', {
        type: 'DM_ARCHIVE_RESPONSE',
        payload: {
          conversationId,
          messages: sanitizedMessages,
          fromPeerId: userId,
          requestId,
        },
        timestamp: new Date(),
      });

      logger.info(`📨 Peer ${userId} a fourni ${sanitizedMessages.length} msg archivés pour ${requesterId}`);
    } catch (error) {
      emitError(socket, 'DM_ARCHIVE_ERROR', error);
    }
  });

  // Client demande le statut d'archive d'une conversation
  socket.on('DM_ARCHIVE_STATUS', async (data) => {
    try {
      const { conversationId } = data;
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      
      const status = await serviceProxy.messages.getArchiveStatus(conversationId, token);
      
      socket.emit('DM_ARCHIVE_STATUS', {
        type: 'DM_ARCHIVE_STATUS',
        payload: status,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'DM_ARCHIVE_ERROR', error);
    }
  });

  // Amis
  socket.on('FRIEND_REQUEST', async (data) => {
    try {
      if (!isUuid(data?.toUserId) || data.toUserId === userId) {
        emitError(socket, 'FRIEND_REQUEST_ERROR', new Error('INVALID_TARGET'));
        return;
      }
      const request = await serviceProxy.friends.sendFriendRequest(userId, data.toUserId, typeof data.message === 'string' ? data.message.slice(0, 200) : undefined);
      
      // Notifier le destinataire
      io.to(`user:${data.toUserId}`).emit('FRIEND_REQUEST', {
        type: 'FRIEND_REQUEST',
        payload: request,
        timestamp: new Date(),
      });
      
      emitToSocket(socket, 'FRIEND_REQUEST_SENT', request);
    } catch (error) {
      emitError(socket, 'FRIEND_REQUEST_ERROR', error);
    }
  });

  socket.on('FRIEND_ACCEPT', async (data) => {
    try {
      const friendship = await serviceProxy.friends.acceptFriendRequest(data.requestId, userId) as { userId: string; friendId: string };
      
      // Notifier les deux utilisateurs
      io.to(`user:${friendship.userId}`).emit('FRIEND_ACCEPT', {
        type: 'FRIEND_ACCEPT',
        payload: friendship,
        timestamp: new Date(),
      });
      io.to(`user:${friendship.friendId}`).emit('FRIEND_ACCEPT', {
        type: 'FRIEND_ACCEPT',
        payload: friendship,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'FRIEND_ACCEPT_ERROR', error);
    }
  });

  // ── Appels ────────────────────────────────────────────────────────────────

  // ── Appel DM 1:1 ──────────────────────────────────────────────────────────
  socket.on('CALL_INITIATE', async (data, callback) => {
    try {
      logger.info(`CALL_INITIATE DM de ${userId} (${user?.username}) vers ${data?.recipientId || '?'} type=${data?.type}`);

      // Aucun contrôle auparavant : on sonnait n'importe quel compte (blocage
      // ignoré) et n'importe quelle room de conversation.
      const callType = data?.type === 'video' ? 'video' : 'voice';
      let conversationId: string | undefined;
      let recipientId: string | undefined;
      if (data?.recipientId !== undefined && data?.recipientId !== null) {
        if (!isUuid(data.recipientId) || data.recipientId === userId) {
          if (typeof callback === 'function') callback({ error: 'INVALID_RECIPIENT' });
          return;
        }
        recipientId = data.recipientId as string;
        conversationId = dmIdFor(userId, recipientId);
      } else if (await hasConversationAccess(userId, data?.conversationId)) {
        conversationId = data.conversationId;
        recipientId = dmPeer(conversationId, userId) ?? undefined;
      } else {
        if (typeof callback === 'function') callback({ error: 'FORBIDDEN' });
        return;
      }
      if (recipientId) {
        if (await isDmBlocked(userId, recipientId) || !(await canDirectMessage(userId, recipientId))) {
          if (typeof callback === 'function') callback({ error: 'CALL_NOT_ALLOWED' });
          return;
        }
      }
      data = { ...data, type: callType, recipientId };

      const call = await serviceProxy.calls.initiateCall({
        type: callType,
        initiatorId: userId,
        conversationId,
        recipientId,
      }) as { id?: string; callId?: string; [key: string]: any };

      const callId = call.id || call.callId || '';
      if (!callId) throw new Error('Calls service returned no call ID');

      socket.join(`call:${callId}`);
      if (typeof callback === 'function') callback({ callId, id: callId });

      const callPayload = {
        callId,
        conversationId,
        initiatorId: userId,
        recipientId: data.recipientId || null,
        callerName: user?.displayName || user?.username,
        callerAvatar: user?.avatarUrl,
        callType: data.type || 'voice',
        isGroup: false,
      };

      const incomingPayload = { type: 'CALL_INCOMING', payload: callPayload, timestamp: new Date() };
      if (data.recipientId) {
        const socketsInRoom = await io.in(`user:${data.recipientId}`).fetchSockets();
        for (const remoteSocket of socketsInRoom) {
          remoteSocket.emit('CALL_INCOMING', incomingPayload);
        }
        try {
          await redis.set(`pending_call:user:${data.recipientId}`, JSON.stringify(incomingPayload), 60);
        } catch { /* non bloquant */ }
      } else if (conversationId) {
        socket.to(`conversation:${conversationId}`).emit('CALL_INCOMING', incomingPayload);
      }

      logger.info(`Appel DM créé: ${callId}`);
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Failed to initiate call' });
    }
  });

  // ── Appel groupe (WebRTC P2P mesh) ────────────────────────────────────────
  socket.on('CALL_INITIATE_GROUP', async (data, callback) => {
    try {
      logger.info(`CALL_INITIATE_GROUP de ${userId} (${user?.username}) channel=${data.channelId} type=${data.type}`);

      if (!data?.channelId) {
        if (typeof callback === 'function') callback({ error: 'channelId requis' });
        return;
      }
      // `channelId` désigne ici une conversation de groupe. Sans contrôle, on
      // sonnait n'importe quel groupe et on écrasait son « appel actif »
      // (call:active:group:*) : les membres rejoignaient ensuite l'appel de
      // l'attaquant.
      if (!(await hasConversationAccess(userId, data.channelId))) {
        if (typeof callback === 'function') callback({ error: 'FORBIDDEN' });
        return;
      }
      data = { ...data, type: data.type === 'video' ? 'video' : 'voice' };

      const groupCall = await serviceProxy.calls.createGroupCall({
        channelId: data.channelId,
        initiatorId: userId,
        type: data.type,
      }) as { id?: string; callId?: string; [key: string]: any };

      const callId = groupCall.id || groupCall.callId || '';
      if (!callId) throw new Error('Calls service returned no call ID');

      socket.join(`call:${callId}`);
      if (typeof callback === 'function') callback({ callId, id: callId });

      const callPayload = {
        callId,
        channelId: data.channelId,
        callType: data.type || 'voice',
        isGroup: true,
        initiatorId: userId,
        callerName: user?.displayName || user?.username,
        callerAvatar: user?.avatarUrl,
      };

      // Notifier tous les membres — channel: pour serveurs, conversation: pour groupes DM
      const incomingGroupPayload = { type: 'CALL_INCOMING', payload: callPayload, timestamp: new Date() };
      socket.to(`conversation:${data.channelId}`).emit('CALL_INCOMING', incomingGroupPayload);

      // Persister l'appel actif pour les membres qui rejoignent après le démarrage
      try {
        await redis.set(`call:active:group:${data.channelId}`, JSON.stringify({ ...callPayload, callCategory: 'group' }), 4 * 3600);
        await redis.set(`call:channel:${callId}`, data.channelId, 4 * 3600);
      } catch { /* non bloquant */ }

      logger.info(`Appel groupe créé: ${callId} channel=${data.channelId}`);
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Failed to initiate group call' });
    }
  });

  // Rejoindre un appel groupe existant (depuis CALL_INCOMING)
  socket.on('CALL_JOIN', async (data, callback) => {
    try {
      const { callId } = data;
      if (!callId) return;

      const call = await serviceProxy.calls.getCall(callId);
      if (!call || call.status === 'ended') {
        if (typeof callback === 'function') callback({ error: 'Appel introuvable ou terminé' });
        return;
      }

      await serviceProxy.calls.joinCall(callId, userId);
      try { await redis.del(`pending_call:user:${userId}`); } catch { /* non bloquant */ }

      // Récupérer les participants déjà dans la room Socket.IO (avec infos utilisateur)
      const socketsInRoom = await io.in(`call:${callId}`).fetchSockets();
      const existingParticipants = socketsInRoom
        .filter((s) => (s as any).userId && (s as any).userId !== userId)
        .map((s) => ({
          userId: (s as any).userId as string,
          userName: (s as any).user?.displayName || (s as any).user?.username || 'Utilisateur',
          userAvatar: (s as any).user?.avatarUrl as string | undefined,
        }));

      socket.join(`call:${callId}`);

      // Vérifier si le groupe franchit le seuil P2P→SFU
      const newCount = socketsInRoom.length + 1; // +1 = ce nouveau participant
      const callCat = (call as any).callCategory || 'group';

      let callMode: 'p2p' | 'sfu' = 'p2p';
      if (callCat === 'server') {
        callMode = 'sfu';
      } else if (callCat === 'group' && newCount > GROUP_SFU_THRESHOLD) {
        callMode = 'sfu';
        // Créer la salle SFU si elle n'existe pas encore
        const currentMode = await redis.get(`call:mode:${callId}`).catch(() => null);
        if (currentMode !== 'sfu') {
          await redis.set(`call:mode:${callId}`, 'sfu', 3600);
          try { await serviceProxy.media.createRoom(callId, 'group'); } catch { /* ok si existe déjà */ }
          // Notifier tous les participants du switch P2P→SFU
          import('./handlers/sfu.handler').then(({ broadcastModeSwitch }) => {
            broadcastModeSwitch(io, callId, 'sfu');
          });
        }
      }

      // Notifier les participants existants qu'un nouveau pair arrive
      socket.to(`call:${callId}`).emit('CALL_PARTICIPANT_JOINED', {
        type: 'CALL_PARTICIPANT_JOINED',
        payload: {
          callId, userId, userName: user?.displayName || user?.username,
          userAvatar: user?.avatarUrl, existingParticipants: [], callMode,
        },
        timestamp: new Date(),
      });

      // Broadcast participant count pour la qualité adaptative
      io.to(`call:${callId}`).emit('CALL_PARTICIPANT_COUNT', {
        type: 'CALL_PARTICIPANT_COUNT',
        payload: { callId, count: newCount },
        timestamp: new Date(),
      });

      // SFU : producteurs déjà publiés dans la salle (micros, caméras, écrans).
      let existingProducers: { producerId: string; userId: string; kind: string }[] = [];
      if (callMode === 'sfu') {
        try {
          const res = await serviceProxy.media.getProducers(callId);
          existingProducers = (res?.producers ?? []).filter((p) => p.userId !== userId);
        } catch {
          // Salle absente (media-server redémarré) : on la recrée, vide.
          await serviceProxy.media.createRoom(callId, callCat === 'server' ? 'server' : 'group').catch(() => {});
        }
      }

      // Confirmer au nouvel arrivant avec la liste des participants existants (pour créer les PCs)
      if (typeof callback === 'function') {
        callback({ callId, existingParticipants, existingProducers, callMode });
      } else {
        socket.emit('CALL_JOIN_ACK', { callId, existingParticipants, existingProducers, callMode });
      }

      logger.info(`${userId} a rejoint l'appel ${callCat} ${callId} (${newCount} participants, mode=${callMode})`);
    } catch (error: any) {
      if (error?.statusCode === 404) {
        socket.emit('CALL_END', { type: 'CALL_END', payload: { callId: data.callId }, timestamp: new Date() });
        if (typeof callback === 'function') callback({ error: 'Appel déjà terminé' });
      } else {
        emitError(socket, 'CALL_ERROR', error);
        if (typeof callback === 'function') callback({ error: 'Failed to join call' });
      }
    }
  });

  socket.on('CALL_ACCEPT', async (data) => {
    try {
      // Idempotency: skip if this user is already in the call room (duplicate accept from another tab)
      const alreadyInRoom = (await io.in(`call:${data.callId}`).fetchSockets())
        .some((s) => (s as any).userId === userId);
      if (alreadyInRoom) {
        socket.join(`call:${data.callId}`);
        return;
      }

      await serviceProxy.calls.joinCall(data.callId, userId);
      try { await redis.del(`pending_call:user:${userId}`); } catch { /* non bloquant */ }

      const socketsInRoom = await io.in(`call:${data.callId}`).fetchSockets();
      const existingParticipants = socketsInRoom
        .filter((s) => (s as any).userId && (s as any).userId !== userId)
        .map((s) => ({
          userId: (s as any).userId as string,
          userName: (s as any).user?.displayName || (s as any).user?.username || 'Utilisateur',
          userAvatar: (s as any).user?.avatarUrl as string | undefined,
        }));

      socket.join(`call:${data.callId}`);

      // Signaler aux participants existants qu'un nouveau pair a rejoint
      socket.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_JOINED', {
        type: 'CALL_PARTICIPANT_JOINED',
        payload: { callId: data.callId, userId, userName: user?.displayName || user?.username, userAvatar: user?.avatarUrl, existingParticipants: [] },
        timestamp: new Date(),
      });

      // Confirmer l'acceptation avec la liste des pairs existants
      io.to(`call:${data.callId}`).emit('CALL_ACCEPT', {
        type: 'CALL_ACCEPT',
        payload: { callId: data.callId, userId, existingParticipants },
        timestamp: new Date(),
      });

      logger.info(`Appel ${data.callId} accepté par ${userId}`);
    } catch (error: any) {
      if (error?.statusCode === 404) {
        // Call was ended before accept arrived — cleanly close on the acceptor's side
        socket.emit('CALL_END', { type: 'CALL_END', payload: { callId: data.callId }, timestamp: new Date() });
      } else {
        emitError(socket, 'CALL_ERROR', error);
      }
    }
  });

  socket.on('CALL_REJECT', async (data) => {
    try {
      await serviceProxy.calls.rejectCall(data.callId, userId);
      try { await redis.del(`pending_call:user:${userId}`); } catch { /* non bloquant */ }
      io.to(`call:${data.callId}`).emit('CALL_REJECT', {
        type: 'CALL_REJECT',
        payload: { callId: data.callId, userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  socket.on('CALL_LEAVE', async (data) => {
    try {
      await serviceProxy.calls.leaveCall(data.callId, userId);
      socket.leave(`call:${data.callId}`);
      // Notifier les autres participants du départ
      io.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_LEFT', {
        type: 'CALL_PARTICIPANT_LEFT',
        payload: { callId: data.callId, userId },
        timestamp: new Date(),
      });
      // Si plus aucun participant dans la room → terminer l'appel
      const remaining = await io.in(`call:${data.callId}`).fetchSockets();
      if (remaining.length === 0) {
        await serviceProxy.calls.endCall(data.callId, userId);
        serviceProxy.media.destroyRoom(data.callId).catch(() => {});
        io.to(`call:${data.callId}`).emit('CALL_END', {
          type: 'CALL_END',
          payload: { callId: data.callId },
          timestamp: new Date(),
        });
        // Nettoyer l'appel actif Redis + notifier les observateurs
        try {
          const channelId = await redis.get(`call:channel:${data.callId}`);
          if (channelId) {
            await redis.del(`call:active:group:${channelId}`);
            await redis.del(`call:channel:${data.callId}`);
            io.to(`conversation:${channelId}`).emit('CALL_ACTIVE_ENDED', { callId: data.callId });
          }
        } catch { /* non bloquant */ }
      }
      logger.info(`${userId} a quitté l'appel ${data.callId}`);
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  socket.on('CALL_END', async (data) => {
    try {
      await serviceProxy.calls.endCall(data.callId, userId);
      io.to(`call:${data.callId}`).emit('CALL_END', {
        type: 'CALL_END',
        payload: { callId: data.callId },
        timestamp: new Date(),
      });
      // Éjecter tous les sockets de la room
      io.socketsLeave(`call:${data.callId}`);
      // Nettoyer l'appel actif Redis + notifier les observateurs
      try {
        const channelId = await redis.get(`call:channel:${data.callId}`);
        if (channelId) {
          await redis.del(`call:active:group:${channelId}`);
          await redis.del(`call:channel:${data.callId}`);
          io.to(`conversation:${channelId}`).emit('CALL_ACTIVE_ENDED', { callId: data.callId });
        }
      } catch { /* non bloquant */ }
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  // WebRTC Signaling — routage ciblé vers targetUserId (ou broadcast si absent)
  //
  // L'émetteur doit lui-même être dans la room de l'appel : sans ce test,
  // n'importe quel compte injectait des offres SDP et des candidats ICE chez
  // n'importe qui, en fournissant simplement un callId et un targetUserId.
  // C'est exactement le contrôle déjà présent sur VOICE_OFFER / VOICE_ANSWER.
  //
  // La cible doit elle aussi être dans l'appel : sinon un participant de
  // n'importe quel appel pouvait pousser des offres SDP chez un tiers. La liste
  // des participants est mise en cache quelques secondes (un échange ICE
  // envoie des dizaines de candidats).
  const callMembersCache = new Map<string, { ids: Set<string>; at: number }>();
  const isUserInCall = async (callId: string, targetId: string): Promise<boolean> => {
    const cached = callMembersCache.get(callId);
    if (cached && Date.now() - cached.at < 5_000 && cached.ids.has(targetId)) return true;
    const sockets = await io.in(`call:${callId}`).fetchSockets();
    const ids = new Set(sockets.map((s) => (s as any).userId as string).filter(Boolean));
    callMembersCache.set(callId, { ids, at: Date.now() });
    return ids.has(targetId);
  };
  const relayWebrtc = async (event: 'WEBRTC_OFFER' | 'WEBRTC_ANSWER' | 'WEBRTC_ICE_CANDIDATE', data: any, payload: Record<string, unknown>) => {
    const callId = data?.callId;
    if (!isId(callId)) return;
    if (!socket.rooms.has(`call:${callId}`)) {
      logger.warn(`${event} refusé : ${userId} n'est pas dans l'appel ${callId}`);
      return;
    }
    let target = `call:${callId}`;
    if (data.targetUserId !== undefined && data.targetUserId !== null) {
      if (!isUuid(data.targetUserId) || !(await isUserInCall(callId, data.targetUserId))) return;
      target = `user:${data.targetUserId}`;
    }
    io.to(target).emit(event, {
      type: event,
      payload: { callId, fromUserId: userId, ...payload },
      timestamp: new Date(),
    });
  };

  socket.on('WEBRTC_OFFER', (data) => { relayWebrtc('WEBRTC_OFFER', data, { offer: data?.offer }).catch(() => {}); });
  socket.on('WEBRTC_ANSWER', (data) => { relayWebrtc('WEBRTC_ANSWER', data, { answer: data?.answer }).catch(() => {}); });
  socket.on('WEBRTC_ICE_CANDIDATE', (data) => { relayWebrtc('WEBRTC_ICE_CANDIDATE', data, { candidate: data?.candidate }).catch(() => {}); });

  // Notifier les autres participants quand un utilisateur start/stop le partage d'écran
  socket.on('CALL_SCREEN_SHARE', (data) => {
    const { callId, active } = data as { callId: string; active: boolean };
    if (!callId || !socket.rooms.has(`call:${callId}`)) return;
    socket.to(`call:${callId}`).emit('CALL_SCREEN_SHARE', {
      type: 'CALL_SCREEN_SHARE',
      payload: { callId, fromUserId: userId, active },
      timestamp: new Date(),
    });
  });

  // Reconnexion à un appel (après perte de connexion WebSocket)
  socket.on('CALL_REJOIN', async (data) => {
    try {
      const { callId } = data;
      if (!callId || typeof callId !== 'string') return;

      // ⚠️  Sécurité : vérifier que l'utilisateur fait bien partie de l'appel
      // avant de lui autoriser de rejoindre la room Socket.IO correspondante.
      // Sans ce check, un attaquant pouvait écouter les ICE candidates d'un
      // appel arbitraire en envoyant simplement un CALL_REJOIN avec son ID.
      const call = await serviceProxy.calls.getCall(callId);
      if (!call || !Array.isArray(call.participants) || !call.participants.includes(userId)) {
        logger.warn(`CALL_REJOIN refusé: ${userId} n'est pas participant de ${callId}`);
        return;
      }
      if (call.status === 'ended') {
        return;
      }

      socket.join(`call:${callId}`);
      // Notifier les autres participants pour relancer la négociation WebRTC
      socket.to(`call:${callId}`).emit('CALL_PEER_RECONNECTED', {
        type: 'CALL_PEER_RECONNECTED',
        payload: { callId, userId },
        timestamp: new Date(),
      });
      logger.info(`${userId} rejoint la room call:${callId} après reconnexion`);
    } catch (error) {
      logger.warn({ err: error }, 'CALL_REJOIN error:');
    }
  });

  // ── Appel serveur/communauté (SFU toujours) ──────────────────────────────────
  socket.on('CALL_INITIATE_SERVER', async (data: {
    channelId: string; serverId: string; type?: string;
  }, callback) => {
    try {
      logger.info(`CALL_INITIATE_SERVER de ${userId} channel=${data.channelId} serveur=${data.serverId}`);

      if (!isId(data?.channelId) || !isId(data?.serverId)) {
        if (typeof callback === 'function') callback({ error: 'channelId et serverId requis' });
        return;
      }

      // Aucun contrôle d'accès auparavant : n'importe quel compte ouvrait un
      // appel dans le salon de n'importe quel serveur.
      if (!(await checkServerPermission(userId, data.serverId, PERM.READ))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }
      // …et le salon doit appartenir à CE serveur : sinon on ouvrait (et on
      // bloquait, via le 409 « appel déjà actif ») le salon vocal d'un autre.
      if (!(await nodeOwnsChannel(data.serverId, data.channelId))) {
        if (typeof callback === 'function') callback({ error: 'CHANNEL_NOT_IN_SERVER' });
        return;
      }
      // Droit de connexion dans CE salon, et limite d'utilisateurs du salon.
      if (!(await checkChannelPermission(userId, data.serverId, data.channelId, PERM.CONNECT))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }
      const voiceMeta = await getChannelMeta(data.serverId, data.channelId);
      const present = voiceChannels.get(data.channelId);
      if (voiceMeta?.userLimit && present && !present.has(userId) && present.size >= voiceMeta.userLimit
        && !(await checkServerPermission(userId, data.serverId, PERM.MOVE_MEMBERS))) {
        if (typeof callback === 'function') callback({ error: 'CHANNEL_FULL', userLimit: voiceMeta.userLimit });
        return;
      }
      data = { ...data, type: data.type === 'video' ? 'video' : 'voice' };

      // Vérifier la limite de participants du serveur.
      // La room interrogée était `call:${serverId}:${channelId}`, que rien ne
      // peuple jamais (les sockets rejoignent `call:${callId}`) : le contrôle
      // retournait donc toujours 0. On compte les participants de l'appel déjà
      // actif sur ce salon, s'il y en a un.
      const limit = await serviceProxy.calls.getServerLimit(data.serverId);
      const activeCallId = await redis.get(`call:channel:active:${data.channelId}`).catch(() => null);
      if (activeCallId) {
        const currentCallSockets = await io.in(`call:${activeCallId}`).fetchSockets();
        if (currentCallSockets.length >= limit) {
          if (typeof callback === 'function') callback({ error: 'CALL_FULL', maxParticipants: limit });
          return;
        }
      }

      let callId: string;
      try {
        const call = await serviceProxy.calls.createServerCall({
          channelId: data.channelId,
          serverId: data.serverId,
          initiatorId: userId,
          type: data.type || 'voice',
        }) as { id: string; callCategory: string };
        callId = call.id;
      } catch (err: any) {
        // 409 : un appel est déjà ouvert sur ce salon. Avant, l'erreur devenait
        // « Impossible de créer l'appel » et personne ne pouvait plus entrer.
        const existingCallId = err?.statusCode === 409 ? existingCallIdOf(err) : null;
        if (!existingCallId) throw err;
        const live = (await io.in(`call:${existingCallId}`).fetchSockets()).length > 0;
        if (live) {
          // Des membres y sont : le client le rejoint (CALL_JOIN, producteurs existants compris).
          if (typeof callback === 'function') callback({ existingCallId });
          return;
        }
        // Appel fantôme (onglet fermé, passerelle redémarrée) : repris à neuf.
        callId = existingCallId;
        await serviceProxy.calls.joinCall(callId, userId).catch(() => {});
        await serviceProxy.media.destroyRoom(callId).catch(() => {});
      }
      socket.join(`call:${callId}`);
      // Mémoriser l'appel actif du salon pour que le plafond de participants
      // s'applique aux suivants.
      await redis.set(`call:channel:active:${data.channelId}`, callId, 4 * 3600).catch(() => {});

      // Créer la salle SFU
      try {
        await serviceProxy.media.createRoom(callId, 'server');
      } catch (sfuErr) {
        logger.error({ err: sfuErr }, 'Impossible de créer la salle SFU pour appel serveur:');
      }

      // Pas de CALL_INCOMING : rejoindre un vocal de serveur ne sonne chez
      // personne. Les membres voient la présence sous le salon (VOICE_STATE_UPDATE) ;
      // l'ancien envoi faisait apparaître un modal « X vous appelle » comme en MP.

      if (typeof callback === 'function') callback({ callId, id: callId });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
      if (typeof callback === 'function') callback({ error: 'Impossible de créer l\'appel serveur' });
    }
  });

  // ── SFU Signaling (relay vers media-server) ────────────────────────────────
  registerSfuHandlers(socket, io, serviceProxy);

  // ============ SERVEURS P2P ============

  socket.on('SERVER_JOIN', async (data) => {
    try {
      if (!checkServerJoinRate(userId)) {
        emitError(socket, 'RATE_LIMITED', { message: 'Trop de join/leave — patientez une minute.' });
        return;
      }
      if (!isId(data?.serverId) || (data.inviteCode !== undefined && data.inviteCode !== null && !isId(data.inviteCode))) {
        emitError(socket, 'SERVER_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }
      // Serveur privé ? Exiger un code d'invite valide.
      // Un user déjà membre peut re-join librement (reconnexion, changement d'onglet).
      try {
        const alreadyMember = await serviceProxy.servers.isMember(data.serverId, userId);
        if (!alreadyMember) {
          const server = await serviceProxy.servers.getServer(data.serverId);
          const isPublic = server?.isPublic ?? server?.is_public ?? false;
          if (!isPublic) {
            const code = data?.inviteCode;
            if (!code) {
              emitError(socket, 'SERVER_ERROR', new Error('INVITE_REQUIRED'));
              return;
            }
            let inviteOk = false;
            try {
              const r = await forwardToNode(data.serverId, 'INVITE_VERIFY', { code });
              inviteOk = !!(r && r.valid !== false && !r.error);
            } catch {
              try {
                const invite = await serviceProxy.servers.resolveInvite(code) as any;
                inviteOk = !!(invite && (invite.serverId === data.serverId || invite.server_id === data.serverId));
              } catch { inviteOk = false; }
            }
            if (!inviteOk) {
              emitError(socket, 'SERVER_ERROR', new Error('INVALID_INVITE'));
              return;
            }
          }
        }
      } catch {
        // Si le check d'accès échoue techniquement, refuser par défaut.
        emitError(socket, 'SERVER_ERROR', new Error('JOIN_CHECK_FAILED'));
        return;
      }
      // Toujours enregistrer dans le microservice (annuaire central). Le code
      // d'invitation est transmis : le service le revalide pour les serveurs
      // privés.
      const member = await serviceProxy.servers.joinServer(data.serverId, userId, data.inviteCode);
      invalidateServerPerms(data.serverId, userId);
      socket.join(`server:${data.serverId}`);

      // Si un node est connecté, lui notifier le join pour sa DB locale
      let defaultChannelId: string | null = null;
      try {
        const nodeResult = await forwardToNode(data.serverId, 'MEMBER_JOIN', {
          userId,
          username: user.username,
          displayName: user.displayName || user.username,
          avatarUrl: user.avatarUrl || null,
        });
        // Le node a déjà broadcasté via NODE_BROADCAST
        // Charger les channels depuis le node
        const chResult = await forwardToNode(data.serverId, 'CHANNEL_LIST', { userId });
        if (chResult?.channels) {
          for (const ch of chResult.channels) {
            if (!isId(ch?.id)) continue;
            socket.join(chRoom(data.serverId, ch.id));
            // Premier salon textuel = salon par défaut pour le message système
            if (!defaultChannelId && (ch.type === 'text' || ch.type === 'announcement')) {
              defaultChannelId = ch.id;
            }
          }
        }

        // Envoyer un message système "X a rejoint le serveur"
        if (defaultChannelId) {
          try {
            await forwardToNode(data.serverId, 'MSG_FORWARD', {
              channelId: defaultChannelId,
              serverId: data.serverId,
              content: `📥 **${user.displayName || user.username}** a rejoint le serveur.`,
              senderId: userId,
              sender: {
                id: userId,
                username: user.username,
                displayName: user.displayName || user.username,
                avatarUrl: user.avatarUrl || null,
              },
              isSystem: true,
            });
          } catch { /* ignore system message error */ }
        }
      } catch {
        // Pas de node → salons visibles depuis le microservice
        try {
          const channels = (await serviceProxy.servers.getServerChannels(data.serverId, userId)) || [];
          for (const channel of channels) {
            if (isId(channel?.id)) socket.join(chRoom(data.serverId, channel.id));
          }
        } catch { /* ignore */ }
        // Broadcast classique
        io.to(`server:${data.serverId}`).emit('MEMBER_JOIN', {
          type: 'MEMBER_JOIN',
          payload: { serverId: data.serverId, member },
          timestamp: new Date(),
        });
      }

      // Notifier TOUS les sockets de l'user (onglets, appareils) → mise à jour liste serveurs
      // C'est indispensable quand le join vient de discover-server (HTTP + SERVER_JOIN socket)
      try {
        const serverInfo = await serviceProxy.servers.getServer(data.serverId);
        io.to(`user:${userId}`).emit('SERVER_JOINED', {
          type: 'SERVER_JOINED',
          payload: {
            id: data.serverId,
            name: serverInfo?.name ?? '',
            iconUrl: serverInfo?.iconUrl ?? serverInfo?.icon_url ?? undefined,
            ownerId: serverInfo?.ownerId ?? serverInfo?.owner_id ?? undefined,
          },
          timestamp: new Date(),
        });
      } catch { /* ne pas bloquer si le fetch server échoue */ }
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // ── SERVER_SELF_JOIN ──────────────────────────────────────────────────────
  // Émis par le client APRÈS un join HTTP (invite-embed, handleJoin).
  // Le gateway :
  //   1. Vérifie la membership
  //   2. Rejoint les rooms socket server + channels
  //   3. Émet SERVER_ADDED à TOUS les sockets de l'user (multi-onglet/appareil)
  socket.on('SERVER_SELF_JOIN', async (data) => {
    try {
      const serverId: string | undefined = data?.serverId;
      if (!isId(serverId)) return;
      if (!checkServerJoinRate(userId)) {
        emitError(socket, 'RATE_LIMITED', { message: 'Trop de join/leave — patientez une minute.' });
        return;
      }

      // Vérifier que l'user est vraiment membre (il vient de rejoindre via HTTP)
      const record = await serviceProxy.servers.getMemberRecord(serverId, userId).catch(() => null);
      if (!record?.isMember) {
        socket.emit('SERVER_ERROR', { type: 'SERVER_ERROR', error: 'NOT_A_MEMBER', serverId });
        return;
      }
      invalidateServerPerms(serverId, userId);

      // Rejoindre les rooms socket (si pas déjà dedans), sur tous les onglets.
      io.in(`user:${userId}`).socketsJoin(`server:${serverId}`);
      const joinedChannels: string[] = [];

      let serverInfo: any = null;
      try {
        // Charger les channels depuis le node
        const chResult = await forwardToNode(serverId, 'CHANNEL_LIST', { userId });
        if (chResult?.channels) {
          for (const ch of chResult.channels) if (isId(ch?.id)) joinedChannels.push(ch.id);
        }
      } catch {
        // Fallback microservice — salons visibles uniquement
        try {
          const channels = (await serviceProxy.servers.getServerChannels(serverId, userId)) || [];
          for (const ch of channels) if (isId(ch?.id)) joinedChannels.push(ch.id);
        } catch { /* ignore */ }
      }
      for (const id of joinedChannels) io.in(`user:${userId}`).socketsJoin(chRoom(serverId, id));

      // Cache des rooms (reconnexion) et diffusion de présence vers ce serveur.
      redis.getUserRooms(userId).then((cached) => {
        if (!cached || cached.serverIds.includes(serverId)) return;
        return redis.saveUserRooms(
          userId,
          [...cached.serverIds, serverId],
          [...cached.channelIds, ...joinedChannels.map((id) => `${serverId}:${id}`)],
        );
      }).catch(() => {});

      // Nouveau membre (arrivé il y a moins de 2 min) : la liste des membres se
      // met à jour chez tout le monde. Un membre existant qui repasse par
      // l'invitation n'est pas réannoncé (ses rôles seraient écrasés).
      const joinedAtMs = record.joinedAt ? new Date(record.joinedAt).getTime() : NaN;
      if (Number.isFinite(joinedAtMs) && Date.now() - joinedAtMs < 120_000 && !connectedNodes.has(serverId)) {
        io.to(`server:${serverId}`).emit('MEMBER_JOIN', {
          type: 'MEMBER_JOIN',
          payload: {
            serverId,
            member: {
              userId,
              username: user.username,
              displayName: user.displayName || user.username,
              avatarUrl: user.avatarUrl || null,
              nickname: record.nickname ?? null,
              roleIds: record.roleIds ?? [],
              joinedAt: record.joinedAt,
              status: 'online',
            },
          },
          timestamp: new Date(),
        });
      }

      // Charger les infos serveur si pas encore disponibles
      if (!serverInfo) {
        try { serverInfo = await serviceProxy.servers.getServer(serverId); } catch { /* ignore */ }
      }

      // Notifier TOUS les sockets de l'user (onglets, appareils) → mise à jour liste serveurs
      io.to(`user:${userId}`).emit('SERVER_JOINED', {
        type: 'SERVER_ADDED',
        payload: {
          id: serverId,
          name: serverInfo?.name ?? data?.name ?? '',
          iconUrl: serverInfo?.iconUrl ?? serverInfo?.icon_url ?? data?.iconUrl ?? undefined,
          ownerId: serverInfo?.ownerId ?? serverInfo?.owner_id ?? undefined,
        },
        timestamp: new Date(),
      });

      logger.info(`${user.username} self-joined server ${serverId} via HTTP → socket rooms updated`);
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  socket.on('SERVER_LEAVE', async (data) => {
    try {
      if (!checkServerJoinRate(userId)) {
        emitError(socket, 'RATE_LIMITED', { message: 'Trop de join/leave — patientez une minute.' });
        return;
      }
      if (!isId(data?.serverId)) return;
      await serviceProxy.servers.leaveServer(data.serverId, userId);
      invalidateServerPerms(data.serverId, userId);
      // Quitter le serveur ET ses salons, sur tous les appareils : sans cela,
      // un membre parti continuait de recevoir les messages en temps réel.
      io.in(`user:${userId}`).socketsLeave(`server:${data.serverId}`);
      const leavePrefix = `ch:${data.serverId}:`;
      for (const s of await io.in(`user:${userId}`).fetchSockets()) {
        for (const room of s.rooms) if (room.startsWith(leavePrefix)) s.leave(room);
      }

      // Notifier le node si connecté (avec retry) — self-leave : actorId = userId
      try {
        await forwardToNode(data.serverId, 'MEMBER_KICK', { userId, actorId: userId, selfLeave: true });
        logger.info(`Member ${userId} removed from node for server ${data.serverId}`);
      } catch (nodeErr: any) {
        logger.warn(`Failed to remove member ${userId} from node for server ${data.serverId}: ${nodeErr?.message}`);
        setTimeout(async () => {
          try {
            await forwardToNode(data.serverId, 'MEMBER_KICK', { userId, actorId: userId, selfLeave: true });
            logger.info(`Retry: member ${userId} removed from node for server ${data.serverId}`);
          } catch {
            logger.warn(`Retry failed: member ${userId} still in node for server ${data.serverId}`);
          }
        }, 500);
      }

      io.to(`server:${data.serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId: data.serverId, userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // ============ MESSAGES SERVEUR (CHANNELS) ============

  socket.on('SERVER_MESSAGE_SEND', async (data) => {
    try {
      const { serverId, channelId } = data ?? {};
      const replyToId = isUuid(data?.replyToId) ? data.replyToId : undefined;
      if (!isId(serverId) || !isId(channelId)) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }
      // Cohérence salon/serveur : la room est namespacée par serveur et n'est
      // rejointe qu'après validation de l'appartenance.
      if (!socket.rooms.has(chRoom(serverId, channelId))) {
        // Fallback : vérifier la membership réelle (résout la race condition au
        // redémarrage) ET que le salon appartient bien à ce serveur — l'ancien
        // repli rejoignait n'importe quel salon de la plateforme.
        const isMember = await serviceProxy.servers.isMember(serverId, userId).catch(() => false);
        if (!isMember || !(await nodeOwnsChannel(serverId, channelId))) {
          emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('NOT_A_CHANNEL_MEMBER'));
          return;
        }
        // Ré-ajouter aux rooms manquantes
        socket.join(`server:${serverId}`);
        socket.join(chRoom(serverId, channelId));
      }
      // READ + SEND dans CE salon (surcharges incluses) — inclut l'appartenance.
      if (!(await checkChannelPermission(userId, serverId, channelId, PERM.READ | PERM.SEND))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      if (Array.isArray(data?.attachments) && data.attachments.length > 0
        && !(await checkChannelPermission(userId, serverId, channelId, PERM.ATTACH_FILES))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('ATTACH_DENIED'));
        return;
      }
      // Mode lent : un message par fenêtre, sauf pour qui gère le salon.
      const slowMeta = await getChannelMeta(serverId, channelId);
      if (slowMeta?.slowMode && slowMeta.slowMode > 0) {
        const exempt = await checkChannelPermission(userId, serverId, channelId, PERM.MANAGE_MESSAGES)
          || await checkChannelPermission(userId, serverId, channelId, PERM.MANAGE_CHANNELS);
        if (!exempt) {
          const slowKey = `slow:${channelId}:${userId}`;
          const until = Number(await redis.get(slowKey).catch(() => null)) || 0;
          if (until > Date.now()) {
            socket.emit('SERVER_MESSAGE_ERROR', { error: 'SLOWMODE', retryAfter: Math.ceil((until - Date.now()) / 1000), channelId });
            return;
          }
          redis.set(slowKey, String(Date.now() + slowMeta.slowMode * 1000), slowMeta.slowMode).catch(() => {});
        }
      }
      // Mute global (modération plateforme) — prime sur les permissions du serveur
      const mute = await getActiveMute(userId);
      if (mute) {
        socket.emit('SERVER_MESSAGE_ERROR', { error: 'MUTED', message: muteMessage(mute) });
        return;
      }
      const v = validateMessageContent(data?.content, data?.attachments, data?.e2eeType);
      const cleanTags = validateTags(data?.tags);
      const content = v.content;
      const attachments = v.attachments;
      const tags = cleanTags;

      // AutoMod : les règles du serveur s'appliquent à tous sauf aux
      // modérateurs (gérer les messages / le serveur), comme sur Discord.
      if (content && !connectedNodes.has(serverId)) {
        const exempt = await checkServerPermissionAny(userId, serverId, PERM.MANAGE_MESSAGES | PERM.MANAGE_SERVER);
        if (!exempt) {
          const verdict = await serviceProxy.servers.automodCheck(serverId, content, userId).catch(() => null);
          if (verdict?.blocked) {
            socket.emit('SERVER_MESSAGE_ERROR', { error: 'AUTOMOD_BLOCKED', reason: verdict.reason, channelId });
            return;
          }
        }
      }

      // Forward au server-node si connecté (avec callback)
      try {
        const result = await forwardToNode(serverId, 'MSG_FORWARD', {
          channelId,
          serverId,
          content,
          attachments,
          replyToId,
          tags,
          senderId: userId,
          sender: {
            id: userId,
            username: user.username,
            displayName: user.displayName || user.username,
            avatarUrl: user.avatarUrl || null,
          },
        });
        // Le node broadcast via NODE_BROADCAST → sera envoyé aux rooms automatiquement
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE' && e.message !== 'NODE_TIMEOUT') {
          emitError(socket, 'SERVER_MESSAGE_ERROR', e);
          return;
        }
      }

      // Fallback: pas de node connecté → microservice servers
      const message = await serviceProxy.servers.createServerMessage(serverId, channelId, {
        senderId: userId,
        content,
        attachments,
        replyToId,
        tags,
      });

      io.to(chRoom(serverId, channelId)).emit('SERVER_MESSAGE_NEW', {
        type: 'SERVER_MESSAGE_NEW',
        payload: message,
        timestamp: new Date(),
      });

      // Mentions dans les messages serveur
      await handleServerMentions({
        mentionedUserIds: data.mentionedUserIds,
        senderId: userId,
        senderName: user.displayName || user.username,
        senderAvatar: user.avatarUrl || null,
        channelId,
        serverId,
        channelName: data.channelName,
        content: data.content as string,
      });
    } catch (error) {
      emitError(socket, 'SERVER_MESSAGE_ERROR', error);
    }
  });

  socket.on('SERVER_MESSAGE_EDIT', async (data) => {
    try {
      const v = validateMessageContent(data?.content, undefined, data?.e2eeType);
      const { serverId, messageId, channelId } = data ?? {};
      const content = v.content;
      if (!isId(serverId) || !isId(messageId) || !isId(channelId) || !(await nodeOwnsChannel(serverId, channelId))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }

      // L'édition ne vérifiait RIEN côté gateway. L'auteur est vérifié par le
      // node / le microservice (l'appel porte désormais x-user-id).
      if (!(await checkServerPermission(userId, serverId, PERM.SEND))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }

      // Forward au server-node si connecté
      try {
        await forwardToNode(serverId, 'MSG_EDIT', {
          messageId, content, channelId, userId,
        });
        // Le node broadcast via NODE_BROADCAST
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE' && e.message !== 'NODE_TIMEOUT') { emitError(socket, 'SERVER_MESSAGE_ERROR', e); return; }
      }

      // Fallback microservice
      await serviceProxy.servers.editServerMessage(serverId, messageId, content, userId);

      io.to(chRoom(serverId, channelId)).emit('SERVER_MESSAGE_EDITED', {
        type: 'SERVER_MESSAGE_EDITED',
        payload: { messageId, content, serverId, channelId, editedBy: userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_MESSAGE_ERROR', error);
    }
  });

  socket.on('SERVER_MESSAGE_DELETE', async (data) => {
    try {
      const { serverId, messageId, channelId } = data ?? {};
      if (!isId(serverId) || !isId(messageId) || !isId(channelId) || !(await nodeOwnsChannel(serverId, channelId))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }

      // On exige au minimum l'appartenance ; la propriété du message (auteur)
      // ou MANAGE_MESSAGES est vérifiée par le node / le microservice. Le
      // microservice reçoit désormais x-user-id : l'appel « internal » sans
      // identité laissait n'importe quel membre supprimer n'importe quel message.
      if (!(await checkServerPermission(userId, serverId, PERM.READ))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }

      // Forward au server-node si connecté
      try {
        await forwardToNode(serverId, 'MSG_DELETE', {
          messageId, channelId, userId,
        });
        // Le node broadcast via NODE_BROADCAST
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE' && e.message !== 'NODE_TIMEOUT') { emitError(socket, 'SERVER_MESSAGE_ERROR', e); return; }
      }

      // Fallback microservice
      await serviceProxy.servers.deleteServerMessage(serverId, messageId, userId);

      io.to(chRoom(serverId, channelId)).emit('SERVER_MESSAGE_DELETED', {
        type: 'SERVER_MESSAGE_DELETED',
        payload: { messageId, serverId, channelId, deletedBy: userId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_MESSAGE_ERROR', error);
    }
  });

  // ── Réactions sur messages de serveur ──
  socket.on('SERVER_REACTION_ADD', async (data) => {
    try {
      const { serverId, channelId, messageId, emoji } = data ?? {};
      if (!isId(serverId) || !isId(channelId) || !isId(messageId) || typeof emoji !== 'string' || !emoji || emoji.length > 50
        || !(await nodeOwnsChannel(serverId, channelId))) {
        emitError(socket, 'REACTION_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }
      if (!(await checkChannelPermission(userId, serverId, channelId, PERM.READ | PERM.REACT))) {
        emitError(socket, 'REACTION_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      await serviceProxy.servers.addServerReaction(serverId, messageId, userId, emoji);
      io.to(chRoom(serverId, channelId)).emit('SERVER_REACTION_UPDATE', {
        type: 'SERVER_REACTION_UPDATE',
        payload: { messageId, userId, emoji, action: 'add' },
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  socket.on('SERVER_REACTION_REMOVE', async (data) => {
    try {
      const { serverId, channelId, messageId, emoji } = data ?? {};
      if (!isId(serverId) || !isId(channelId) || !isId(messageId) || typeof emoji !== 'string' || !emoji || emoji.length > 50
        || !(await nodeOwnsChannel(serverId, channelId))) {
        emitError(socket, 'REACTION_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }
      if (!(await checkChannelPermission(userId, serverId, channelId, PERM.READ))) {
        emitError(socket, 'REACTION_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      await serviceProxy.servers.removeServerReaction(serverId, messageId, userId, emoji);
      io.to(chRoom(serverId, channelId)).emit('SERVER_REACTION_UPDATE', {
        type: 'SERVER_REACTION_UPDATE',
        payload: { messageId, userId, emoji, action: 'remove' },
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  // ── Message history via node ──
  socket.on('SERVER_MESSAGE_HISTORY', async (data, callback) => {
    try {
      const { serverId, channelId, before } = data ?? {};
      const limit = Math.min(Math.max(Number(data?.limit) || 50, 1), 100);
      if (!isId(serverId) || !isId(channelId)) {
        if (typeof callback === 'function') callback({ messages: [], error: 'INVALID_PAYLOAD' });
        return;
      }
      // Sans ce contrôle, n'importe quel compte lisait l'historique de
      // n'importe quel salon en connaissant serverId + channelId. READ est
      // évalué DANS le salon : un salon privé n'est pas lisible par @everyone.
      if (!(await checkChannelPermission(userId, serverId, channelId, PERM.READ))) {
        if (typeof callback === 'function') callback({ messages: [], error: 'PERMISSION_DENIED' });
        return;
      }
      try {
        const result = await forwardToNode(serverId, 'MSG_HISTORY', { channelId, before, limit, userId });
        if (typeof callback === 'function') callback(result);
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { if (typeof callback === 'function') callback({ error: e.message }); return; }
      }
      // Fallback microservice
      const messages = await serviceProxy.servers.getChannelMessages(serverId, channelId, limit, before, userId);
      if (typeof callback === 'function') callback({ messages });
    } catch (error: any) {
      if (typeof callback === 'function') callback({ error: error.message });
    }
  });

  // ── Channels CRUD via node ──
  socket.on('SERVER_GET_CHANNELS', async (data, callback) => {
    // Un contrôle d'autorisation qui ne peut pas s'exécuter doit REFUSER.
    // L'ancien « fail open si le check échoue techniquement » transformait une
    // panne du service servers en ouverture générale.
    try {
      const member = await serviceProxy.servers.isMember(data.serverId, userId);
      if (!member) {
        if (typeof callback === 'function') callback({ channels: [], error: 'NOT_MEMBER' });
        return;
      }
    } catch {
      if (typeof callback === 'function') callback({ channels: [], error: 'CHECK_FAILED' });
      return;
    }
    try {
      try {
        const result = await forwardToNode(data.serverId, 'CHANNEL_LIST', {});
        if (typeof callback === 'function') callback(result);
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { if (typeof callback === 'function') callback({ channels: [], error: e.message }); return; }
      }
      // userId : seuls les salons visibles (surcharges de permissions).
      const channels = await serviceProxy.servers.getServerChannels(data.serverId, userId);
      if (typeof callback === 'function') callback({ channels: channels || [] });
    } catch {
      if (typeof callback === 'function') callback({ channels: [], error: true });
    }
  });

  socket.on('CHANNEL_CREATE', async (data, callback) => {
    const ack = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const { serverId } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) { // MANAGE_CHANNELS
        emitError(socket, 'CHANNEL_ERROR', new Error('PERMISSION_DENIED'));
        ack({ error: 'PERMISSION_DENIED' });
        return;
      }
      const clean = validateChannelInput({ ...data, type: data.type || 'text' });
      try {
        const result = await forwardToNode(serverId, 'CHANNEL_CREATE', {
          name: clean.name, type: clean.type || 'text', topic: clean.topic, parentId: clean.parentId, userId,
        });
        // Le node broadcast CHANNEL_CREATE via NODE_BROADCAST
        // Aussi notifier via socket pour confirmation
        if (result?.channel) {
          io.to(`server:${serverId}`).emit('CHANNEL_CREATE', {
            type: 'CHANNEL_CREATE',
            payload: { ...result.channel, serverId },
            timestamp: new Date(),
          });
        }
        ack({ channel: result?.channel ? { ...result.channel, serverId } : null });
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'CHANNEL_ERROR', e); ack({ error: e.message }); return; }
      }
      // Fallback microservice
      const channel = await serviceProxy.servers.createChannel(serverId, {
        name: clean.name!, type: clean.type || 'text', parentId: clean.parentId ?? undefined,
        topic: clean.topic, isNsfw: clean.isNsfw, slowMode: clean.slowMode, userLimit: clean.userLimit, isPrivate: clean.isPrivate,
      }, userId, token) as any;
      invalidateChannelMeta(serverId);
      await announceChannel(serverId, channel, 'CHANNEL_CREATE');
      ack({ channel });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
      ack({ error: (error as any)?.message ?? 'ERROR' });
    }
  });

  socket.on('CHANNEL_UPDATE', async (data) => {
    try {
      const { serverId, channelId } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) {
        emitError(socket, 'CHANNEL_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      const clean = validateChannelInput(data);
      try {
        await forwardToNode(serverId, 'CHANNEL_UPDATE', {
          channelId, name: clean.name, topic: clean.topic, position: data.position, type: clean.type, parentId: clean.parentId, userId,
        });
        // Le node broadcast via NODE_BROADCAST
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'CHANNEL_ERROR', e); return; }
      }
      const updates: Record<string, unknown> = { ...clean };
      if (data.position !== undefined && clean.position === undefined) updates.position = data.position;
      const channel = await serviceProxy.servers.updateChannel(serverId, channelId, updates, userId, token) as any;
      invalidateChannelMeta(serverId);
      // Changer de catégorie peut changer la visibilité (salon synchronisé).
      if (clean.parentId !== undefined) {
        invalidateServerPerms(serverId);
        scheduleChannelResync(serverId);
      }
      await announceChannel(serverId, channel, 'CHANNEL_UPDATE');
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  socket.on('CHANNEL_DELETE', async (data) => {
    try {
      const { serverId, channelId } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) {
        emitError(socket, 'CHANNEL_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      try {
        await forwardToNode(serverId, 'CHANNEL_DELETE', { channelId, userId });
        // Le node broadcast via NODE_BROADCAST
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE' && e.message !== 'NODE_TIMEOUT') { emitError(socket, 'CHANNEL_ERROR', e); return; }
      }
      await serviceProxy.servers.deleteChannel(serverId, channelId, userId, token);
      invalidateChannelMeta(serverId);
      io.in(`server:${serverId}`).socketsLeave(chRoom(serverId, channelId));
      io.to(`server:${serverId}`).emit('CHANNEL_DELETE', {
        type: 'CHANNEL_DELETE',
        payload: { channelId, serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  // ── Channel Permissions ──
  socket.on('CHANNEL_PERMS_GET', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      if (!isId(data?.serverId) || !isId(data?.channelId)) return respond({ permissions: [], overrides: [], error: 'INVALID_PAYLOAD' });
      // Les surcharges décrivent qui voit quoi : réservées à qui gère salons ou rôles.
      if (!(await checkServerPermissionAny(userId, data.serverId, PERM.MANAGE_CHANNELS | PERM.MANAGE_ROLES))) {
        return respond({ permissions: [], overrides: [], error: 'PERMISSION_DENIED' });
      }
      try {
        const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_GET', { channelId: data.channelId });
        return respond(result);
      } catch (e: any) {
        if (e.message !== 'NO_NODE') return respond({ permissions: [], overrides: [], error: e.message });
      }
      const result = await serviceProxy.servers.getChannelOverrides(data.serverId, data.channelId);
      respond(result);
    } catch (e: any) {
      respond({ permissions: [], overrides: [], error: e.message });
    }
  });

  socket.on('CHANNEL_PERMS_DELETE', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const targetType = data?.targetType === 'member' ? 'member' : 'role';
      if (!isId(data?.serverId) || !isId(data?.channelId) || !isId(data?.targetId)) return respond({ error: 'INVALID_PAYLOAD' });
      if (!(await checkServerPermissionAny(userId, data.serverId, PERM.MANAGE_CHANNELS | PERM.MANAGE_ROLES))) return respond({ error: 'PERMISSION_DENIED' });
      if (connectedNodes.has(data.serverId)) return respond({ error: 'NOT_SUPPORTED_ON_NODE' });
      await serviceProxy.servers.deleteChannelOverride(data.serverId, data.channelId, targetType, data.targetId, userId);
      afterOverridesChanged(data.serverId, data.channelId);
      respond({ success: true });
    } catch (e: any) {
      respond({ error: e.message });
    }
  });

  socket.on('CHANNEL_PERMS_SYNC', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      if (!isId(data?.serverId) || !isId(data?.channelId)) return respond({ error: 'INVALID_PAYLOAD' });
      if (!(await checkServerPermission(userId, data.serverId, PERM.MANAGE_CHANNELS))) return respond({ error: 'PERMISSION_DENIED' });
      if (connectedNodes.has(data.serverId)) return respond({ error: 'NOT_SUPPORTED_ON_NODE' });
      await serviceProxy.servers.syncChannelOverrides(data.serverId, data.channelId, userId);
      afterOverridesChanged(data.serverId, data.channelId);
      respond({ success: true });
    } catch (e: any) {
      respond({ error: e.message });
    }
  });

  // Glisser-déposer : un lot de positions/catégories, une seule diffusion.
  socket.on('CHANNEL_REORDER', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const { serverId } = data ?? {};
      if (!isId(serverId)) return respond({ error: 'INVALID_PAYLOAD' });
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) return respond({ error: 'PERMISSION_DENIED' });
      const positions = validateChannelReorder(data.positions);
      let channels: any[] = [];
      if (connectedNodes.has(serverId)) {
        for (const row of positions) {
          await forwardToNode(serverId, 'CHANNEL_UPDATE', { channelId: row.id, position: row.position, parentId: row.parentId, userId });
        }
      } else {
        const result = await serviceProxy.servers.reorderChannels(serverId, positions, userId);
        channels = result?.channels ?? [];
        invalidateChannelMeta(serverId);
        if (positions.some((p) => p.parentId !== undefined)) {
          invalidateServerPerms(serverId);
          scheduleChannelResync(serverId);
        }
      }
      // Positions seules : aucun nom de salon privé ne fuit dans la diffusion.
      const visible = channels.length
        ? channels.map((c: any) => ({ id: c.id, position: c.position, parentId: c.parentId ?? null }))
        : positions.map((p) => ({ id: p.id, position: p.position, ...(p.parentId !== undefined ? { parentId: p.parentId } : {}) }));
      io.to(`server:${serverId}`).emit('CHANNELS_REORDERED', {
        type: 'CHANNELS_REORDERED',
        payload: { serverId, positions: visible },
        timestamp: new Date(),
      });
      respond({ success: true });
    } catch (e: any) {
      emitError(socket, 'CHANNEL_ERROR', e);
      respond({ error: e.message });
    }
  });

  socket.on('CHANNEL_PERMS_SET', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      if (!(await checkServerPermissionAny(userId, data?.serverId, PERM.MANAGE_CHANNELS | PERM.MANAGE_ROLES))) {
        return respond({ error: 'PERMISSION_DENIED' });
      }
      const allow = Number(data?.allow ?? 0);
      const deny = Number(data?.deny ?? 0);
      // `roleId` reste accepté (ancien contrat, rôles seulement).
      const targetType: 'role' | 'member' = data?.targetType === 'member' ? 'member' : 'role';
      const targetId = data?.targetId ?? data?.roleId;
      const nodeHosted = connectedNodes.has(data.serverId);
      const max = nodeHosted ? 0xFFFF : ALL_PERMS_MASK;
      if (!isId(data?.channelId) || !isId(targetId)
        || !Number.isInteger(allow) || !Number.isInteger(deny) || allow < 0 || deny < 0 || allow > max || deny > max) {
        return respond({ error: 'INVALID_PAYLOAD' });
      }
      if (nodeHosted) {
        if (targetType !== 'role') return respond({ error: 'NOT_SUPPORTED_ON_NODE' });
        // Le node applique l'anti-escalade dans son propre espace de bits
        // (on ne peut pas accorder via un salon un droit qu'on n'a pas).
        const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_SET', {
          channelId: data.channelId,
          roleId: targetId,
          allow,
          deny,
          userId,
        });
        return respond(result);
      }
      // Microservice : anti-escalade dans le salon, côté service.
      const result = await serviceProxy.servers.setChannelOverride(data.serverId, data.channelId, { targetType, targetId, allow, deny }, userId);
      afterOverridesChanged(data.serverId, data.channelId);
      respond(result);
    } catch (e: any) {
      emitError(socket, 'CHANNEL_ERROR', e);
      respond({ error: e.message });
    }
  });

  // ── Rôles via node ──
  socket.on('ROLE_LIST', async (data, callback) => {
    try {
      if (!(await checkServerPermission(userId, data.serverId, PERM.READ))) {
        if (typeof callback === 'function') callback({ roles: [], error: 'PERMISSION_DENIED' });
        return;
      }
      const result = await forwardToNode(data.serverId, 'ROLE_LIST', {});
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback: récupérer depuis le microservice servers
      if (e.message === 'NO_NODE') {
        try {
          const roles = await serviceProxy.servers.getRoles(data.serverId);
          if (typeof callback === 'function') callback({ roles: roles || [] });
          return;
        } catch { /* fall through */ }
      }
      if (typeof callback === 'function') callback({ roles: [], error: e.message });
    }
  });

  socket.on('ROLE_CREATE', async (data, callback) => {
    const ack = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const hasPerm = await checkServerPermission(userId, data.serverId, PERM.MANAGE_ROLES);
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      const clean = validateRoleInput(data);
      invalidateServerPerms(data.serverId);
      // Anti-escalation : un non-owner ne peut pas accorder des bits qu'il
      // ne possède pas. ADMIN reste réservé à l'owner.
      const actor = await getUserPermBits(userId, data.serverId);
      let safePerms = clean.permissions ?? 0;
      if (!actor.isOwner) {
        safePerms = safePerms & actor.perms;
        safePerms &= ~PERM.ADMIN; // jamais d'ADMIN sauf owner
      }
      try {
        const result = await forwardToNode(data.serverId, 'ROLE_CREATE', {
          name: clean.name, color: clean.color, permissions: safePerms, mentionable: clean.mentionable, hoist: clean.hoist, userId,
        });
        if (result?.role) {
          io.to(`server:${data.serverId}`).emit('ROLE_CREATE', {
            type: 'ROLE_CREATE',
            payload: { ...result.role, serverId: data.serverId },
            timestamp: new Date(),
          });
        }
        ack({ role: result?.role ?? null });
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'ROLE_ERROR', e); ack({ error: e.message }); return; }
      }
      // Fallback microservice
      const role = await serviceProxy.servers.createRole(data.serverId, {
        name: clean.name!, color: clean.color, permissions: safePerms,
        hoist: clean.hoist, mentionable: clean.mentionable, iconEmoji: clean.iconEmoji,
      } as any, userId) as Record<string, unknown>;
      io.to(`server:${data.serverId}`).emit('ROLE_CREATE', {
        type: 'ROLE_CREATE',
        payload: { ...role, serverId: data.serverId },
        timestamp: new Date(),
      });
      ack({ role: { ...role, serverId: data.serverId } });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
      ack({ error: (error as any)?.message ?? 'ERROR' });
    }
  });

  socket.on('ROLE_UPDATE', async (data) => {
    try {
      const hasPerm = await checkServerPermission(userId, data.serverId, PERM.MANAGE_ROLES);
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      const clean = validateRoleInput(data);
      invalidateServerPerms(data.serverId);
      // Anti-escalation identique à ROLE_CREATE.
      const actor = await getUserPermBits(userId, data.serverId);
      let safePerms: number | undefined = clean.permissions;
      if (safePerms !== undefined && !actor.isOwner) {
        safePerms = safePerms & actor.perms;
        safePerms &= ~PERM.ADMIN;
      }
      // Un non-owner ne peut pas modifier la position d'un rôle (bypass hiérarchie).
      const safePosition = actor.isOwner ? data.position : undefined;
      try {
        const result = await forwardToNode(data.serverId, 'ROLE_UPDATE', {
          roleId: data.roleId, name: clean.name, color: clean.color,
          permissions: safePerms, position: safePosition, mentionable: clean.mentionable, userId,
        });
        if (result?.role) {
          io.to(`server:${data.serverId}`).emit('ROLE_UPDATE', {
            type: 'ROLE_UPDATE',
            payload: { ...result.role, serverId: data.serverId },
            timestamp: new Date(),
          });
        }
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'ROLE_ERROR', e); return; }
      }
      // Fallback microservice
      const updated = await serviceProxy.servers.updateRole(data.serverId, data.roleId, {
        name: clean.name, color: clean.color, permissions: safePerms,
        position: safePosition, mentionable: clean.mentionable, hoist: clean.hoist, iconEmoji: clean.iconEmoji,
      }, userId) as Record<string, unknown>;
      // Les droits d'un rôle décident des salons visibles.
      if (safePerms !== undefined) scheduleChannelResync(data.serverId);
      io.to(`server:${data.serverId}`).emit('ROLE_UPDATE', {
        type: 'ROLE_UPDATE',
        payload: { ...updated, roleId: data.roleId, serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
    }
  });

  socket.on('ROLE_DELETE', async (data) => {
    try {
      const hasPerm = await checkServerPermission(userId, data.serverId, PERM.MANAGE_ROLES);
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      invalidateServerPerms(data.serverId);
      try {
        await forwardToNode(data.serverId, 'ROLE_DELETE', { roleId: data.roleId, userId });
        io.to(`server:${data.serverId}`).emit('ROLE_DELETE', {
          type: 'ROLE_DELETE',
          payload: { roleId: data.roleId, serverId: data.serverId },
          timestamp: new Date(),
        });
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'ROLE_ERROR', e); return; }
      }
      // Fallback microservice
      await serviceProxy.servers.deleteRole(data.serverId, data.roleId, userId);
      scheduleChannelResync(data.serverId);
      io.to(`server:${data.serverId}`).emit('ROLE_DELETE', {
        type: 'ROLE_DELETE',
        payload: { roleId: data.roleId, serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
    }
  });

  // Droits effectifs du membre courant — sur le serveur, ou DANS un salon
  // (surcharges incluses). Sert à l'interface : saisie verrouillée, raccourcis
  // de gestion… L'autorisation réelle reste vérifiée à chaque action.
  socket.on('MY_PERMISSIONS', async (data, callback) => {
    if (typeof callback !== 'function') return;
    try {
      const { serverId, channelId } = data ?? {};
      if (!isId(serverId)) return callback({ error: 'INVALID_PAYLOAD' });
      const bits = isId(channelId)
        ? await getChannelPermBits(userId, serverId, channelId)
        : await getUserPermBits(userId, serverId);
      callback({ serverId, channelId: isId(channelId) ? channelId : null, isOwner: bits.isOwner, permissions: bits.perms });
    } catch (e: any) {
      callback({ error: e?.message ?? 'ERROR' });
    }
  });

  socket.on('ROLE_REORDER', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const { serverId } = data ?? {};
      if (!isId(serverId) || !Array.isArray(data?.positions) || data.positions.length === 0 || data.positions.length > 250) {
        return respond({ error: 'INVALID_PAYLOAD' });
      }
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_ROLES))) return respond({ error: 'PERMISSION_DENIED' });
      if (connectedNodes.has(serverId)) return respond({ error: 'NOT_SUPPORTED_ON_NODE' });
      const positions = (data.positions as any[]).map((row) => ({ id: String(row?.id ?? ''), position: Math.floor(Number(row?.position)) }));
      if (positions.some((row) => !isId(row.id) || !Number.isFinite(row.position))) return respond({ error: 'INVALID_PAYLOAD' });
      invalidateServerPerms(serverId);
      const result = await serviceProxy.servers.reorderRoles(serverId, positions, userId);
      io.to(`server:${serverId}`).emit('ROLES_REORDERED', {
        type: 'ROLES_REORDERED',
        payload: { serverId, roles: result?.roles ?? [] },
        timestamp: new Date(),
      });
      respond({ success: true });
    } catch (e: any) {
      emitError(socket, 'ROLE_ERROR', e);
      respond({ error: e.message });
    }
  });

  // ── Présence en masse (DM list, liste d'amis) ──
  socket.on('GET_BULK_PRESENCE', async (data: { userIds: string[] }, callback) => {
    try {
      if (!Array.isArray(data?.userIds) || data.userIds.length === 0) {
        if (typeof callback === 'function') callback({ presence: [] });
        return;
      }
      // Liste bornée et assainie (elle était illimitée), et respect du réglage
      // « afficher mon statut en ligne » de chaque utilisateur.
      const ids = [...new Set((data.userIds as unknown[]).filter(isUuid))].slice(0, 200);
      const presence = await redis.getBulkPresence(ids);
      const hidden = await Promise.all(presence.map((p) => (p.userId === userId ? false : isPresenceHidden(p.userId))));
      const visible = presence.map((p, i) => (hidden[i] ? { userId: p.userId, status: 'offline', customStatus: null, emoji: null } : p));
      if (typeof callback === 'function') callback({ presence: visible });
    } catch (error) {
      if (typeof callback === 'function') callback({ presence: [] });
    }
  });

  // ── État vocal d'un serveur (snapshot) ──
  socket.on('GET_VOICE_STATE', async (data: { serverId: string }, callback) => {
    try {
      if (!data?.serverId || typeof callback !== 'function') {
        if (typeof callback === 'function') callback({ channels: [] });
        return;
      }
      // L'état vocal d'un serveur n'est visible que par ses membres.
      const isMember = await serviceProxy.servers.isMember(data.serverId, userId);
      if (!isMember) { callback({ channels: [] }); return; }
      // Return all channels that belong to this server
      const channels: Array<{ channelId: string; participants: any[] }> = [];
      voiceChannels.forEach((participants, channelId) => {
        const parts = Array.from(participants.values());
        if (parts.length > 0 && parts[0].serverId === data.serverId) {
          channels.push({
            channelId,
            participants: parts.map(publicVoiceParticipant),
            status: voiceChannelStatus.get(channelId) ?? null,
          } as any);
        }
      });
      callback({ channels });
    } catch {
      if (typeof callback === 'function') callback({ channels: [] });
    }
  });

  // ── Membres via node ──
  socket.on('MEMBER_LIST', async (data, callback) => {
    const respond = (payload: any) => { if (typeof callback === 'function') callback(payload); };
    try {
      if (!(await checkServerPermission(userId, data.serverId, PERM.READ))) {
        respond({ members: [], error: 'PERMISSION_DENIED' });
        return;
      }

      const uid = (m: any): string => m?.userId || m?.user_id || m?.id;

      /**
       * Ajoute le statut en ligne. Un `isUserOnline` PAR MEMBRE faisait un
       * aller-retour Redis par membre : 1 000 membres = 1 000 allers-retours
       * à chaque ouverture de la liste. Un seul appel groupé suffit.
       */
      const withPresence = async (members: any[]): Promise<any[]> => {
        const ids = [...new Set(members.map(uid).filter(Boolean))];
        // Un seul pipeline Redis : statut choisi (absent, ne pas déranger),
        // invisible → hors ligne, et le réglage « afficher mon statut ».
        const list = await redis.getBulkPresence(ids).catch(() => [] as Awaited<ReturnType<typeof redis.getBulkPresence>>);
        const byId = new Map(list.map((p) => [p.userId, p]));
        const hidden = new Set<string>();
        await Promise.all(list
          .filter((p) => p.status !== 'offline' && p.userId !== userId)
          .map(async (p) => { if (await isPresenceHidden(p.userId).catch(() => false)) hidden.add(p.userId); }));
        return members.map((m) => {
          const p = byId.get(uid(m));
          if (!p || hidden.has(uid(m))) return { ...m, status: 'offline', customStatus: null };
          return { ...m, status: p.status, customStatus: p.customStatus ?? null };
        });
      };

      // Les membres du microservice servent à la fois de référence (filtrage
      // des membres périmés côté node) et de source de secours : une seule
      // lecture, au lieu des deux que faisait la version précédente.
      let msMembers: any[] | null = null;
      try {
        msMembers = (await serviceProxy.servers.getMembers(data.serverId)) ?? [];
      } catch {
        msMembers = null; // MySQL injoignable
      }

      let nodeMembers: any[] = [];
      let nodeReachable = true;
      try {
        const result = await forwardToNode(data.serverId, 'MEMBER_LIST', {});
        nodeMembers = result?.members ?? [];
      } catch {
        nodeReachable = false;
      }

      // Pas de node (ou node vide) → on sert la liste du microservice.
      if (!nodeReachable || nodeMembers.length === 0) {
        if (!msMembers || msMembers.length === 0) {
          respond({ members: [] });
          return;
        }
        // Semer les membres manquants dans le node, en arrière-plan.
        if (nodeReachable) {
          for (const m of msMembers) {
            forwardToNode(data.serverId, 'MEMBER_JOIN', {
              userId: uid(m),
              username: m.username,
              displayName: m.displayName || m.display_name || null,
              avatarUrl: m.avatarUrl || m.avatar_url || null,
            }).catch(() => { /* semis best-effort */ });
          }
        }
        respond({ members: await withPresence(msMembers) });
        return;
      }

      // Node + microservice : croiser les deux pour écarter les membres périmés.
      if (!msMembers || msMembers.length === 0) {
        respond({ members: await withPresence(nodeMembers) });
        return;
      }

      const validUserIds = new Set(msMembers.map(uid));
      const nodeUserIds = new Set(nodeMembers.map(uid));

      const filteredMembers = nodeMembers.filter((m) => validUserIds.has(uid(m)));

      for (const stale of nodeMembers) {
        if (validUserIds.has(uid(stale))) continue;
        logger.info(`Cleaning stale member ${uid(stale)} from node for server ${data.serverId}`);
        forwardToNode(data.serverId, 'MEMBER_KICK', { userId: uid(stale), systemCleanup: true }).catch(() => {});
      }

      for (const m of msMembers) {
        if (nodeUserIds.has(uid(m))) continue;
        forwardToNode(data.serverId, 'MEMBER_JOIN', {
          userId: uid(m),
          username: m.username,
          displayName: m.displayName || m.display_name || null,
          avatarUrl: m.avatarUrl || m.avatar_url || null,
        }).catch(() => { /* semis best-effort */ });
      }

      respond({ members: await withPresence(filteredMembers) });
    } catch (e: any) {
      respond({ members: [], error: e?.message ?? 'MEMBER_LIST_FAILED' });
    }
  });

  // ── MEMBER_UPDATE ── Mise à jour des rôles / nickname d'un membre
  socket.on('MEMBER_UPDATE', async (data, callback) => {
    try {
      const { serverId, targetUserId } = data;
      const clean = validateMemberUpdate(data);
      const roleIds = clean.roleIds;
      const nickname = clean.nickname;

      if (!isId(serverId) || !isUuid(targetUserId)) {
        if (typeof callback === 'function') callback({ error: 'INVALID_PAYLOAD' });
        return;
      }

      // Permissions par champ, comme Discord : rôles → MANAGE_ROLES ; pseudo
      // d'un autre → MANAGE_NICKNAMES ; son propre pseudo → CHANGE_NICKNAME.
      const selfNickOnly = targetUserId === userId && roleIds === undefined;
      const hasPerm = selfNickOnly
        ? await checkServerPermissionAny(userId, serverId, PERM.CHANGE_NICKNAME | PERM.MANAGE_NICKNAMES)
        : (roleIds === undefined || await checkServerPermission(userId, serverId, PERM.MANAGE_ROLES))
          && (nickname === undefined || targetUserId === userId || await checkServerPermission(userId, serverId, PERM.MANAGE_NICKNAMES));
      if (!hasPerm) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }

      // Hiérarchie : on ne modifie pas un membre dont les droits dépassent les
      // siens (retirer les rôles d'un admin, renommer le propriétaire…).
      if (targetUserId !== userId && !(await canActOnMember(userId, targetUserId, serverId))) {
        if (typeof callback === 'function') callback({ error: 'TARGET_OUTRANKS_YOU' });
        return;
      }

      // Anti-escalation : un non-owner ne peut assigner QUE des rôles dont
      // les permissions sont un sous-ensemble des siennes. Empêche un user
      // MANAGE_ROLES de s'auto-assigner un rôle ADMIN.
      let safeRoleIds: string[] | undefined = roleIds;
      if (Array.isArray(roleIds) && roleIds.length > 0) {
        const actor = await getUserPermBits(userId, serverId);
        if (!actor.isOwner) {
          try {
            const roles = await serviceProxy.servers.getRoles(serverId) || [];
            const allowed = new Set<string>();
            for (const r of roles) {
              const raw = (r as any).permissions;
              const p = (typeof raw === 'number' ? raw : parseInt(String(raw ?? '0'), 10)) & ALL_PERMS_MASK;
              // Le rôle est assignable si tous ses bits ⊆ bits de l'acteur, ET pas ADMIN.
              if ((p & ~actor.perms) === 0 && !(p & PERM.ADMIN)) {
                allowed.add((r as any).id);
              }
            }
            safeRoleIds = roleIds.filter((rid) => typeof rid === 'string' && allowed.has(rid));
            if (safeRoleIds.length !== roleIds.length) {
              logger.warn(`MEMBER_UPDATE escalation blocked: ${userId} tried to assign superior roles on server ${serverId}`);
            }
          } catch (e) {
            if (typeof callback === 'function') callback({ error: 'ROLE_CHECK_FAILED' });
            return;
          }
        }
      }

      invalidateServerPerms(serverId, targetUserId);
      try {
        const result = await forwardToNode(serverId, 'MEMBER_UPDATE', {
          userId: targetUserId, roleIds: safeRoleIds, nickname,
        });
        // Node broadcasts via NODE_BROADCAST relay
        if (typeof callback === 'function') callback(result);
      } catch (e: any) {
        if (e.message !== 'NO_NODE') {
          if (typeof callback === 'function') callback({ error: e.message });
          return;
        }
        // Fallback: update MySQL directly
        await serviceProxy.servers.updateMember(serverId, targetUserId, { roleIds: safeRoleIds, nickname }, userId, token);
        if (safeRoleIds !== undefined) scheduleChannelResync(serverId, targetUserId);
        // Broadcast to all server members
        io.to(`server:${serverId}`).emit('MEMBER_UPDATE', {
          type: 'MEMBER_UPDATE',
          payload: { userId: targetUserId, serverId, roleIds: safeRoleIds, nickname },
          timestamp: new Date(),
        });
        if (typeof callback === 'function') callback({ success: true });
      }
    } catch (error) {
      emitError(socket, 'MEMBER_ERROR', error);
      if (typeof callback === 'function') callback({ error: (error as any).message });
    }
  });

  socket.on('MEMBER_KICK', async (data) => {
    try {
      const { serverId, targetUserId } = data;
      // KICK_MEMBERS (0x400) OU l'ancien KICK (0x10) : les deux paires
      // coexistent dans les rôles existants.
      const hasKickPerm = await checkServerPermissionAny(userId, serverId, KICK_ANY);
      if (!hasKickPerm) { emitError(socket, 'MEMBER_ERROR', new Error('PERMISSION_DENIED')); return; }
      // Hiérarchie : on ne peut expulser qu'un membre dont les droits sont
      // inclus dans les siens. Sans ce test, un modérateur expulsait un
      // administrateur — ou le propriétaire.
      const kickTarget = targetUserId || data.userId;
      if (!(await canActOnMember(userId, kickTarget, serverId))) {
        emitError(socket, 'MEMBER_ERROR', new Error('TARGET_OUTRANKS_YOU'));
        return;
      }
      invalidateServerPerms(serverId, kickTarget);
      try {
        await forwardToNode(serverId, 'MEMBER_KICK', { userId: targetUserId || data.userId, actorId: userId });
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'MEMBER_ERROR', e); return; }
        await serviceProxy.servers.kickMember(serverId, targetUserId || data.userId, userId);
      }
      io.to(`user:${targetUserId || data.userId}`).emit('SERVER_KICKED', {
        type: 'SERVER_KICKED',
        payload: { serverId },
        timestamp: new Date(),
      });
      io.to(`server:${serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId, userId: targetUserId || data.userId, kicked: true },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MEMBER_ERROR', error);
    }
  });

  socket.on('MEMBER_BAN', async (data) => {
    try {
      const { serverId, targetUserId, reason } = data;
      // BAN_MEMBERS (0x800) OU l'ancien BAN (0x20). Voir MEMBER_KICK.
      const hasBanPerm = await checkServerPermissionAny(userId, serverId, BAN_ANY);
      if (!hasBanPerm) { emitError(socket, 'MEMBER_ERROR', new Error('PERMISSION_DENIED')); return; }
      const banTarget = targetUserId || data.userId;
      if (!(await canActOnMember(userId, banTarget, serverId))) {
        emitError(socket, 'MEMBER_ERROR', new Error('TARGET_OUTRANKS_YOU'));
        return;
      }
      invalidateServerPerms(serverId, banTarget);
      try {
        await forwardToNode(serverId, 'MEMBER_BAN', { userId: targetUserId || data.userId, reason, actorId: userId });
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'MEMBER_ERROR', e); return; }
        await serviceProxy.servers.banMember(serverId, targetUserId || data.userId, userId, reason);
      }
      io.to(`user:${targetUserId || data.userId}`).emit('SERVER_BANNED', {
        type: 'SERVER_BANNED',
        payload: { serverId, reason },
        timestamp: new Date(),
      });
      io.to(`server:${serverId}`).emit('MEMBER_LEAVE', {
        type: 'MEMBER_LEAVE',
        payload: { serverId, userId: targetUserId || data.userId, banned: true },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'MEMBER_ERROR', error);
    }
  });

  // ── Server info via node ──
  socket.on('SERVER_INFO', async (data, callback) => {
    // Fail-closed : voir SERVER_GET_CHANNELS.
    try {
      const member = await serviceProxy.servers.isMember(data.serverId, userId);
      if (!member) {
        if (typeof callback === 'function') callback({ error: 'NOT_MEMBER' });
        return;
      }
    } catch {
      if (typeof callback === 'function') callback({ error: 'CHECK_FAILED' });
      return;
    }
    try {
      const result = await forwardToNode(data.serverId, 'SERVER_INFO', {});
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback: microservice
      try {
        const server = await serviceProxy.servers.getServer(data.serverId);
        // getServer est un appel interne (liste complète) : on n'expose au
        // membre que les salons qu'il peut voir.
        if (server && Array.isArray(server.channels)) {
          server.channels = (await serviceProxy.servers.getServerChannels(data.serverId, userId).catch(() => [])) ?? [];
        }
        if (typeof callback === 'function') callback(server);
      } catch {
        if (typeof callback === 'function') callback({ error: e.message });
      }
    }
  });

  // Quand le créateur du serveur utilise le code d'invitation, notifier tous les membres
  socket.on('SERVER_OWNER_JOINED', async (data) => {
    try {
      const { serverId } = data;
      if (!serverId) return;
      // Le frontend s'en sert pour masquer l'onglet Invitations : sans contrôle,
      // n'importe quel membre altérait l'interface de tous les autres.
      const srv = await serviceProxy.servers.getServer(serverId).catch(() => null);
      const realOwnerId = srv?.ownerId ?? srv?.owner_id;
      if (!realOwnerId || realOwnerId !== userId) {
        logger.warn(`SERVER_OWNER_JOINED refusé : ${userId} n'est pas owner de ${serverId}`);
        return;
      }
      io.to(`server:${serverId}`).emit('SERVER_OWNER_JOINED', {
        type: 'SERVER_OWNER_JOINED',
        payload: { serverId, ownerId: userId },
        timestamp: new Date(),
      });
      logger.info(`SERVER_OWNER_JOINED broadcasted pour serveur ${serverId} par owner ${userId}`);
    } catch (error) {
      logger.warn({ err: error }, 'SERVER_OWNER_JOINED error:');
    }
  });

  socket.on('SERVER_UPDATE_NODE', async (data) => {
    try {
      const { serverId } = data;
      if (!(await checkServerPermissionAny(userId, serverId, PERM.MANAGE_SERVER))) {
        emitError(socket, 'SERVER_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      const clean = validateServerInput(data);
      Object.assign(data, clean);
      try {
        const result = await forwardToNode(serverId, 'SERVER_UPDATE', {
          name: clean.name, description: clean.description,
          iconUrl: clean.iconUrl, bannerUrl: clean.bannerUrl, isPublic: clean.isPublic,
        });
        io.to(`server:${serverId}`).emit('SERVER_UPDATE', {
          type: 'SERVER_UPDATE',
          payload: { id: serverId, ...result },
          timestamp: new Date(),
        });
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE' && e.message !== 'NODE_TIMEOUT') {
          emitError(socket, 'SERVER_ERROR', e);
          return;
        }
      }
      // Fallback: pas de node → microservice
      const updates: Record<string, any> = {};
      if (data.name !== undefined) updates.name = data.name;
      if (data.description !== undefined) updates.description = data.description;
      if (data.iconUrl !== undefined) updates.iconUrl = data.iconUrl;
      if (data.bannerUrl !== undefined) updates.bannerUrl = data.bannerUrl;
      if (data.isPublic !== undefined) updates.isPublic = data.isPublic;
      const updated = await serviceProxy.servers.updateServer(data.serverId, updates, userId, token) as Record<string, any> | undefined;
      io.to(`server:${data.serverId}`).emit('SERVER_UPDATE', {
        type: 'SERVER_UPDATE',
        payload: {
          id: data.serverId,
          name: data.name,
          description: data.description,
          iconUrl: data.iconUrl,
          bannerUrl: data.bannerUrl,
          isPublic: data.isPublic,
          ...(updated && updated.success === undefined ? updated : {}),
        },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'SERVER_ERROR', error);
    }
  });

  // ── Invitations via node ──
  socket.on('INVITE_LIST', async (data, callback) => {
    try {
      // Un code d'invitation ouvre l'accès à un serveur privé : la liste est
      // réservée à ceux qui peuvent gérer le serveur.
      if (!(await checkServerPermissionAny(userId, data.serverId, PERM.MANAGE_SERVER | PERM.MANAGE_CHANNELS))) {
        if (typeof callback === 'function') callback({ invites: [], error: 'PERMISSION_DENIED' });
        return;
      }
      const result = await forwardToNode(data.serverId, 'INVITE_LIST', {});
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback microservice
      try {
        const invites = await serviceProxy.servers.getInvites(data.serverId);
        if (typeof callback === 'function') callback({ invites: invites || [] });
      } catch {
        if (typeof callback === 'function') callback({ invites: [], error: e.message });
      }
    }
  });

  socket.on('INVITE_DELETE', async (data, callback) => {
    try {
      if (!(await checkServerPermissionAny(userId, data.serverId, PERM.MANAGE_SERVER | PERM.MANAGE_CHANNELS))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }
      if (!isId(data?.inviteId)) {
        if (typeof callback === 'function') callback({ error: 'INVALID_PAYLOAD' });
        return;
      }
      try {
        await forwardToNode(data.serverId, 'INVITE_DELETE', { inviteId: data.inviteId });
      } catch (e: any) {
        if (e.message !== 'NO_NODE') throw e;
      }
      // La copie MySQL (utilisée par les liens HTTP /invite/<code>) doit
      // disparaître aussi : sinon une invitation révoquée restait utilisable.
      await serviceProxy.servers.deleteInvite(data.inviteId, userId).catch((err: any) => {
        if (err?.statusCode !== 404) throw err;
      });
      if (typeof callback === 'function') callback({ success: true });
    } catch (e: any) {
      if (typeof callback === 'function') callback({ error: e.message });
    }
  });

  socket.on('INVITE_CREATE', async (data, callback) => {
    let clean: ReturnType<typeof validateInviteInput>;
    try { clean = validateInviteInput(data); }
    catch (e: any) { if (typeof callback === 'function') callback({ error: e.message }); return; }
    // « Créer une invitation » : droit de base de @everyone sur Discord.
    if (!(await checkServerPermission(userId, data.serverId, PERM.CREATE_INVITE))) {
      if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
      return;
    }
    try {
      const result = await forwardToNode(data.serverId, 'INVITE_CREATE', {
        creatorId: userId, maxUses: clean.maxUses, expiresIn: clean.expiresIn,
        customSlug: clean.customSlug, isPermanent: clean.isPermanent,
      });
      // Synchroniser l'invitation dans le MySQL central pour que le lien HTTP fonctionne
      if (result && result.code) {
        try {
          await serviceProxy.servers.createInvite(data.serverId, {
            creatorId: userId,
            code: result.code,
            id: result.id,
            maxUses: clean.maxUses,
            expiresIn: clean.expiresIn,
            customSlug: clean.customSlug,
            isPermanent: clean.isPermanent,
          });
        } catch {
          // Sync non critique – le lien pourrait ne pas fonctionner mais ne bloque pas la création
          logger.warn('INVITE_CREATE: échec sync MySQL (node fonctionnel)');
        }
      }
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback microservice
      try {
        const invite = await serviceProxy.servers.createInvite(data.serverId, {
          creatorId: userId, maxUses: clean.maxUses, expiresIn: clean.expiresIn,
          customSlug: clean.customSlug, isPermanent: clean.isPermanent,
        });
        if (typeof callback === 'function') callback(invite);
      } catch {
        if (typeof callback === 'function') callback({ error: e.message });
      }
    }
  });

  socket.on('INVITE_VERIFY', async (data, callback) => {
    try {
      if (!checkInviteVerifyRate(userId)) {
        if (typeof callback === 'function') callback({ error: 'RATE_LIMITED' });
        return;
      }
      const result = await forwardToNode(data.serverId, 'INVITE_VERIFY', { code: data.code });
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback microservice
      try {
        const invite = await serviceProxy.servers.resolveInvite(data.code);
        if (typeof callback === 'function') callback(invite);
      } catch {
        if (typeof callback === 'function') callback({ error: e.message });
      }
    }
  });

  // Typing dans un channel serveur
  socket.on('SERVER_TYPING_START', async (data) => {
    // Le client doit d'abord avoir rejoint le salon (CHANNEL_JOIN / SERVER_JOIN
    // valident l'appartenance) : sans ce test, on pouvait spammer l'indicateur
    // de frappe dans n'importe quel salon de la plateforme.
    if (!isId(data?.serverId) || !isId(data?.channelId) || !socket.rooms.has(chRoom(data.serverId, data.channelId))) return;
    socket.to(chRoom(data.serverId, data.channelId)).emit('SERVER_TYPING_START', {
      type: 'SERVER_TYPING_START',
      payload: { userId, channelId: data.channelId, serverId: data.serverId },
      timestamp: new Date(),
    });
  });

  socket.on('SERVER_TYPING_STOP', async (data) => {
    if (!isId(data?.serverId) || !isId(data?.channelId) || !socket.rooms.has(chRoom(data.serverId, data.channelId))) return;
    socket.to(chRoom(data.serverId, data.channelId)).emit('SERVER_TYPING_STOP', {
      type: 'SERVER_TYPING_STOP',
      payload: { userId, channelId: data.channelId, serverId: data.serverId },
      timestamp: new Date(),
    });
  });

  // Rejoindre/quitter une room de channel
  socket.on('CHANNEL_JOIN', async (data) => {
    try {
      const { channelId, serverId } = data ?? {};
      if (!isId(channelId) || !isId(serverId)) return;

      // Pour les serveurs avec node connecté, la membership est gérée localement par le node.
      // On forward la vérification au node ; sinon on interroge le microservice.
      let isMember = false;
      const nodeSocket = getNodeSocket(serverId);
      if (nodeSocket) {
        const result = await forwardToNode(serverId, 'MEMBER_CHECK', { userId }) as any;
        isMember = result?.isMember === true;
      } else {
        isMember = await serviceProxy.servers.isMember(serverId, userId);
      }

      if (!isMember) {
        socket.emit('error', { message: 'Accès refusé — vous n\'êtes pas membre de ce serveur' });
        return;
      }

      // Le salon doit appartenir à CE serveur (l'appartenance ne se vérifiait
      // que sur le serveur passé en paramètre, pas sur le salon).
      if (!(await nodeOwnsChannel(serverId, channelId))) {
        socket.emit('error', { message: 'Salon introuvable dans ce serveur' });
        return;
      }
      // …et il doit être visible pour ce membre (salon privé).
      if (!(await checkChannelPermission(userId, serverId, channelId, PERM.READ))) {
        socket.emit('error', { message: 'Accès refusé à ce salon' });
        return;
      }

      socket.join(chRoom(serverId, channelId));
      logger.info(`${userId} rejoint ${chRoom(serverId, channelId)}`);
    } catch (err) {
      logger.warn({ err }, 'CHANNEL_JOIN permission check error');
    }
  });

  socket.on('CHANNEL_LEAVE', async (data) => {
    if (!isId(data?.channelId)) return;
    if (isId(data?.serverId)) {
      socket.leave(chRoom(data.serverId, data.channelId));
      return;
    }
    const suffix = `:${data.channelId}`;
    for (const room of socket.rooms) {
      if (room.startsWith('ch:') && room.endsWith(suffix)) socket.leave(room);
    }
  });

  // Mise à jour de présence
  socket.on('PRESENCE_UPDATE', async (data) => {
    try {
      const VALID_STATUSES = ['online', 'idle', 'dnd', 'invisible'];
      if (!data?.status || !VALID_STATUSES.includes(data.status)) return;

      const emoji: string | null = data.emoji ? String(data.emoji).trim().slice(0, 2) || null : null;
      const text: string | null = data.text
        ? String(data.text).trim().slice(0, 100) || null
        : (data.customStatus ? String(data.customStatus).trim().slice(0, 100) || null : null);

      // `auto: true` → transition automatique (auto-idle / retour d'activité).
      // Dans ce cas on ne touche PAS au choix explicite de l'utilisateur
      // (chosenStatus) ni à la DB : seul `status` change, et `autoIdle` retient
      // que l'absence est automatique afin que le heartbeat puisse la lever.
      const isAuto = data.auto === true;

      if (isAuto) {
        // setPresence conserve `chosenStatus` existant (non fourni ici).
        await redis.setPresence(userId, {
          status: data.status,
          emoji,
          text,
          lastActivity: Date.now(),
          autoIdle: data.status === 'idle',
        });
        const friends = await serviceProxy.friends.getFriends(userId);
        broadcastPresenceUpdate(userId, data.status, friends, text, emoji);
        return;
      }

      // Choix explicite de l'utilisateur → met à jour le statut choisi + DB.
      await redis.setPresence(userId, {
        status: data.status,
        chosenStatus: data.status,
        emoji,
        text,
        lastActivity: Date.now(),
        autoIdle: false,
      });

      // DB write fire-and-forget
      serviceProxy.users.updateStatus(userId, data.status, text, emoji)
        .catch((err: unknown) => logger.warn({ err }, `updateStatus DB failed for ${userId}`));

      const friends = await serviceProxy.friends.getFriends(userId);
      broadcastPresenceUpdate(userId, data.status, friends, text, emoji);
    } catch (error) {
      emitError(socket, 'PRESENCE_ERROR', error);
    }
  });

  // ============ PROFIL ============

  // Mise à jour du profil via WebSocket
  socket.on('PROFILE_UPDATE', async (data) => {
    try {
      data = validateProfile(data);
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      const result = await serviceProxy.users.updateProfile(userId, data, token);
      const updatedUser = (result as any)?.data || { userId, ...data };

      // Mettre à jour l'objet user local
      Object.assign(socket as AuthenticatedSocket, { user: { ...user, ...data } });

      // Notifier le client avec le profil complet
      socket.emit('PROFILE_UPDATE', {
        type: 'PROFILE_UPDATE',
        payload: updatedUser,
        timestamp: new Date(),
      });

      // Notifier les amis du changement de profil
      try {
        const friends = await serviceProxy.friends.getFriends(userId);
        for (const friend of friends) {
          io.to(`user:${friend.friendId || friend.id}`).emit('PROFILE_UPDATE', {
            type: 'PROFILE_UPDATE',
            payload: { userId, ...data },
            timestamp: new Date(),
          });
        }
      } catch (e) {
        logger.warn({ err: e }, 'Erreur notification profil amis:');
      }

      // Notifier les membres de serveur (non-amis) via les rooms du socket
      try {
        for (const room of socket.rooms) {
          if (room.startsWith('server:')) {
            io.to(room).emit('PROFILE_UPDATE', {
              type: 'PROFILE_UPDATE',
              payload: { userId, ...data },
              timestamp: new Date(),
            });
          }
        }
      } catch (e) {
        logger.warn({ err: e }, 'Erreur notification profil serveurs:');
      }
    } catch (error) {
      emitError(socket, 'PROFILE_UPDATE_ERROR', error);
    }
  });

  // Changement de nom d'utilisateur via WebSocket (broadcaste le nouveau username à amis + serveurs)
  socket.on('CHANGE_USERNAME', async (data) => {
    try {
      const { newUsername, password } = data || {};
      if (!newUsername || !password) {
        socket.emit('CHANGE_USERNAME_ERROR', { error: 'Données manquantes' });
        return;
      }
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      const result = await serviceProxy.users.changeUsername(userId, newUsername, password, token) as any;
      if (!result?.success) {
        socket.emit('CHANGE_USERNAME_ERROR', { error: result?.error || 'Erreur lors du changement' });
        return;
      }
      // Mettre à jour le user local du socket
      Object.assign(socket as AuthenticatedSocket, { user: { ...user, username: newUsername } });
      socket.emit('CHANGE_USERNAME_SUCCESS', { username: newUsername });

      // Broadcaster le nouveau username comme un PROFILE_UPDATE à amis + serveurs
      const usernamePayload = { userId, username: newUsername };
      const tsNow = new Date();
      try {
        const friends = await serviceProxy.friends.getFriends(userId);
        for (const friend of friends) {
          io.to(`user:${friend.friendId || friend.id}`).emit('PROFILE_UPDATE', {
            type: 'PROFILE_UPDATE', payload: usernamePayload, timestamp: tsNow,
          });
        }
      } catch (e) { logger.warn({ err: e }, 'Erreur notif username amis:'); }
      try {
        for (const room of socket.rooms) {
          if (room.startsWith('server:')) {
            io.to(room).emit('PROFILE_UPDATE', {
              type: 'PROFILE_UPDATE', payload: usernamePayload, timestamp: tsNow,
            });
          }
        }
      } catch (e) { logger.warn({ err: e }, 'Erreur notif username serveurs:'); }
    } catch (error) {
      emitError(socket, 'CHANGE_USERNAME_ERROR', error);
    }
  });

  // ============ GROUPES DE DISCUSSION ============

  // Créer un groupe
  socket.on('GROUP_CREATE', async (data) => {
    try {
      const clean = validateGroupInput(data);
      const name = clean.name;
      const avatarUrl = clean.avatarUrl;
      const participantIds: string[] = clean.participantIds || data.participantIds || [];
      const isOpen = clean.isOpen !== false;

      // Inclure le créateur dans les participants
      const allParticipants = [userId, ...participantIds.filter((id: string) => id !== userId)];

      // Créer la conversation de groupe via le service messages
      const group = await serviceProxy.messages.createConversation({
        type: 'group',
        name,
        avatarUrl,
        participants: allParticipants,
        createdBy: userId,
        isOpen,
      });

      const groupId = (group as any).id;

      // Faire rejoindre le créateur
      socket.join(`conversation:${groupId}`);

      // Notifier et faire rejoindre chaque participant RÉELLEMENT ajouté : le
      // service écarte ceux qui ont bloqué le créateur, et la liste du client
      // ne doit pas servir à abonner qui que ce soit à la room.
      const createdIds: string[] = Array.isArray((group as any)?.participantIds)
        ? (group as any).participantIds
        : Array.isArray((group as any)?.participants)
          ? (group as any).participants.map((p: any) => p?.userId ?? p?.id).filter(Boolean)
          : [];
      for (const participantId of createdIds.filter((id) => id !== userId && participantIds.includes(id))) {
        io.to(`user:${participantId}`).emit('GROUP_CREATE', {
          type: 'GROUP_CREATE',
          payload: group,
          timestamp: new Date(),
        });
        // Faire rejoindre les participants connectés à la room
        const participantSockets = await io.in(`user:${participantId}`).fetchSockets();
        for (const ps of participantSockets) {
          ps.join(`conversation:${groupId}`);
        }
      }

      // Confirmation au créateur
      socket.emit('GROUP_CREATE', {
        type: 'GROUP_CREATE',
        payload: group,
        timestamp: new Date(),
      });

      logger.info(`Groupe créé: ${groupId} par ${userId} avec ${allParticipants.length} participants`);
    } catch (error) {
      emitError(socket, 'GROUP_CREATE_ERROR', error);
    }
  });

  // Mettre à jour un groupe (nom, avatar, participants)
  socket.on('GROUP_UPDATE', async (data) => {
    try {
      const { groupId } = data;
      const clean = validateGroupInput(data);
      const name = clean.name;
      const avatarUrl = clean.avatarUrl;
      const addParticipants = clean.addParticipants;
      const removeParticipants = clean.removeParticipants;
      const isOpen = clean.isOpen;
      const token: string | undefined = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');

      // Mettre à jour nom/avatar/isOpen via service messages
      if (name !== undefined || avatarUrl !== undefined || isOpen !== undefined) {
        await serviceProxy.messages.updateConversation(groupId, { name, avatarUrl, isOpen }, token);
      }

      // Ajouter des participants
      if (addParticipants?.length) {
        for (const pid of addParticipants) {
          await serviceProxy.messages.addParticipant(groupId, pid, token);
          invalidateConversationAccess(groupId, pid);
          // Notifier le nouveau membre
          io.to(`user:${pid}`).emit('GROUP_MEMBER_ADD', {
            type: 'GROUP_MEMBER_ADD',
            payload: { groupId, userId: pid, addedBy: userId },
            timestamp: new Date(),
          });
          // Faire rejoindre les sockets connectés
          const pSockets = await io.in(`user:${pid}`).fetchSockets();
          for (const ps of pSockets) {
            ps.join(`conversation:${groupId}`);
          }
        }
      }

      // Retirer des participants
      if (removeParticipants?.length) {
        for (const pid of removeParticipants) {
          await serviceProxy.messages.removeParticipant(groupId, pid, token);
          invalidateConversationAccess(groupId, pid);
          // Notifier le membre retiré
          io.to(`user:${pid}`).emit('GROUP_MEMBER_REMOVE', {
            type: 'GROUP_MEMBER_REMOVE',
            payload: { groupId, userId: pid, removedBy: userId },
            timestamp: new Date(),
          });
          // Retirer de la room
          const pSockets = await io.in(`user:${pid}`).fetchSockets();
          for (const ps of pSockets) {
            ps.leave(`conversation:${groupId}`);
          }
        }
      }

      // Notifier tous les membres restants
      io.to(`conversation:${groupId}`).emit('GROUP_UPDATE', {
        type: 'GROUP_UPDATE',
        payload: { groupId, name, avatarUrl, isOpen, addParticipants, removeParticipants, updatedBy: userId },
        timestamp: new Date(),
      });

      logger.info(`Groupe mis à jour: ${groupId} par ${userId}`);
    } catch (error) {
      emitError(socket, 'GROUP_UPDATE_ERROR', error);
    }
  });

  // Quitter un groupe
  socket.on('GROUP_LEAVE', async (data) => {
    try {
      const { groupId } = data;

      // Appeler le service pour quitter (gère le transfert de propriété)
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      const result = await serviceProxy.messages.leaveConversation(groupId, userId, token);
      invalidateConversationAccess(groupId, userId);

      // Retirer de la room socket
      socket.leave(`conversation:${groupId}`);

      // Confirmer au client
      const resultObj = (typeof result === 'object' && result !== null) ? result : {};
      socket.emit('GROUP_LEAVE', {
        type: 'GROUP_LEAVE',
        payload: { groupId, userId, ...(resultObj as Record<string, unknown>) },
        timestamp: new Date(),
      });

      // Si le groupe n'est pas supprimé, notifier les membres restants
      if (!(result as any).deleted) {
        io.to(`conversation:${groupId}`).emit('GROUP_UPDATE', {
          type: 'GROUP_UPDATE',
          payload: { 
            groupId, 
            removeParticipants: [userId], 
            newOwnerId: (result as any).newOwnerId,
            leftBy: userId,
          },
          timestamp: new Date(),
        });
      } else {
        // Le groupe a été supprimé, notifier tout le monde
        io.to(`conversation:${groupId}`).emit('GROUP_DELETE', {
          type: 'GROUP_DELETE',
          payload: { groupId },
          timestamp: new Date(),
        });
      }

      logger.info(`Utilisateur ${userId} a quitté le groupe ${groupId}`);
    } catch (error) {
      emitError(socket, 'GROUP_LEAVE_ERROR', error);
    }
  });

  // Supprimer un groupe (owner only)
  socket.on('GROUP_DELETE', async (data) => {
    try {
      const { groupId } = data;

      // Supprimer D'ABORD (le service refuse si l'appelant n'est pas
      // propriétaire), notifier ensuite. L'ordre inverse faisait disparaître le
      // groupe de toutes les interfaces même quand la suppression était refusée.
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      await serviceProxy.messages.deleteConversation(groupId, token);

      io.to(`conversation:${groupId}`).emit('GROUP_DELETE', {
        type: 'GROUP_DELETE',
        payload: { groupId, deletedBy: userId },
        timestamp: new Date(),
      });
      invalidateConversationAccess(groupId);

      logger.info(`Groupe supprimé: ${groupId} par ${userId}`);
    } catch (error) {
      emitError(socket, 'GROUP_DELETE_ERROR', error);
    }
  });

  // ── Voice Chat System ──
  socket.on('VOICE_JOIN', async (data) => {
    const { serverId, channelId } = data ?? {};
    if (!isId(serverId) || !isId(channelId)) return;

    // Vérifier que l'utilisateur est membre du serveur
    try {
      const isMember = await serviceProxy.servers.isMember(serverId, userId);
      if (!isMember) {
        socket.emit('error', { message: 'Accès refusé — vous n\'êtes pas membre de ce serveur' });
        return;
      }
    } catch (err) {
      logger.warn({ err }, 'VOICE_JOIN permission check error');
      return;
    }

    // Vérifier que le salon appartient BIEN à ce serveur et qu'il est vocal.
    // Sans ce contrôle, `serverId` ne sert qu'au test d'appartenance et `channelId`
    // peut désigner le salon vocal d'un tout autre serveur.
    // Les serveurs auto-hébergés gardent leurs salons sur leur node : on vérifie
    // au moins que le salon lui appartient.
    if (connectedNodes.has(serverId)) {
      if (!(await nodeOwnsChannel(serverId, channelId))) {
        socket.emit('error', { message: 'Salon introuvable dans ce serveur' });
        return;
      }
    } else {
      try {
        const channels = await serviceProxy.servers.getServerChannels(serverId) as any[];
        const target = (channels || []).find((c: any) => (c.id ?? c.channelId) === channelId);
        if (!target) {
          socket.emit('error', { message: 'Salon introuvable dans ce serveur' });
          return;
        }
        if (target.type !== 'voice' && target.type !== 'stage') {
          socket.emit('error', { message: 'Ce salon n\'est pas un salon vocal' });
          return;
        }
      } catch (err) {
        logger.warn({ err }, 'VOICE_JOIN channel check error');
        return;
      }
    }

    // Droit de se connecter au salon (surcharges incluses).
    if (!(await checkChannelPermission(userId, serverId, channelId, PERM.CONNECT))) {
      socket.emit('VOICE_ERROR', { type: 'VOICE_ERROR', payload: { channelId, error: 'PERMISSION_DENIED' } });
      return;
    }
    // Limite d'utilisateurs : MOVE_MEMBERS passe outre, comme sur Discord.
    const meta = await getChannelMeta(serverId, channelId);
    const already = voiceChannels.get(channelId);
    if (meta?.userLimit && already && !already.has(userId) && already.size >= meta.userLimit
      && !(await checkServerPermission(userId, serverId, PERM.MOVE_MEMBERS))) {
      socket.emit('VOICE_ERROR', { type: 'VOICE_ERROR', payload: { channelId, error: 'CHANNEL_FULL', userLimit: meta.userLimit } });
      return;
    }

    // Leave any existing voice channel first (y compris depuis un autre onglet).
    const existingChannel = userVoiceChannel.get(userId);
    if (existingChannel && existingChannel !== channelId) {
      removeVoiceParticipant(userId, existingChannel);
    }

    // Join the new voice channel
    if (!voiceChannels.has(channelId)) {
      voiceChannels.set(channelId, new Map());
    }
    const participants = voiceChannels.get(channelId)!;
    const previous = participants.get(userId);
    const participant: VoicePresence = {
      socketId: socket.id,
      userId,
      username: user.username,
      displayName: (user as any).displayName || user.username,
      avatarUrl: (user as any).avatarUrl || (user as any).avatar_url || undefined,
      muted: data?.muted === true,
      deafened: data?.deafened === true,
      video: data?.video === true,
      streaming: false,
      serverMuted: previous?.serverMuted ?? false,
      serverDeafened: previous?.serverDeafened ?? false,
      joinedAt: previous?.joinedAt ?? Date.now(),
      serverId,
    };
    participants.set(userId, participant);
    userVoiceChannel.set(userId, channelId);

    // Join voice room for signaling
    socket.join(`voice:${channelId}`);

    // Notify all in server that user joined voice
    broadcastVoiceState(serverId, channelId);

    // Notify existing participants about the new user (for WebRTC connections)
    socket.to(`voice:${channelId}`).emit('VOICE_USER_JOINED', {
      channelId,
      userId,
      username: user.username,
      avatarUrl: participant.avatarUrl,
    });

    logger.info(`${user.username} joined voice channel ${channelId}`);
  });

  socket.on('VOICE_LEAVE', (data) => {
    const { serverId, channelId } = data;
    leaveVoiceChannel(userId, socket);
  });

  socket.on('VOICE_STATE_UPDATE', (data) => {
    const currentChannelId = userVoiceChannel.get(userId);
    if (!currentChannelId) return;

    const participants = voiceChannels.get(currentChannelId);
    if (!participants) return;
    const p = participants.get(userId);
    if (!p || p.socketId !== socket.id) return;

    if (typeof data?.muted === 'boolean') p.muted = data.muted;
    if (typeof data?.deafened === 'boolean') p.deafened = data.deafened;
    if (typeof data?.video === 'boolean') p.video = data.video;
    if (typeof data?.streaming === 'boolean') p.streaming = data.streaming;

    broadcastVoiceState(p.serverId, currentChannelId);
  });

  // Anneau vert « parle » : relayé à tout le serveur (liste des salons), sans
  // état. Le client n'émet que les transitions ; on borne quand même le débit.
  let lastSpeakingAt = 0;
  socket.on('VOICE_SPEAKING', (data) => {
    const channelId = userVoiceChannel.get(userId);
    if (!channelId) return;
    const p = voiceChannels.get(channelId)?.get(userId);
    if (!p || p.socketId !== socket.id) return;
    const speaking = data?.speaking === true;
    const now = Date.now();
    if (speaking && now - lastSpeakingAt < 120) return;
    if (speaking) lastSpeakingAt = now;
    socket.to(`server:${p.serverId}`).emit('VOICE_SPEAKING', { serverId: p.serverId, channelId, userId, speaking });
  });

  // « Définir un statut de salon » — texte libre affiché sous le salon vocal.
  socket.on('VOICE_CHANNEL_STATUS', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const { serverId, channelId } = data ?? {};
      if (!isId(serverId) || !isId(channelId)) return respond({ error: 'INVALID_PAYLOAD' });
      const participants = voiceChannels.get(channelId);
      // Éphémère : un salon vide n'a pas de statut.
      if (!participants || participants.size === 0) return respond({ error: 'CHANNEL_EMPTY' });
      const first = participants.values().next().value as VoicePresence | undefined;
      if (first?.serverId !== serverId) return respond({ error: 'INVALID_PAYLOAD' });
      const inChannel = userVoiceChannel.get(userId) === channelId;
      if (!inChannel && !(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) {
        return respond({ error: 'PERMISSION_DENIED' });
      }
      const status = typeof data.status === 'string' ? data.status.replace(/\s+/g, ' ').trim().slice(0, 100) : '';
      if (status) voiceChannelStatus.set(channelId, status);
      else voiceChannelStatus.delete(channelId);
      broadcastVoiceState(serverId, channelId);
      respond({ success: true, status });
    } catch (error: any) {
      respond({ error: error?.message ?? 'ERROR' });
    }
  });

  // Modération vocale : rendre muet/sourd, déconnecter, déplacer.
  socket.on('VOICE_MODERATE', async (data, callback) => {
    const respond = (payload: unknown) => { if (typeof callback === 'function') callback(payload); };
    try {
      const { serverId, targetUserId, action } = data ?? {};
      const ACTIONS = ['mute', 'unmute', 'deafen', 'undeafen', 'disconnect', 'move'];
      if (!isId(serverId) || !isUuid(targetUserId) || !ACTIONS.includes(action)) return respond({ error: 'INVALID_PAYLOAD' });
      const channelId = userVoiceChannel.get(targetUserId);
      const target = channelId ? voiceChannels.get(channelId)?.get(targetUserId) : undefined;
      if (!channelId || !target || target.serverId !== serverId) return respond({ error: 'NOT_IN_VOICE' });

      const needed = action === 'disconnect' || action === 'move' ? PERM.MOVE_MEMBERS : PERM.MUTE_MEMBERS;
      if (!(await checkServerPermission(userId, serverId, needed))) return respond({ error: 'PERMISSION_DENIED' });
      if (targetUserId !== userId && !(await canActOnMember(userId, targetUserId, serverId))) {
        return respond({ error: 'TARGET_OUTRANKS_YOU' });
      }

      if (action === 'move') {
        const to = data?.channelId;
        const meta = isId(to) ? await getChannelMeta(serverId, to) : null;
        if (!meta || (meta.type !== 'voice' && meta.type !== 'stage')) return respond({ error: 'INVALID_CHANNEL' });
        io.to(`user:${targetUserId}`).emit('VOICE_FORCE', { type: 'VOICE_FORCE', payload: { serverId, action, channelId: to, by: userId } });
        return respond({ success: true });
      }
      if (action === 'disconnect') {
        io.to(`user:${targetUserId}`).emit('VOICE_FORCE', { type: 'VOICE_FORCE', payload: { serverId, action, channelId, by: userId } });
        removeVoiceParticipant(targetUserId, channelId);
        return respond({ success: true });
      }
      if (action === 'mute') target.serverMuted = true;
      if (action === 'unmute') target.serverMuted = false;
      if (action === 'deafen') target.serverDeafened = true;
      if (action === 'undeafen') target.serverDeafened = false;
      io.to(`user:${targetUserId}`).emit('VOICE_FORCE', { type: 'VOICE_FORCE', payload: { serverId, action, channelId, by: userId } });
      broadcastVoiceState(serverId, channelId);
      respond({ success: true });
    } catch (error: any) {
      respond({ error: error?.message ?? 'ERROR' });
    }
  });

  // WebRTC signaling for voice
  socket.on('VOICE_OFFER', (data) => {
    const { channelId, targetUserId, offer } = data;
    const channelParticipants = voiceChannels.get(channelId);
    if (!channelParticipants) return;
    // L'émetteur doit lui-même être dans le salon : sinon n'importe quelle socket
    // authentifiée peut injecter de la signalisation vers un participant.
    if (!channelParticipants.has(userId)) return;
    const target = channelParticipants.get(targetUserId);
    if (!target) return;
    io.to(target.socketId).emit('VOICE_OFFER', {
      channelId,
      fromUserId: userId,
      offer,
    });
  });

  socket.on('VOICE_ANSWER', (data) => {
    const { channelId, targetUserId, answer } = data;
    const channelParticipants = voiceChannels.get(channelId);
    if (!channelParticipants) return;
    // L'émetteur doit lui-même être dans le salon : sinon n'importe quelle socket
    // authentifiée peut injecter de la signalisation vers un participant.
    if (!channelParticipants.has(userId)) return;
    const target = channelParticipants.get(targetUserId);
    if (!target) return;
    io.to(target.socketId).emit('VOICE_ANSWER', {
      channelId,
      fromUserId: userId,
      answer,
    });
  });

  socket.on('VOICE_ICE_CANDIDATE', (data) => {
    const { channelId, targetUserId, candidate } = data;
    const channelParticipants = voiceChannels.get(channelId);
    if (!channelParticipants) return;
    // L'émetteur doit lui-même être dans le salon : sinon n'importe quelle socket
    // authentifiée peut injecter de la signalisation vers un participant.
    if (!channelParticipants.has(userId)) return;
    const target = channelParticipants.get(targetUserId);
    if (!target) return;
    io.to(target.socketId).emit('VOICE_ICE_CANDIDATE', {
      channelId,
      fromUserId: userId,
      candidate,
    });
  });

  // Déconnexion
  socket.on('disconnect', async (reason) => {
    logger.info(`Déconnexion: ${user.username} (${userId}) - Raison: ${reason}`);
    
    // Clean up voice state on disconnect
    leaveVoiceChannel(userId, socket);

    // Ne pas laisser de timers derrière soi
    for (const timer of pendingArchiveRequests.values()) clearTimeout(timer);
    pendingArchiveRequests.clear();
    
    connectedClients.delete(socket.id);
    
    try {
      // Mettre à jour le statut hors ligne (seulement si plus aucun socket actif)
      await redis.setUserOffline(userId, socket.id);
      await redis.deleteSession(userId, sessionId);
      
      // Notifier les amis seulement si l'utilisateur est vraiment offline
      const stillOnline = await redis.isUserOnline(userId);
      if (!stillOnline) {
        // Préserver la clé presence (TTL 24h) pour restauration au reconnect
        const currentPresence = await redis.getPresence(userId);
        if (currentPresence) {
          await redis.setPresence(userId, currentPresence);
        }

        try {
          const friends = await serviceProxy.friends.getFriends(userId);
          // Broadcast aux amis seulement (plus de broadcast serveur)
          broadcastPresenceUpdate(userId, 'offline', friends, null, null);
        } catch (friendsError) {
          logger.warn({ err: friendsError }, `Impossible de notifier les amis pour ${userId}:`);
        }

        // last_seen + is_online=FALSE fire-and-forget
        serviceProxy.users.updateLastSeen(userId)
          .catch((err: unknown) => logger.warn({ err }, `updateLastSeen failed for ${userId}`));
      }
    } catch (error) {
      logger.error({ err: error }, `Erreur lors de la déconnexion de ${userId}:`);
    }
  });

  // Appels : fermer l'onglet n'envoie jamais CALL_LEAVE. Sans ce nettoyage,
  // l'appel restait « en cours » en base et le salon vocal renvoyait 409 à
  // tous ceux qui essayaient de le rejoindre. Délai de grâce : une simple
  // reconnexion (CALL_REJOIN) ne coupe pas l'appel.
  socket.on('disconnecting', () => {
    for (const room of socket.rooms) {
      if (!room.startsWith('call:')) continue;
      const callId = room.slice('call:'.length);
      setTimeout(() => { endCallIfEmpty(callId, userId).catch(() => {}); }, 15_000);
    }
  });

  // Tous les gestionnaires sont posés : distribuer les évènements en attente.
  releaseHandlers();
});

/** Termine un appel dont plus aucune socket ne fait partie (base + salle SFU). */
async function endCallIfEmpty(callId: string, byUserId: string): Promise<void> {
  if ((await io.in(`call:${callId}`).fetchSockets()).length > 0) return;
  await serviceProxy.calls.endCall(callId, byUserId).catch(() => {});
  serviceProxy.media.destroyRoom(callId).catch(() => {});
}

/** `existingCallId` d'une réponse 409 du service calls (« appel déjà actif »). */
function existingCallIdOf(err: unknown): string | null {
  const m = /^Service error: \d{3} (.*)$/s.exec(err instanceof Error ? err.message : '');
  if (!m) return null;
  try {
    const id = JSON.parse(m[1])?.existingCallId;
    return isId(id) ? id : null;
  } catch {
    return null;
  }
}

// ============ AUTO-IDLE : détection d'inactivité côté gateway ============

{
  const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
  const seen = new Set<string>();

  setInterval(async () => {
    seen.clear();
    for (const [, client] of connectedClients) {
      const { userId } = client as { userId: string };
      if (!userId || seen.has(userId)) continue;
      seen.add(userId);
      try {
        const p = await redis.getPresence(userId);
        if (!p) continue;
        if (p.chosenStatus === 'online' && p.status === 'online' && Date.now() - p.lastActivity > IDLE_TIMEOUT_MS) {
          await redis.setPresence(userId, { ...p, status: 'idle', autoIdle: true });
          const idleFriends = await serviceProxy.friends.getFriends(userId);
          broadcastPresenceUpdate(userId, 'idle', idleFriends, p.text, p.emoji);
        }
      } catch { /* non-bloquant */ }
    }
  }, 60_000);
}

/**
 * Le salon appartient-il bien à ce serveur ?
 *
 * Le node est la source de la liste de ses salons ; on la met en cache Redis
 * pour ne pas payer un aller-retour par broadcast. Le cache est court : un
 * salon créé devient diffusable en moins d'une minute.
 */
const NODE_CHANNELS_TTL = 60;

/** Événements de node relayés tels quels (hors cas traités explicitement). */
const NODE_PASSTHROUGH_EVENTS = new Set<string>([
  'CHANNEL_PERMS_UPDATE',
]);

async function nodeOwnsChannel(serverId: string, channelId: string): Promise<boolean> {
  if (!isId(serverId) || !isId(channelId)) return false;
  const key = `nodechans:${serverId}`;
  try {
    const cached = await redis.get(key);
    if (cached) {
      const ids: string[] = JSON.parse(cached);
      // Présent dans le cache → oui. Absent → on recharge : le salon vient
      // peut-être d'être créé (sinon il restait refusé jusqu'à 60 s).
      if (Array.isArray(ids) && ids.includes(channelId)) return true;
    }
  } catch { /* cache indisponible — on recharge */ }

  let ids: string[] = [];
  try {
    const result = await forwardToNode(serverId, 'CHANNEL_LIST', {}, 5_000);
    ids = (result?.channels ?? []).map((c: any) => c?.id).filter((id: unknown): id is string => typeof id === 'string');
  } catch {
    try {
      const channels = await serviceProxy.servers.getServerChannels(serverId);
      ids = (channels ?? []).map((c: any) => c?.id ?? c?.channelId).filter((id: unknown): id is string => typeof id === 'string');
    } catch {
      // Impossible de vérifier → refuser plutôt que de relayer à l'aveugle.
      return false;
    }
  }
  redis.set(key, JSON.stringify(ids), NODE_CHANNELS_TTL).catch(() => {});
  return ids.includes(channelId);
}

// ============ SERVER NODES NAMESPACE (self-hosted) ============

// Le namespace /server-nodes utilise une authentification différente (nodeToken, pas JWT user)
const serverNodesNs = io.of('/server-nodes');

serverNodesNs.use(async (socket, next) => {
  try {
    const { nodeToken, serverId, register, token } = socket.handshake.auth;

    // ── Mode enregistrement ────────────────────────────────────────────
    // Ce mode CRÉE un serveur en base. Il exigeait auparavant zéro credential :
    // n'importe qui pouvait donc générer des serveurs (et des nodeToken) en
    // boucle depuis Internet. Le node doit désormais présenter le JWT de
    // l'utilisateur qui l'installe — c'est lui qui portera le serveur créé.
    if (register === true) {
      if (!token || typeof token !== 'string') {
        return next(new Error('Enregistrement refusé — connectez-vous dans le client AlfyChat pour obtenir un jeton d\'installation'));
      }
      let ownerId: string;
      try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as { userId?: string; id?: string };
        ownerId = (decoded.userId || decoded.id) as string;
        if (!isUuid(ownerId)) throw new Error('no-user');
      } catch {
        return next(new Error('Jeton d\'installation invalide ou expiré'));
      }
      // Un compte banni ne doit pas pouvoir créer de serveur (fail-closed).
      const moderation = await serviceProxy.users.getModerationStatus(ownerId).catch(() => undefined);
      if (moderation === undefined) {
        return next(new Error('Vérification du compte impossible pour le moment'));
      }
      if (moderation?.banned) {
        return next(new Error('Ce compte est banni'));
      }
      if (!checkNodeRegisterRate(ownerId)) {
        return next(new Error('Trop d\'enregistrements de serveurs — patientez quelques minutes'));
      }
      (socket as any).registerMode = true;
      (socket as any).registerOwnerId = ownerId;
      return next();
    }

    // Mode connexion normal : valide le token
    if (!nodeToken || !serverId) {
      return next(new Error('nodeToken et serverId requis'));
    }
    if (typeof nodeToken !== 'string' || !isId(serverId)) {
      return next(new Error('nodeToken et serverId requis'));
    }
    const result = await serviceProxy.servers.validateNodeToken(nodeToken) as any;
    if (!result || result.serverId !== serverId) {
      return next(new Error('Token de node invalide — serverId ne correspond pas'));
    }
    // L'endpoint HTTP est déclaré par le node : il est validé ICI, une fois,
    // avant d'être mémorisé. Le gateway y envoie ensuite un secret interne —
    // un endpoint arbitraire valait exfiltration de secret + SSRF.
    const rawEndpoint = socket.handshake.auth.endpoint;
    if (rawEndpoint !== undefined && rawEndpoint !== null && rawEndpoint !== '') {
      const validated = await validateNodeEndpoint(rawEndpoint);
      if (!validated) {
        logger.warn(`Endpoint de node refusé pour ${serverId}: ${String(rawEndpoint).slice(0, 120)}`);
        return next(new Error('Endpoint invalide — une origine HTTPS publique est requise (ni IP privée, ni chemin)'));
      }
      (socket as any).nodeEndpoint = validated;
    }
    (socket as any).serverId = serverId;
    next();
  } catch (err: any) {
    logger.error({ err: err?.message || err }, 'Erreur authentification server-node:');
    // Pas de détail interne côté client.
    next(new Error('Authentification server-node échouée'));
  }
});

serverNodesNs.on('connection', async (nodeSocket) => {
  // ── Mode auto-enregistrement ───────────────────────────────────────
  if ((nodeSocket as any).registerMode) {
    const serverName: string | undefined = nodeSocket.handshake.auth.name;
    const registerOwnerId: string = (nodeSocket as any).registerOwnerId;
    try {
      const result = await serviceProxy.servers.registerNode(serverName, registerOwnerId) as any;
      if (!result || !result.serverId) {
        nodeSocket.emit('REGISTER_ERROR', { message: 'Échec de la création du serveur' });
        nodeSocket.disconnect();
        return;
      }
      logger.info(`✅ Serveur auto-enregistré: ${result.serverName} (${result.serverId}) par ${registerOwnerId}`);
      nodeSocket.emit('REGISTERED', {
        serverId: result.serverId,
        nodeToken: result.nodeToken,
        serverName: result.serverName,
        inviteCode: result.inviteCode,
      });
    } catch (err) {
      logger.error({ err }, 'Erreur lors de l\'auto-enregistrement du server-node:');
      nodeSocket.emit('REGISTER_ERROR', { message: 'Erreur interne du gateway' });
    }
    nodeSocket.disconnect();
    return;
  }

  const serverId: string = (nodeSocket as any).serverId;
  // Endpoint déjà validé dans le middleware d'authentification du namespace ;
  // ne JAMAIS relire handshake.auth.endpoint ici.
  const endpoint: string | undefined = (nodeSocket as any).nodeEndpoint;

  logger.info(`🟢 Server-node connecté: serverId=${serverId} endpoint=${endpoint || 'n/a'}`);

  connectedNodes.set(serverId, {
    socketId: nodeSocket.id,
    serverId,
    endpoint,
    connectedAt: new Date(),
  });

  // ── Générer un code admin à usage unique ──────────────────────────────
  // À chaque connexion du node, un nouveau code est généré et affiché dans
  // la console du server-node. Ce code permet à l'hôte de réclamer les
  // droits admin depuis le frontend. Il expire en 15 min et est invalidé
  // dès qu'il est utilisé.
  // 14 caractères (alphabet 32) = ~70 bits d'entropie — hors de portée du brute-force
  // même en contournant la limite par IP (AUTH_BRUTEFORCE_REGEX).
  const setupCode = (() => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = randomBytes(14);
    let code = '';
    for (let i = 0; i < 14; i++) code += chars[bytes[i] % chars.length];
    return code;
  })();
  await redis.set(`setup_code:${serverId}`, setupCode, 900); // 15 min
  nodeSocket.emit('SETUP_CODE', { code: setupCode, serverId, expiresIn: 900 });

  // Secret propre à ce serveur, remis au node sur ce canal authentifié
  // (nodeToken). Le node s'en sert pour authentifier les requêtes HTTP du
  // gateway : il n'a plus jamais besoin du INTERNAL_SECRET maître, que
  // `.env.example` demandait de « réclamer à l'opérateur ».
  nodeSocket.emit('NODE_SECRET', { secret: deriveNodeSecret(serverId) });
  logger.info(`🔑 Code admin généré pour serverId=${serverId}`);

  // Notifier tous les membres connectés que le serveur est maintenant en ligne
  io.to(`server:${serverId}`).emit('SERVER_NODE_ONLINE', {
    type: 'SERVER_NODE_ONLINE',
    payload: { serverId },
    timestamp: new Date(),
  });

  // Le node broadcast un message après l'avoir stocké dans SQLite
  // NODE_BROADCAST est le canal unifié pour tous les broadcasts du node
  // SÉCURITÉ : Valider que les broadcasts ne ciblent que le serveur de ce node
  nodeSocket.on('NODE_BROADCAST', async (data: { event: string; data: any }) => {
    const { event, data: payload } = data ?? ({} as any);
    if (typeof event !== 'string' || !payload || typeof payload !== 'object') return;
    if (payload.channelId !== undefined && !isId(payload.channelId)) return;

    // Vérifier que le serverId du payload appartient au node connecté
    if (payload?.serverId && payload.serverId !== serverId) {
      logger.warn(`NODE_BROADCAST rejeté: node ${serverId} tente de broadcast vers serveur ${payload.serverId}`);
      return;
    }
    // …et que le salon visé lui appartient aussi. Le contrôle ci-dessus ne se
    // déclenchait que si `serverId` était présent dans le payload : en
    // l'omettant, un node diffusait dans le salon de n'importe quel autre
    // serveur (la branche `default` route vers `channel:${payload.channelId}`).
    if (payload?.channelId && !(await nodeOwnsChannel(serverId, payload.channelId))) {
      logger.warn(`NODE_BROADCAST rejeté: salon ${payload.channelId} n'appartient pas au serveur ${serverId}`);
      return;
    }

    switch (event) {
      // ── Messages ──
      case 'MSG_BROADCAST':
        if (!payload.channelId) return;
        io.to(chRoom(serverId, payload.channelId)).emit('SERVER_MESSAGE_NEW', {
          type: 'SERVER_MESSAGE_NEW',
          payload: payload.message,
          timestamp: new Date(),
        });
        break;

      case 'MSG_EDIT':
        if (!payload.channelId) return;
        io.to(chRoom(serverId, payload.channelId)).emit('SERVER_MESSAGE_EDITED', {
          type: 'SERVER_MESSAGE_EDITED',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      case 'MSG_DELETE':
        if (!payload.channelId) return;
        io.to(chRoom(serverId, payload.channelId)).emit('SERVER_MESSAGE_DELETED', {
          type: 'SERVER_MESSAGE_DELETED',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      // ── Channels ──
      case 'CHANNEL_CREATE':
        io.to(`server:${serverId}`).emit('CHANNEL_CREATE', {
          type: 'CHANNEL_CREATE',
          payload: { ...payload.channel, serverId },
          timestamp: new Date(),
        });
        break;

      case 'CHANNEL_UPDATE':
        io.to(`server:${serverId}`).emit('CHANNEL_UPDATE', {
          type: 'CHANNEL_UPDATE',
          payload: { ...payload.channel, serverId },
          timestamp: new Date(),
        });
        break;

      case 'CHANNEL_DELETE':
        io.to(`server:${serverId}`).emit('CHANNEL_DELETE', {
          type: 'CHANNEL_DELETE',
          payload: { channelId: payload.channelId, serverId },
          timestamp: new Date(),
        });
        break;

      // ── Roles ──
      case 'ROLE_CREATE':
        io.to(`server:${serverId}`).emit('ROLE_CREATE', {
          type: 'ROLE_CREATE',
          payload: { ...payload.role, serverId },
          timestamp: new Date(),
        });
        break;

      case 'ROLE_UPDATE':
        io.to(`server:${serverId}`).emit('ROLE_UPDATE', {
          type: 'ROLE_UPDATE',
          payload: { ...payload.role, serverId },
          timestamp: new Date(),
        });
        break;

      case 'ROLE_DELETE':
        io.to(`server:${serverId}`).emit('ROLE_DELETE', {
          type: 'ROLE_DELETE',
          payload: { roleId: payload.roleId, serverId },
          timestamp: new Date(),
        });
        break;

      // ── Membres ──
      case 'MEMBER_JOIN':
        io.to(`server:${serverId}`).emit('MEMBER_JOIN', {
          type: 'MEMBER_JOIN',
          payload: { ...payload.member, serverId },
          timestamp: new Date(),
        });
        break;

      case 'MEMBER_UPDATE':
        io.to(`server:${serverId}`).emit('MEMBER_UPDATE', {
          type: 'MEMBER_UPDATE',
          payload: { ...payload.member, serverId },
          timestamp: new Date(),
        });
        break;

      case 'MEMBER_KICK':
        io.to(`server:${serverId}`).emit('MEMBER_LEAVE', {
          type: 'MEMBER_LEAVE',
          payload: { serverId, userId: payload.userId, kicked: true },
          timestamp: new Date(),
        });
        break;

      case 'MEMBER_BAN':
        io.to(`server:${serverId}`).emit('MEMBER_LEAVE', {
          type: 'MEMBER_LEAVE',
          payload: { serverId, userId: payload.userId, banned: true },
          timestamp: new Date(),
        });
        break;

      // ── Server info ──
      case 'SERVER_UPDATE':
        io.to(`server:${serverId}`).emit('SERVER_UPDATE', {
          type: 'SERVER_UPDATE',
          payload: { id: serverId, ...payload },
          timestamp: new Date(),
        });
        break;

      // ── Typing ──
      case 'TYPING_START':
        if (!payload.channelId) return;
        io.to(chRoom(serverId, payload.channelId)).emit('SERVER_TYPING_START', {
          type: 'SERVER_TYPING_START',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      case 'TYPING_STOP':
        if (!payload.channelId) return;
        io.to(chRoom(serverId, payload.channelId)).emit('SERVER_TYPING_STOP', {
          type: 'SERVER_TYPING_STOP',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      // ── Autres événements : LISTE BLANCHE. Le relais « tel quel » de
      // n'importe quel nom d'événement permettait à un node malveillant de
      // forger des événements plateforme (message:new, CALL_INCOMING,
      // MODERATION_ENFORCED, FRIEND_REQUEST…) chez tous ses membres.
      default: {
        if (!NODE_PASSTHROUGH_EVENTS.has(event)) {
          logger.warn(`NODE_BROADCAST rejeté: événement non autorisé "${String(event).slice(0, 64)}" depuis ${serverId}`);
          return;
        }
        const room = payload.channelId
          ? chRoom(serverId, payload.channelId)
          : `server:${serverId}`;
        io.to(room).emit(event, {
          type: event,
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;
      }
    }
  });

  // Legacy: support MSG_BROADCAST direct (compat). Même contrôle d'appartenance
  // du salon que NODE_BROADCAST — il n'en avait aucun.
  nodeSocket.on('MSG_BROADCAST', async (data: { channelId: string; message: any }) => {
    if (!isId(data?.channelId) || !(await nodeOwnsChannel(serverId, data.channelId))) {
      logger.warn(`MSG_BROADCAST rejeté: salon ${data?.channelId} hors du serveur ${serverId}`);
      return;
    }
    io.to(chRoom(serverId, data.channelId)).emit('SERVER_MESSAGE_NEW', {
      type: 'SERVER_MESSAGE_NEW',
      payload: data.message,
      timestamp: new Date(),
    });
  });

  // Status du node
  nodeSocket.on('NODE_STATUS', (data: { serverId: string; status: string; name: string; memberCount: number }) => {
    logger.info(`📊 Node status: ${data.name} — ${data.memberCount} membres — ${data.status}`);
  });

  nodeSocket.on('disconnect', () => {
    // Ne supprimer que si c'est bien CE socket qui est enregistré
    // (évite la race condition lors d'une reconnexion rapide)
    const current = connectedNodes.get(serverId);
    if (current && current.socketId === nodeSocket.id) {
      logger.info(`🔴 Server-node déconnecté: serverId=${serverId}`);
      connectedNodes.delete(serverId);
      io.to(`server:${serverId}`).emit('SERVER_NODE_OFFLINE', {
        type: 'SERVER_NODE_OFFLINE',
        payload: { serverId },
        timestamp: new Date(),
      });
    } else {
      logger.info(`🔄 Ancien socket du server-node déconnecté (remplacé): serverId=${serverId}`);
    }
  });
});

// ============ FONCTIONS UTILITAIRES ============

function emitToSocket(socket: Socket, type: GatewayEventType | string, payload: unknown): void {
  socket.emit(type, {
    type,
    payload,
    timestamp: new Date(),
  } as GatewayEvent);
}

function emitError(socket: Socket, type: string, error: unknown): void {
  let message = error instanceof Error ? error.message : 'Une erreur est survenue';
  // « Service error: 403 {...corps brut...} » : ne renvoyer au client que le
  // champ `error` du service, jamais le corps complet (détails internes).
  const m = /^Service error: (\d{3}) (.*)$/s.exec(message);
  if (m) {
    let clean = `Erreur ${m[1]}`;
    try {
      const body = JSON.parse(m[2]);
      if (typeof body?.error === 'string') clean = body.error;
    } catch { /* corps non JSON : code seul */ }
    message = clean;
  }
  socket.emit('ERROR', {
    type,
    payload: { message },
    timestamp: new Date(),
  });
}

async function broadcastPresenceUpdate(
  userId: string,
  status: string,
  friends: Array<{ friendId?: string; id?: string }>,
  text?: string | null,
  emoji?: string | null,
): Promise<void> {
  // Les amis voient 'offline' quand l'utilisateur est en mode invisible, ou
  // quand il a désactivé « afficher mon statut en ligne » (réglage jusqu'ici
  // enregistré mais jamais appliqué).
  const hidden = status !== 'offline' && await isPresenceHidden(userId).catch(() => false);
  const visibleStatus = status === 'invisible' || hidden ? 'offline' : status;
  const presencePayload = {
    type: 'PRESENCE_UPDATE',
    payload: {
      userId,
      status: visibleStatus,
      customStatus: hidden ? null : (text ?? null), // compat ascendante
      text: hidden ? null : (text ?? null),
      emoji: hidden ? null : (emoji ?? null),
    },
    timestamp: new Date(),
  };

  const recipients = new Set<string>();
  for (const friend of friends) {
    const fid = friend.friendId ?? (friend as any).id;
    if (fid) recipients.add(fid);
  }

  // Sans amitié, la liste des MP d'un utilisateur ne recevait jamais ses mises
  // à jour de présence (le broadcast ne visait que la liste d'amis) : le
  // statut affiché restait figé à sa valeur de chargement initial pour tout
  // contact avec qui on discute sans être ami. On ajoute donc les
  // destinataires de ses conversations privées.
  try {
    const conversations = await serviceProxy.messages.getConversations(userId);
    for (const conv of conversations as Array<{ type?: string; recipientId?: string }>) {
      if (conv.type === 'dm' && conv.recipientId) recipients.add(conv.recipientId);
    }
  } catch { /* non bloquant — la présence reste diffusée aux amis au minimum */ }

  // Membres des serveurs en commun : sans eux, la liste des membres d'un
  // serveur ne bougeait jamais (statut figé au chargement). Une seule émission
  // vers toutes les rooms : Socket.IO ne livre qu'une fois par socket.
  const rooms = [...recipients].map((fid) => `user:${fid}`);
  try {
    const cached = await redis.getUserRooms(userId);
    for (const sid of cached?.serverIds ?? []) if (isId(sid)) rooms.push(`server:${sid}`);
  } catch { /* non bloquant — amis et MP au minimum */ }
  if (rooms.length > 0) io.to(rooms).emit('PRESENCE_UPDATE', presencePayload);
}

// ============ DÉMARRAGE ============

/**
 * Charge les instances de service depuis la DB MySQL et les enregistre dans le registre.
 * Fallback sur les URL d'environnement si la DB n'est pas disponible.
 */
async function loadInstancesFromDB(): Promise<void> {
  const rows = await monitoringDB.loadServiceInstances();
  if (rows.length > 0) {
    let loaded = 0;
    for (const row of rows) {
      serviceRegistry.register({
        id: row.id,
        serviceType: row.serviceType as ServiceType,
        endpoint: row.endpoint,
        domain: row.domain,
        location: row.location,
        metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 0, bandwidthUsage: 0, requestCount20min: 0 },
        enabled: row.enabled,
      });
      // Whitelist : tous les IDs en DB sont autorisés à heartbeater
      allowedServiceIds.add(row.id);
      if (row.serviceKeyHash) serviceKeyHashes.set(row.id, row.serviceKeyHash);
      if (!row.enabled) bannedServiceIds.add(row.id);
      else loaded++;
    }
    logger.info(`ServiceRegistry: ${loaded} instances actives + ${rows.length - loaded} désactivées chargées depuis la DB`);
    return;
  }

  // Fallback: aucune entrée en DB → utiliser les vars d'environnement
  const location = (process.env.DEFAULT_LOCATION || 'EU').toUpperCase();
  const defaults: Array<{ id: string; type: ServiceType; url: string }> = [
    { id: 'users-default',    type: 'users',    url: USERS_URL },
    { id: 'messages-default', type: 'messages', url: MESSAGES_URL },
    { id: 'friends-default',  type: 'friends',  url: FRIENDS_URL },
    { id: 'calls-default',    type: 'calls',    url: CALLS_URL },
    { id: 'servers-default',  type: 'servers',  url: SERVERS_URL },
    { id: 'bots-default',     type: 'bots',     url: BOTS_URL },
    { id: 'media-default',    type: 'media',    url: MEDIA_URL },
  ];

  for (const d of defaults) {
    let domain = d.url;
    try { domain = new URL(d.url).host; } catch { /* url invalide, on garde tel quel */ }
    serviceRegistry.register({
      id: d.id,
      serviceType: d.type,
      endpoint: d.url,
      domain,
      location,
      metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 0, bandwidthUsage: 0, requestCount20min: 0 },
    });
  }
  logger.info(`ServiceRegistry: ${defaults.length} instances initialisées depuis les vars d'environnement (fallback)`);
}

httpServer.listen(PORT, async () => {
  logger.info(`🚀 Gateway AlfyChat démarré sur le port ${PORT}`);
  logger.info(`📡 WebSocket prêt à recevoir des connexions`);

  // Init monitoring DB and start collection loop
  await monitoringDB.init();
  await loadInstancesFromDB();

  // Enregistrer ce gateway dans le registry (multi-gateway)
  const GATEWAY_ID   = process.env.GATEWAY_ID   || 'gateway-default';
  const GATEWAY_NAME = process.env.GATEWAY_NAME  || 'Gateway Principal';
  const GATEWAY_URL  = process.env.GATEWAY_PUBLIC_URL || `http://localhost:${PORT}`;
  gatewayRegistry.register({ id: GATEWAY_ID, name: GATEWAY_NAME, url: GATEWAY_URL, isSelf: true });
  monitoringDB.upsertGateway({ id: GATEWAY_ID, name: GATEWAY_NAME, url: GATEWAY_URL, enabled: true }).catch(() => {});
  // Charger les autres gateways depuis la DB
  const storedGateways = await monitoringDB.loadGateways();
  for (const gw of storedGateways) {
    if (gw.id !== GATEWAY_ID) gatewayRegistry.register({ ...gw });
  }

  // ── Hot-reload guard : clear previous intervals created by bun --hot ──
  const g = globalThis as any;
  if (g.__gw_monitoringInterval) clearInterval(g.__gw_monitoringInterval);
  if (g.__gw_pruneInterval) clearInterval(g.__gw_pruneInterval);

  // First cycle immediately, then every MONITORING_INTERVAL_MS
  runMonitoringCycle(connectedClients.size).catch((err) => logger.error({ err: err }, 'Monitoring cycle error:'));
  g.__gw_monitoringInterval = setInterval(() => {
    runMonitoringCycle(connectedClients.size).catch((err) => logger.error({ err: err }, 'Monitoring cycle error:'));
  }, MONITORING_INTERVAL_MS);
  // Daily prune at startup + every 24h
  monitoringDB.prune(30).catch(() => {});
  g.__gw_pruneInterval = setInterval(() => monitoringDB.prune(30).catch(() => {}), 24 * 60 * 60 * 1000);
});

// Gestion de l'arrêt gracieux
// -- HTML error pages (browser content-negotiation) --------------------------
app.get('/', (req, res, next) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.sendFile(path.join(__dirname, '../public/index.html'));
  next();
});
app.use((req, res) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.status(404).sendFile(path.join(__dirname, '../public/errors/404.html'));
  res.status(404).json({ error: 'Route not found', path: req.path });
});
app.use((err: any, req: any, res: any, _next: any) => {
  if (req.accepts(['html', 'json']) === 'html')
    return res.status(500).sendFile(path.join(__dirname, '../public/errors/500.html'));
  res.status(500).json({ error: 'Internal server error' });
});

process.on('SIGTERM', async () => {
  logger.info('Signal SIGTERM reçu, arrêt gracieux...');
  
  // Fermer les connexions WebSocket
  io.close();
  
  // Fermer Redis
  await redis.disconnect();
  
  process.exit(0);
});

export { io, redis, serviceProxy, connectedNodes, serverNodesNs };
