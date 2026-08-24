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
  validateProfile, validateGroupInput, validateServerInput, validateChannelInput,
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
  proxyRequest, proxyToNode, proxyToNodeMultipart, proxyMultipartToService, proxyToMedia,
} from './http/proxy';
import { apiVersionMiddleware } from './http/api-version';
import {
  serviceKeyHashes, bannedServiceIds, allowedServiceIds,
  generateServiceKey, validateServiceSecret,
} from './state/service-keys';
import { requireAdmin } from './monitoring/admin-guard';
import { runMonitoringCycle, MONITORING_INTERVAL_MS } from './monitoring/cycle';
import { anomalyMiddleware, attachAnomalyWsHooks } from './monitoring/anomaly';
import { connectedClients, connectedNodes, voiceChannels, userVoiceChannel } from './state/connections';
import type { VoiceParticipant } from './state/connections';
import { isDmBlocked, invalidateBlockCache } from './state/block-cache';
import { checkMessageRate, checkServerJoinRate, checkInviteVerifyRate, checkNodeRegisterRate } from './state/rate-limit';
import { validateNodeEndpoint } from './utils/node-endpoint';
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
    !/^http:\/\/localhost(:\d+)?$/.test(origin)
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
      const decoded = jwt.verify(token, JWT_SECRET) as any;
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

// Ne pas parser le JSON sur /api/media/* (multipart/form-data) ni les uploads multipart vers les nodes
app.use((req, res, next) => {
  if (req.path.startsWith('/api/media')) return next();
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
  if (req.method !== 'POST') return next();
  const hit =
    AUTH_BRUTEFORCE_PATHS.some((p) => req.path === p || req.path.startsWith(p + '/'))
    || AUTH_BRUTEFORCE_REGEX.some((re) => re.test(req.path));
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
registerServersRoutes(app);
// Routes OAuth2 (avant /api/bots pour éviter les conflits de pattern)
app.all('/api/oauth2/*', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
app.all('/api/oauth2', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
// Routes Bots
app.all('/api/bots/*', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
app.all('/api/bots', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res, BOTS_URL, 'bots'));
// Routes Hébergement serveurs (ServerHosting)
app.all('/api/subscriptions/webhooks/*', (req, res) => proxyRequest(SUBSCRIPTIONS_URL, req, res));
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
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Accès interne requis' });
  }
  const { callId, tier, participantCount, tierParams } = req.body;
  if (!callId || tier === undefined) {
    return res.status(400).json({ error: 'callId et tier requis' });
  }
  broadcastQualityUpdate(io, callId, tier, participantCount, tierParams);
  res.json({ success: true });
});

// ── Endpoint interne : le service users applique une sanction en direct ──
// Un ban/kick doit couper la session immédiatement, sans attendre l'expiration du JWT.
app.post('/internal/moderation/enforce', express.json(), (req, res) => {
  const secret = req.headers['x-internal-secret'];
  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Accès interne requis' });
  }
  const { userId, type, reason, expiresAt } = req.body ?? {};
  if (!userId || !type) {
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

    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };

    // Vérifier l'utilisateur et son statut de modération via le service users
    const [user, moderation] = await Promise.all([
      serviceProxy.users.getUser(decoded.userId) as Promise<User | null>,
      serviceProxy.users.getModerationStatus(decoded.userId).catch(() => null),
    ]);

    if (!user) {
      return next(new Error('Utilisateur non trouvé'));
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
  const ids: string[] = Array.isArray(mentionedUserIds)
    ? (mentionedUserIds as string[]).filter((id) => id && id !== senderId)
    : [];
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
    return;
  }
  // Changement de rôle → tous les membres du serveur sont concernés.
  redis.deleteByPattern(`perm:${serverId}:*`).catch(() => {});
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

/** Remove a user from their current voice channel and notify others */
function leaveVoiceChannel(userId: string, socket: AuthenticatedSocket) {
  const channelId = userVoiceChannel.get(userId);
  if (!channelId) return;

  const participants = voiceChannels.get(channelId);
  const participant = participants?.get(userId);
  const serverId = participant?.serverId;

  participants?.delete(userId);
  userVoiceChannel.delete(userId);
  socket.leave(`voice:${channelId}`);

  // Clean up empty channels
  if (participants && participants.size === 0) {
    voiceChannels.delete(channelId);
  }

  if (serverId) {
    // Notify remaining participants
    socket.to(`voice:${channelId}`).emit('VOICE_USER_LEFT', {
      channelId,
      userId,
    });

    // Broadcast updated voice state
    const remaining = participants ? Array.from(participants.values()).map(p => ({
      userId: p.userId,
      username: p.username,
      avatarUrl: p.avatarUrl,
      muted: p.muted,
      deafened: p.deafened,
    })) : [];

    io.to(`server:${serverId}`).emit('VOICE_STATE_UPDATE', {
      channelId,
      serverId,
      participants: remaining,
    });

    logger.info(`User ${userId} left voice channel ${channelId}`);
  }
}

io.on('connection', async (socket: AuthenticatedSocket) => {
  const { userId, sessionId, user } = socket;
  const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
  
  if (!userId || !sessionId || !user) {
    socket.disconnect();
    return;
  }

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

  // Joindre automatiquement toutes les conversations DM de l'utilisateur
  try {
    const friends = await serviceProxy.friends.getFriends(userId);
    if (friends && Array.isArray(friends)) {
      for (const friend of friends) {
        const sortedIds = [userId, friend.id].sort();
        const dmConversationId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
        socket.join(`conversation:${dmConversationId}`);
      }
    }
  } catch (error) {
    logger.warn({ err: error }, 'Erreur join des rooms DM');
  }

  // Joindre automatiquement toutes les conversations de groupe de l'utilisateur
  try {
    const groupConversations = await serviceProxy.messages.getConversations(userId);
    if (groupConversations && Array.isArray(groupConversations)) {
      for (const conv of groupConversations) {
        const convId = conv.id || conv.conversationId;
        if (convId && !String(convId).startsWith('dm_')) {
          socket.join(`conversation:${convId}`);
        }
      }
      const groupCount = groupConversations.filter((c: any) => {
        const cid = c.id || c.conversationId;
        return cid && !String(cid).startsWith('dm_');
      }).length;
      if (groupCount > 0) logger.info(`${user.username} auto-joined ${groupCount} group conversation rooms`);
    }
  } catch (error) {
    logger.warn({ err: error }, 'Erreur join des rooms de groupe');
  }

  // Joindre automatiquement tous les serveurs dont l'utilisateur est membre
  try {
    // ── Chemin rapide : restaurer depuis le cache Redis (évite NOT_A_CHANNEL_MEMBER au redémarrage) ──
    try {
      const cached = await redis.getUserRooms(userId);
      if (cached) {
        for (const sid of cached.serverIds) socket.join(`server:${sid}`);
        for (const cid of cached.channelIds) socket.join(`channel:${cid}`);
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
        if (!sid) return;
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
            const chResult = await forwardToNode(sid, 'CHANNEL_LIST', {});
            channels = chResult?.channels || [];
          } catch {
            const server: any = await serviceProxy.servers.getServer(sid);
            channels = server?.channels || [];
          }
          for (const ch of channels) {
            socket.join(`channel:${ch.id}`);
            allChannelIds.push(ch.id);
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

  // Notifier les amis seulement (plus de broadcast serveur — member-list utilise GET_BULK_PRESENCE)
  broadcastPresenceUpdate(userId, chosenStatus, friends, restoredText, restoredEmoji);

  // Envoyer les pings en attente (messages reçus hors ligne) — DB + Redis
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
      const v = validateMessageContent(data?.content, data?.attachments, data?.e2eeType);
      data = { ...data, content: v.content, ...(v.attachments ? { attachments: v.attachments } : {}) };
      const message = await serviceProxy.messages.createMessage({
        ...data,
        senderId: userId,
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

      // ── Vérification de blocage (DM uniquement) ──
      // Si l'un des deux utilisateurs a bloqué l'autre, on refuse l'envoi.
      if (data.recipientId && typeof data.recipientId === 'string' && data.recipientId !== userId) {
        const blocked = await isDmBlocked(userId, data.recipientId);
        if (blocked) {
          socket.emit('message:error', { error: 'BLOCKED', message: 'Vous ne pouvez pas envoyer de message à cet utilisateur.' });
          return;
        }
      }

      // ── Construire le conversationId ──
      let conversationId: string = data.conversationId || data.channelId;
      if (!conversationId && data.recipientId) {
        const sortedIds = [userId, data.recipientId].sort();
        conversationId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
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
      }).then((message: any) => {
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

        // Mentions dans les messages de groupe (@username → mentionedUserIds)
        const mentionedUserIds: string[] = Array.isArray(data.mentionedUserIds)
          ? (data.mentionedUserIds as string[]).filter((id: string) => id && id !== userId)
          : [];
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
        socket.emit('message:failed', {
          messageId,
          error: 'Échec de la sauvegarde — veuillez réessayer',
          detail: err?.message || String(err),
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
      const sortedIds = [userId, recipientId].sort();
      roomId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
    } else if (conversationId) {
      // Vérifier que l'utilisateur est bien participant avant de joindre
      if ((conversationId as string).startsWith('dm_')) {
        // DM déterministe — vérifier que userId fait partie du room ID
        if (!(conversationId as string).includes(userId)) {
          socket.emit('conversation:join:error', { error: 'Accès non autorisé' });
          return;
        }
        roomId = conversationId;
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
  socket.on('e2ee:history-request', async (data: { recipientId: string; conversationId: string }) => {
    if (!data.recipientId || !data.conversationId) return;
    // Only allow requests for DM conversations where userId is a participant
    if (!data.conversationId.startsWith('dm_') || !data.conversationId.includes(userId)) return;
    // Vérifier si le destinataire est connecté (même source que le bandeau d'ami)
    const isRecipientOnline = await redis.isUserOnline(data.recipientId);
    if (!isRecipientOnline) {
      // Destinataire hors ligne → notifier l'expéditeur immédiatement
      socket.emit('e2ee:history-error', { reason: 'recipient_offline', conversationId: data.conversationId });
      return;
    }
    logger.info(`[E2EE] History request from ${userId} to ${data.recipientId} for ${data.conversationId}`);
    io.to(`user:${data.recipientId}`).emit('e2ee:history-request', {
      requesterId: userId,
      conversationId: data.conversationId,
    });
  });

  // User B responds with re-encrypted messages
  socket.on('e2ee:history-response', (data: {
    requesterId: string;
    conversationId: string;
    messages: Array<{ id: string; content: string; senderId: string; createdAt: string }>;
  }) => {
    if (!data.requesterId || !data.conversationId || !data.messages) return;
    if (!data.conversationId.startsWith('dm_') || !data.conversationId.includes(userId)) return;
    // Cap at 500 messages per response to prevent abuse
    const msgs = data.messages.slice(0, 500);
    logger.info(`[E2EE] History response from ${userId} to ${data.requesterId}: ${msgs.length} messages`);
    io.to(`user:${data.requesterId}`).emit('e2ee:history-response', {
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
      const { conversationId, messageId, beforeDate, limit } = data;
      const requestId = uuidv4();
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');

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
      const { requestId, conversationId, messages, requesterId } = data;

      // Valider que l'utilisateur fait partie de la conversation
      // Le conversationId DM a le format dm_<userId1>_<userId2> (triés)
      if (conversationId && conversationId.startsWith('dm_')) {
        const parts = conversationId.replace('dm_', '').split('_');
        if (!parts.includes(userId)) {
          logger.warn(`DM_ARCHIVE_PEER_RESPONSE rejeté: ${userId} n'est pas participant de ${conversationId}`);
          return;
        }
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
      const request = await serviceProxy.friends.sendFriendRequest(userId, data.toUserId, data.message);
      
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
      logger.info(`CALL_INITIATE DM de ${userId} (${user?.username}) vers ${data.recipientId || '?'} type=${data.type}`);

      let conversationId = data.conversationId;
      if (!conversationId && data.recipientId) {
        const sortedIds = [userId, data.recipientId].sort();
        conversationId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
      }

      const call = await serviceProxy.calls.initiateCall({
        type: data.type,
        initiatorId: userId,
        conversationId,
        recipientId: data.recipientId,
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

      if (!data.channelId) {
        if (typeof callback === 'function') callback({ error: 'channelId requis' });
        return;
      }

      const groupCall = await serviceProxy.calls.createGroupCall({
        channelId: data.channelId,
        initiatorId: userId,
        type: data.type || 'voice',
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
      socket.to(`channel:${data.channelId}`).emit('CALL_INCOMING', incomingGroupPayload);
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

      // Confirmer au nouvel arrivant avec la liste des participants existants (pour créer les PCs)
      if (typeof callback === 'function') {
        callback({ callId, existingParticipants, callMode });
      } else {
        socket.emit('CALL_JOIN_ACK', { callId, existingParticipants, callMode });
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
  const relayWebrtc = (event: 'WEBRTC_OFFER' | 'WEBRTC_ANSWER' | 'WEBRTC_ICE_CANDIDATE', data: any, payload: Record<string, unknown>) => {
    const callId = data?.callId;
    if (!callId || typeof callId !== 'string') return;
    if (!socket.rooms.has(`call:${callId}`)) {
      logger.warn(`${event} refusé : ${userId} n'est pas dans l'appel ${callId}`);
      return;
    }
    const target = data.targetUserId ? `user:${data.targetUserId}` : `call:${callId}`;
    io.to(target).emit(event, {
      type: event,
      payload: { callId, fromUserId: userId, ...payload },
      timestamp: new Date(),
    });
  };

  socket.on('WEBRTC_OFFER', (data) => relayWebrtc('WEBRTC_OFFER', data, { offer: data?.offer }));
  socket.on('WEBRTC_ANSWER', (data) => relayWebrtc('WEBRTC_ANSWER', data, { answer: data?.answer }));
  socket.on('WEBRTC_ICE_CANDIDATE', (data) => relayWebrtc('WEBRTC_ICE_CANDIDATE', data, { candidate: data?.candidate }));

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

      if (!data.channelId || !data.serverId) {
        if (typeof callback === 'function') callback({ error: 'channelId et serverId requis' });
        return;
      }

      // Aucun contrôle d'accès auparavant : n'importe quel compte ouvrait un
      // appel dans le salon de n'importe quel serveur.
      if (!(await checkServerPermission(userId, data.serverId, PERM.READ))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }

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

      const call = await serviceProxy.calls.createServerCall({
        channelId: data.channelId,
        serverId: data.serverId,
        initiatorId: userId,
        type: data.type || 'voice',
      }) as { id: string; callCategory: string };

      const callId = call.id;
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

      // Notifier le canal (bannière passive, pas de dialogue modal)
      io.to(`channel:${data.channelId}`).emit('CALL_INCOMING', {
        type: 'CALL_INCOMING',
        payload: {
          callId,
          channelId: data.channelId,
          serverId: data.serverId,
          callCategory: 'server',
          isGroup: false,
          initiatorId: userId,
          callerName: (socket as any).user?.displayName || (socket as any).user?.username || userId,
          callType: data.type || 'voice',
        },
        timestamp: new Date(),
      });

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
      // Toujours enregistrer dans le microservice (annuaire central)
      const member = await serviceProxy.servers.joinServer(data.serverId, userId);
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
        const chResult = await forwardToNode(data.serverId, 'CHANNEL_LIST', {});
        if (chResult?.channels) {
          for (const ch of chResult.channels) {
            socket.join(`channel:${ch.id}`);
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
        // Pas de node → charger channels depuis microservice
        try {
          const server = await serviceProxy.servers.getServer(data.serverId);
          if (server?.channels) {
            for (const channel of server.channels) {
              socket.join(`channel:${channel.id}`);
            }
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
      if (!serverId) return;

      // Vérifier que l'user est vraiment membre (il vient de rejoindre via HTTP)
      const isMember = await serviceProxy.servers.isMember(serverId, userId).catch(() => false);
      if (!isMember) {
        socket.emit('SERVER_ERROR', { type: 'SERVER_ERROR', error: 'NOT_A_MEMBER', serverId });
        return;
      }

      // Rejoindre les rooms socket (si pas déjà dedans)
      socket.join(`server:${serverId}`);

      let serverInfo: any = null;
      try {
        // Charger les channels depuis le node
        const chResult = await forwardToNode(serverId, 'CHANNEL_LIST', {});
        if (chResult?.channels) {
          for (const ch of chResult.channels) {
            socket.join(`channel:${ch.id}`);
          }
        }
      } catch {
        // Fallback microservice
        try {
          serverInfo = await serviceProxy.servers.getServer(serverId);
          if (serverInfo?.channels) {
            for (const ch of serverInfo.channels) {
              socket.join(`channel:${ch.id}`);
            }
          }
        } catch { /* ignore */ }
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
      await serviceProxy.servers.leaveServer(data.serverId, userId);
      invalidateServerPerms(data.serverId, userId);
      socket.leave(`server:${data.serverId}`);

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
      const { serverId, channelId, replyToId } = data;
      if (!serverId || !channelId) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('INVALID_PAYLOAD'));
        return;
      }
      // Cohérence channel/serveur : le channel room n'est rejoint qu'après
      // CHANNEL_JOIN/SERVER_JOIN qui valident la membership. Un user qui forge
      // channelId ne sera pas dans cette room.
      if (!socket.rooms.has(`channel:${channelId}`)) {
        // Fallback : vérifier la membership réelle (résout la race condition au redémarrage)
        const isMember = await serviceProxy.servers.isMember(serverId, userId).catch(() => false);
        if (!isMember) {
          emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('NOT_A_CHANNEL_MEMBER'));
          return;
        }
        // Ré-ajouter aux rooms manquantes
        socket.join(`server:${serverId}`);
        socket.join(`channel:${channelId}`);
      }
      // Permission SEND (0x2) — inclut déjà le check de membership côté server.
      if (!(await checkServerPermission(userId, serverId, PERM.SEND))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('PERMISSION_DENIED'));
        return;
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

      io.to(`channel:${channelId}`).emit('SERVER_MESSAGE_NEW', {
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
      const { serverId, messageId, channelId } = data;
      const content = v.content;

      // L'édition ne vérifiait RIEN côté gateway. Comme les appels sortants
      // partent en mode « internal » (qui court-circuite requireMember et
      // requirePerm côté microservice), c'était l'absence totale de contrôle.
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

      io.to(`channel:${channelId}`).emit('SERVER_MESSAGE_EDITED', {
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
      const { serverId, messageId, channelId } = data;

      // Idem SERVER_MESSAGE_EDIT : aucun contrôle auparavant. On exige au
      // minimum l'appartenance ; la propriété du message (auteur) ou
      // MANAGE_MESSAGES est vérifiée par le node / le microservice.
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

      io.to(`channel:${channelId}`).emit('SERVER_MESSAGE_DELETED', {
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
      const { serverId, channelId, messageId, emoji } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.REACT))) {
        emitError(socket, 'REACTION_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      await serviceProxy.servers.addServerReaction(serverId, messageId, userId, emoji);
      io.to(`channel:${channelId}`).emit('SERVER_REACTION_UPDATE', {
        type: 'SERVER_REACTION_UPDATE',
        payload: { messageId, userId, emoji, action: 'add' },
      });
    } catch (error) {
      emitError(socket, 'REACTION_ERROR', error);
    }
  });

  socket.on('SERVER_REACTION_REMOVE', async (data) => {
    try {
      const { serverId, channelId, messageId, emoji } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.REACT))) {
        emitError(socket, 'REACTION_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      await serviceProxy.servers.removeServerReaction(serverId, messageId, userId, emoji);
      io.to(`channel:${channelId}`).emit('SERVER_REACTION_UPDATE', {
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
      const { serverId, channelId, before, limit } = data;
      // Sans ce contrôle, n'importe quel compte lisait l'historique de
      // n'importe quel salon en connaissant serverId + channelId.
      if (!(await checkServerPermission(userId, serverId, PERM.READ))) {
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
      const messages = await serviceProxy.servers.getChannelMessages(serverId, channelId, limit, before);
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
      const channels = await serviceProxy.servers.getServerChannels(data.serverId);
      if (typeof callback === 'function') callback({ channels: channels || [] });
    } catch {
      if (typeof callback === 'function') callback({ channels: [], error: true });
    }
  });

  socket.on('CHANNEL_CREATE', async (data) => {
    try {
      const { serverId } = data;
      if (!(await checkServerPermission(userId, serverId, PERM.MANAGE_CHANNELS))) { // MANAGE_CHANNELS
        emitError(socket, 'CHANNEL_ERROR', new Error('PERMISSION_DENIED'));
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
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'CHANNEL_ERROR', e); return; }
      }
      // Fallback microservice
      const channel = await serviceProxy.servers.createChannel(serverId, { name: clean.name!, type: clean.type || 'text', parentId: clean.parentId }, userId, token);
      io.to(`server:${serverId}`).emit('CHANNEL_CREATE', {
        type: 'CHANNEL_CREATE',
        payload: channel,
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
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
      const channel = await serviceProxy.servers.updateChannel(serverId, channelId, { ...(data.updates || {}), ...clean }, userId, token);
      io.to(`server:${serverId}`).emit('CHANNEL_UPDATE', {
        type: 'CHANNEL_UPDATE',
        payload: channel,
        timestamp: new Date(),
      });
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
      io.to(`server:${serverId}`).emit('CHANNEL_DELETE', {
        type: 'CHANNEL_DELETE',
        payload: { channelId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CHANNEL_ERROR', error);
    }
  });

  // ── Channel Permissions ──
  socket.on('CHANNEL_PERMS_GET', async (data, callback) => {
    try {
      if (!(await checkServerPermission(userId, data.serverId, PERM.READ))) {
        if (typeof callback === 'function') callback({ permissions: [], error: 'PERMISSION_DENIED' });
        return;
      }
      const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_GET', { channelId: data.channelId });
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      if (typeof callback === 'function') callback({ permissions: [], error: e.message });
    }
  });

  socket.on('CHANNEL_PERMS_SET', async (data, callback) => {
    try {
      if (!(await checkServerPermission(userId, data.serverId, PERM.MANAGE_CHANNELS))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }
      const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_SET', {
        channelId: data.channelId,
        roleId: data.roleId,
        allow: data.allow,
        deny: data.deny,
        userId,
      });
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      if (e.message !== 'NO_NODE') emitError(socket, 'CHANNEL_ERROR', e);
      if (typeof callback === 'function') callback({ error: e.message });
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

  socket.on('ROLE_CREATE', async (data) => {
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
          name: clean.name, color: clean.color, permissions: safePerms, mentionable: clean.mentionable, userId,
        });
        if (result?.role) {
          io.to(`server:${data.serverId}`).emit('ROLE_CREATE', {
            type: 'ROLE_CREATE',
            payload: { ...result.role, serverId: data.serverId },
            timestamp: new Date(),
          });
        }
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'ROLE_ERROR', e); return; }
      }
      // Fallback microservice
      const role = await serviceProxy.servers.createRole(data.serverId, {
        name: clean.name!, color: clean.color, permissions: safePerms,
      }, userId) as Record<string, unknown>;
      io.to(`server:${data.serverId}`).emit('ROLE_CREATE', {
        type: 'ROLE_CREATE',
        payload: { ...role, serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
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
        position: safePosition, mentionable: clean.mentionable,
      }, userId) as Record<string, unknown>;
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
      io.to(`server:${data.serverId}`).emit('ROLE_DELETE', {
        type: 'ROLE_DELETE',
        payload: { roleId: data.roleId, serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
    }
  });

  // ── Présence en masse (DM list, liste d'amis) ──
  socket.on('GET_BULK_PRESENCE', async (data: { userIds: string[] }, callback) => {
    try {
      if (!Array.isArray(data?.userIds) || data.userIds.length === 0) {
        if (typeof callback === 'function') callback({ presence: [] });
        return;
      }
      const presence = await redis.getBulkPresence(data.userIds);
      if (typeof callback === 'function') callback({ presence });
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
            participants: parts.map(p => ({
              userId: p.userId,
              username: p.username,
              avatarUrl: p.avatarUrl,
              muted: p.muted,
              deafened: p.deafened,
            })),
          });
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
        const ids = members.map(uid).filter(Boolean);
        const online = await redis.getOnlineSet(ids).catch(() => new Set<string>());
        return members.map((m) => ({ ...m, status: online.has(uid(m)) ? 'online' : 'offline' }));
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
      const roleIds = clean.roleIds ?? data.roleIds;
      const nickname = clean.nickname ?? data.nickname;

      // Permission check: MANAGE_ROLES required
      const hasPerm = await checkServerPermission(userId, serverId, PERM.MANAGE_ROLES);
      if (!hasPerm) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
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
      if (!(await checkServerPermission(userId, serverId, PERM.ADMIN))) { // ADMIN
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
      if (!(await checkServerPermission(userId, data.serverId, PERM.MANAGE_CHANNELS))) {
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
      if (!(await checkServerPermission(userId, data.serverId, PERM.MANAGE_CHANNELS))) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }
      await forwardToNode(data.serverId, 'INVITE_DELETE', { inviteId: data.inviteId });
      if (typeof callback === 'function') callback({ success: true });
    } catch (e: any) {
      if (typeof callback === 'function') callback({ error: e.message });
    }
  });

  socket.on('INVITE_CREATE', async (data, callback) => {
    let clean: ReturnType<typeof validateInviteInput>;
    try { clean = validateInviteInput(data); }
    catch (e: any) { if (typeof callback === 'function') callback({ error: e.message }); return; }
    if (!(await checkServerPermission(userId, data.serverId, PERM.MANAGE_CHANNELS))) {
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
    if (!socket.rooms.has(`channel:${data?.channelId}`)) return;
    socket.to(`channel:${data.channelId}`).emit('SERVER_TYPING_START', {
      type: 'SERVER_TYPING_START',
      payload: { userId, channelId: data.channelId, serverId: data.serverId },
      timestamp: new Date(),
    });
  });

  socket.on('SERVER_TYPING_STOP', async (data) => {
    if (!socket.rooms.has(`channel:${data?.channelId}`)) return;
    socket.to(`channel:${data.channelId}`).emit('SERVER_TYPING_STOP', {
      type: 'SERVER_TYPING_STOP',
      payload: { userId, channelId: data.channelId, serverId: data.serverId },
      timestamp: new Date(),
    });
  });

  // Rejoindre/quitter une room de channel
  socket.on('CHANNEL_JOIN', async (data) => {
    try {
      const { channelId, serverId } = data;
      if (!channelId || !serverId) return;

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

      socket.join(`channel:${channelId}`);
      logger.info(`${userId} rejoint channel:${channelId}`);
    } catch (err) {
      logger.warn({ err }, 'CHANNEL_JOIN permission check error');
    }
  });

  socket.on('CHANNEL_LEAVE', async (data) => {
    socket.leave(`channel:${data.channelId}`);
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

      // Notifier et faire rejoindre chaque participant
      for (const participantId of participantIds) {
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
    const { serverId, channelId } = data;
    if (!serverId || !channelId) return;

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
    // Les serveurs auto-hébergés gardent leurs salons sur leur node : on ne peut pas
    // les valider ici, ce chemin reste inchangé.
    if (!connectedNodes.has(serverId)) {
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

    // Leave any existing voice channel first
    const existingChannel = userVoiceChannel.get(userId);
    if (existingChannel) {
      leaveVoiceChannel(userId, socket);
    }

    // Join the new voice channel
    if (!voiceChannels.has(channelId)) {
      voiceChannels.set(channelId, new Map());
    }
    const participants = voiceChannels.get(channelId)!;
    const participant: VoiceParticipant = {
      socketId: socket.id,
      userId,
      username: user.username,
      avatarUrl: (user as any).avatarUrl || (user as any).avatar_url || undefined,
      muted: false,
      deafened: false,
      serverId,
    };
    participants.set(userId, participant);
    userVoiceChannel.set(userId, channelId);

    // Join voice room for signaling
    socket.join(`voice:${channelId}`);

    // Notify all in server that user joined voice
    const voiceState = Array.from(participants.values()).map(p => ({
      userId: p.userId,
      username: p.username,
      avatarUrl: p.avatarUrl,
      muted: p.muted,
      deafened: p.deafened,
    }));

    io.to(`server:${serverId}`).emit('VOICE_STATE_UPDATE', {
      channelId,
      serverId,
      participants: voiceState,
    });

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
    const { serverId, channelId, muted, deafened } = data;
    const currentChannelId = userVoiceChannel.get(userId);
    if (!currentChannelId) return;

    const participants = voiceChannels.get(currentChannelId);
    if (!participants) return;
    const p = participants.get(userId);
    if (!p) return;

    if (muted !== undefined) p.muted = muted;
    if (deafened !== undefined) p.deafened = deafened;

    // Broadcast updated state
    const voiceState = Array.from(participants.values()).map(pp => ({
      userId: pp.userId,
      username: pp.username,
      avatarUrl: pp.avatarUrl,
      muted: pp.muted,
      deafened: pp.deafened,
    }));

    io.to(`server:${p.serverId}`).emit('VOICE_STATE_UPDATE', {
      channelId: currentChannelId,
      serverId: p.serverId,
      participants: voiceState,
    });
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
});

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

async function nodeOwnsChannel(serverId: string, channelId: string): Promise<boolean> {
  if (!serverId || !channelId) return false;
  const key = `nodechans:${serverId}`;
  try {
    const cached = await redis.get(key);
    if (cached) {
      const ids: string[] = JSON.parse(cached);
      if (Array.isArray(ids)) return ids.includes(channelId);
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
        const decoded = jwt.verify(token, JWT_SECRET) as { userId?: string; id?: string };
        ownerId = (decoded.userId || decoded.id) as string;
        if (!ownerId) throw new Error('no-user');
      } catch {
        return next(new Error('Jeton d\'installation invalide ou expiré'));
      }
      // Un compte banni ne doit pas pouvoir créer de serveur.
      const moderation = await serviceProxy.users.getModerationStatus(ownerId).catch(() => null);
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
    next(new Error(`Authentification server-node échouée: ${err?.message || 'erreur inconnue'}`));
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
    const { event, data: payload } = data;

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
        io.to(`channel:${payload.channelId}`).emit('SERVER_MESSAGE_NEW', {
          type: 'SERVER_MESSAGE_NEW',
          payload: payload.message,
          timestamp: new Date(),
        });
        break;

      case 'MSG_EDIT':
        io.to(`channel:${payload.channelId}`).emit('SERVER_MESSAGE_EDITED', {
          type: 'SERVER_MESSAGE_EDITED',
          payload,
          timestamp: new Date(),
        });
        break;

      case 'MSG_DELETE':
        io.to(`channel:${payload.channelId}`).emit('SERVER_MESSAGE_DELETED', {
          type: 'SERVER_MESSAGE_DELETED',
          payload,
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
        io.to(`channel:${payload.channelId}`).emit('SERVER_TYPING_START', {
          type: 'SERVER_TYPING_START',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      case 'TYPING_STOP':
        io.to(`channel:${payload.channelId}`).emit('SERVER_TYPING_STOP', {
          type: 'SERVER_TYPING_STOP',
          payload: { ...payload, serverId },
          timestamp: new Date(),
        });
        break;

      // ── Catch-all : tous les événements non mappés explicitement sont
      // relayés tel-quel vers la room server:{serverId}. Cela permet aux
      // handlers du node (forum, stage, bot, automod…) d'envoyer des événements
      // sans avoir à modifier ce switch à chaque ajout.
      default: {
        const room = payload?.channelId
          ? `channel:${payload.channelId}`
          : `server:${serverId}`;
        io.to(room).emit(event, {
          type: event,
          payload: payload?.serverId ? payload : { ...payload, serverId },
          timestamp: new Date(),
        });
        break;
      }
    }
  });

  // Legacy: support MSG_BROADCAST direct (compat). Même contrôle d'appartenance
  // du salon que NODE_BROADCAST — il n'en avait aucun.
  nodeSocket.on('MSG_BROADCAST', async (data: { channelId: string; message: any }) => {
    if (!data?.channelId || !(await nodeOwnsChannel(serverId, data.channelId))) {
      logger.warn(`MSG_BROADCAST rejeté: salon ${data?.channelId} hors du serveur ${serverId}`);
      return;
    }
    io.to(`channel:${data.channelId}`).emit('SERVER_MESSAGE_NEW', {
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
  const message = error instanceof Error ? error.message : 'Une erreur est survenue';
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
  // Les amis voient 'offline' quand l'utilisateur est en mode invisible
  const visibleStatus = status === 'invisible' ? 'offline' : status;
  const presencePayload = {
    type: 'PRESENCE_UPDATE',
    payload: {
      userId,
      status: visibleStatus,
      customStatus: text ?? null, // compat ascendante
      text: text ?? null,
      emoji: emoji ?? null,
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

  for (const fid of recipients) {
    io.to(`user:${fid}`).emit('PRESENCE_UPDATE', presencePayload);
  }
  // Broadcast serveur supprimé — les member-lists utilisent GET_BULK_PRESENCE à la demande
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
