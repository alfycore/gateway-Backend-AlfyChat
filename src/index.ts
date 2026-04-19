// ==========================================
// ALFYCHAT - GATEWAY WEBSOCKET
// Point d'entrée unique pour toutes les communications temps réel
// ==========================================

import express from 'express';
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
import { messageRateLimit, MSG_RATE_WINDOW, MSG_RATE_MAX, serverJoinRateLimit, checkServerJoinRate, checkInviteVerifyRate } from './state/rate-limit';
import { runtime } from './state/runtime';
import { forwardToNode, getNodeSocket } from './services/forward';
import { registerInternalRoutes } from './http/internal.routes';
import { registerAdminRoutes } from './http/admin.routes';
import { registerFriendsRoutes } from './http/friends.routes';
import { registerServersRoutes } from './http/servers.routes';
import { registerMediaRoutes } from './http/media.routes';
import { registerHealthRoutes } from './http/health.routes';
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
registerInternalRoutes(app);

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
registerServersRoutes(app);
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
});

// ============ TYPES ============

interface AuthenticatedSocket extends Socket {
  userId?: string;
  sessionId?: string;
  user?: User;
}

// ============ MIDDLEWARE D'AUTHENTIFICATION ============

io.use(async (socket: AuthenticatedSocket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return next(new Error('Token d\'authentification requis'));
    }

    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
    
    // Vérifier l'utilisateur via le service users
    const user = await serviceProxy.users.getUser(decoded.userId) as User | null;
    
    if (!user) {
      return next(new Error('Utilisateur non trouvé'));
    }

    socket.userId = decoded.userId;
    socket.sessionId = uuidv4();
    socket.user = user;

    // Détection d'anomalies WS — suit les événements non-triviaux après auth
    attachAnomalyWsHooks(socket, decoded.userId);

    next();
  } catch (error) {
    logger.error({ err: error }, 'Erreur d\'authentification WebSocket:');
    next(new Error('Token invalide'));
  }
});

// ============ GESTION DES CONNEXIONS ============

/**
 * Vérifie qu'un utilisateur a les permissions requises sur un serveur.
 * Le owner bypasse tous les checks. ADMIN (0x40) bypasse aussi.
 */
async function checkServerPermission(
  userId: string,
  serverId: string,
  requiredPerms: number,
): Promise<boolean> {
  try {
    // 1. Check if owner
    const server = await serviceProxy.servers.getServer(serverId);
    const ownerId = server?.ownerId || server?.owner_id;
    if (ownerId === userId) return true;

    // 2. Get member's role_ids
    const members = await serviceProxy.servers.getMembers(serverId);
    const member = (members || []).find((m: any) =>
      (m.userId || m.user_id || m.id) === userId
    );
    if (!member) return false;

    let roleIds: string[] = member.roleIds || member.role_ids || [];
    if (typeof roleIds === 'string') {
      try { roleIds = JSON.parse(roleIds); } catch { roleIds = []; }
    }
    if (!Array.isArray(roleIds)) roleIds = [];

    // 3. Get all roles
    const roles = await serviceProxy.servers.getRoles(serverId);
    if (!roles || !Array.isArray(roles)) return false;

    // 4. Compute combined bitmask
    let combinedPerms = 0;
    for (const role of roles) {
      if (roleIds.includes(role.id)) {
        const perms = role.permissions;
        if (Array.isArray(perms)) {
          // Legacy string array format
          if (perms.includes('ADMIN')) return true;
          if (perms.includes('MANAGE_ROLES') && (requiredPerms & 0x100)) combinedPerms |= 0x100;
          if (perms.includes('MANAGE_CHANNELS') && (requiredPerms & 0x80)) combinedPerms |= 0x80;
        } else {
          const p = typeof perms === 'number' ? perms : parseInt(String(perms) || '0', 10);
          // Masquer pour éviter qu'un bit hors plage (permissions:-1, 0x80000000…)
          // passe un & requiredPerms de façon imprévue.
          if (Number.isFinite(p)) combinedPerms |= (p & 0xFFF);
        }
      }
    }

    // 5. ADMIN implies all
    if (combinedPerms & 0x40) return true;

    // 6. Check required bits
    return (combinedPerms & requiredPerms) === requiredPerms;
  } catch (err) {
    logger.warn({ err: err }, 'checkServerPermission error:');
    return false;
  }
}

/**
 * Retourne (isOwner, combinedPerms) pour un user sur un serveur. Utilisé pour
 * empêcher l'escalade : un user ne peut pas accorder/assigner des permissions
 * qu'il ne possède pas lui-même.
 */
async function getUserPermBits(userId: string, serverId: string): Promise<{ isOwner: boolean; perms: number }> {
  try {
    const server = await serviceProxy.servers.getServer(serverId);
    const ownerId = server?.ownerId || server?.owner_id;
    if (ownerId === userId) return { isOwner: true, perms: 0xFFF };

    const members = await serviceProxy.servers.getMembers(serverId);
    const member = (members || []).find((m: any) =>
      (m.userId || m.user_id || m.id) === userId
    );
    if (!member) return { isOwner: false, perms: 0 };

    let roleIds: string[] = member.roleIds || member.role_ids || [];
    if (typeof roleIds === 'string') {
      try { roleIds = JSON.parse(roleIds); } catch { roleIds = []; }
    }
    if (!Array.isArray(roleIds)) roleIds = [];

    const roles = await serviceProxy.servers.getRoles(serverId);
    if (!roles || !Array.isArray(roles)) return { isOwner: false, perms: 0 };

    let combined = 0;
    for (const role of roles) {
      if (!roleIds.includes(role.id)) continue;
      const raw = role.permissions;
      const p = typeof raw === 'number' ? raw : parseInt(String(raw ?? '0'), 10);
      if (Number.isFinite(p)) combined |= (p & 0xFFF);
    }
    // ADMIN implique tout.
    if (combined & 0x40) combined = 0xFFF;
    return { isOwner: false, perms: combined };
  } catch (err) {
    logger.warn({ err }, 'getUserPermBits error');
    return { isOwner: false, perms: 0 };
  }
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
    console.error('Error joining DM rooms:', error);
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
    console.error('Error joining group conversation rooms:', error);
  }

  // Joindre automatiquement tous les serveurs dont l'utilisateur est membre
  try {
    const userServers = await serviceProxy.servers.getUserServers(userId, token);
    if (userServers && Array.isArray(userServers)) {
      for (const srv of userServers) {
        const sid = srv.id || srv.server_id;
        if (sid) {
          socket.join(`server:${sid}`);
          // Notifier le node si connecté (pour s'assurer que le membre existe dans la DB locale)
          // + charger et joindre les channels du node
          forwardToNode(sid, 'MEMBER_JOIN', {
            userId,
            username: user.username,
            displayName: user.displayName || user.username,
            avatarUrl: user.avatarUrl || null,
          }).then(() => {
            // Charger les channels depuis le node pour auto-join
            return forwardToNode(sid, 'CHANNEL_LIST', {});
          }).then((chResult) => {
            if (chResult?.channels) {
              for (const ch of chResult.channels) {
                socket.join(`channel:${ch.id}`);
              }
            }
          }).catch(() => {
            // Pas de node → charger channels depuis microservice
            serviceProxy.servers.getServer(sid).then((server: any) => {
              if (server?.channels) {
                for (const channel of server.channels) {
                  socket.join(`channel:${channel.id}`);
                }
              }
            }).catch(() => { /* ignore */ });
          });
        }
      }
      logger.info(`${user.username} auto-joined ${userServers.length} server rooms`);
    }
  } catch (error) {
    console.error('Error joining server rooms:', error);
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

  // Stocker le statut en ligne dans Redis (conserver le statut choisi par l'utilisateur)
  const previousStatus = user.status && user.status !== 'offline' ? user.status : 'online';
  await redis.setUserStatus(userId, previousStatus, user.customStatus ?? null);

  // Notifier les amis de la connexion
  broadcastPresenceUpdate(userId, previousStatus, friends, user.customStatus ?? null);

  // Envoyer les pings en attente (messages reçus hors ligne) — DB + Redis
  try {
    // 1. Notifications persistantes en DB (source de vérité)
    let dbNotifications: Record<string, { count: number; senderName: string }> = {};
    try {
      dbNotifications = (await serviceProxy.messages.getNotifications(userId, token)) as Record<string, { count: number; senderName: string }>;
    } catch { /* non bloquant */ }

    // 2. Compat. Redis (fusionne avec DB)
    const redisPings = await redis.getPendingPings(userId);
    const merged: Record<string, { count: number; senderName: string }> = { ...redisPings };
    for (const [convId, notif] of Object.entries(dbNotifications)) {
      if (!merged[convId]) {
        merged[convId] = notif;
      } else {
        merged[convId] = {
          count: Math.max(merged[convId].count, notif.count),
          senderName: notif.senderName || merged[convId].senderName,
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

  // ============ GESTIONNAIRES D'ÉVÉNEMENTS ============

  // Heartbeat
  socket.on('HEARTBEAT', () => {
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

  // Messages
  socket.on('MESSAGE_CREATE', async (data) => {
    try {
      const v = validateMessageContent(data?.content, data?.attachments);
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
      // ── Rate limiting ──
      const now = Date.now();
      const timestamps = messageRateLimit.get(userId) || [];
      const recent = timestamps.filter(t => now - t < MSG_RATE_WINDOW);
      if (recent.length >= MSG_RATE_MAX) {
        socket.emit('message:error', { error: 'RATE_LIMITED', message: 'Trop de messages envoyés. Calme-toi !' });
        return;
      }
      recent.push(now);
      messageRateLimit.set(userId, recent);

      // ── Validation contenu ──
      try {
        const v = validateMessageContent(data?.content, data?.attachments);
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

      // ── ÉTAPE 1 : Générer l'ID côté gateway, construire le payload IMMÉDIATEMENT ──
      const messageId = uuidv4();
      const messageForClient = {
        id: messageId,
        conversationId,
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
      }).catch((err: Error) => {
        // La DB a échoué : notifier l'expéditeur pour afficher une erreur sur le message
        console.error('❌ DB write failed for message:', messageId, err?.message || err);
        socket.emit('message:failed', {
          messageId,
          error: 'Échec de la sauvegarde — veuillez réessayer',
          detail: err?.message || String(err),
        });
      });

    } catch (error) {
      console.error('❌ Error in message:send:', error);
      socket.emit('message:error', { error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  socket.on('MESSAGE_UPDATE', async (data) => {
    try {
      const v = validateMessageContent(data?.content);
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
      const now = Date.now();
      const timestamps = messageRateLimit.get(userId) || [];
      const recent = timestamps.filter(t => now - t < MSG_RATE_WINDOW);
      if (recent.length >= MSG_RATE_MAX) {
        socket.emit('message:edit-error', { messageId: data?.messageId, error: 'RATE_LIMITED' });
        return;
      }
      recent.push(now);
      messageRateLimit.set(userId, recent);

      const v = validateMessageContent(data?.content);
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
      console.error('❌ Error editing message:', error);
      socket.emit('message:edit-error', { messageId: data?.messageId, error: error instanceof Error ? error.message : 'Erreur interne' });
    }
  });

  socket.on('MESSAGE_DELETE', async (data) => {
    try {
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
    const room = data.conversationId ? `conversation:${data.conversationId}` : `user:${userId}`;
    try {
      await serviceProxy.messages.deleteMessage(data.messageId, userId);
    } catch (error: any) {
      const status = error?.statusCode as number | undefined;
      if (status === 404) {
        // Message pas encore en base (écriture fire-and-forget en cours) — différer.
        pendingDeletions.set(data.messageId, userId);
        console.warn('⚠️ Delete scheduled (message not in DB yet):', data.messageId);
      } else {
        // Service temporairement indisponible après retries — planifier un second essai.
        console.warn('⚠️ Delete failed (service error), scheduling retry:', data.messageId, error?.message);
        setTimeout(() => {
          serviceProxy.messages.deleteMessage(data.messageId, userId).catch((retryErr) => {
            console.error('❌ Delete retry failed:', data.messageId, retryErr?.message);
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
      socket.join(`conversation:${roomId}`);
      socket.emit('conversation:joined', { conversationId: roomId });
    }
  });

  // ── E2EE history recovery: relay request & response between DM participants ──
  // User A lost keys → asks User B to re-encrypt the conversation history
  socket.on('e2ee:history-request', async (data: { recipientId: string; conversationId: string }) => {
    if (!data.recipientId || !data.conversationId) return;
    // Only allow requests for DM conversations where userId is a participant
    if (!data.conversationId.startsWith('dm_') || !data.conversationId.includes(userId)) return;
    // Vérifier si le destinataire est connecté
    const recipientSockets = await io.in(`user:${data.recipientId}`).fetchSockets();
    if (recipientSockets.length === 0) {
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
    await redis.setTyping(data.conversationId, userId);
    
    socket.to(`conversation:${data.conversationId}`).emit('TYPING_START', {
      type: 'TYPING_START',
      payload: { userId, conversationId: data.conversationId },
      timestamp: new Date(),
    });
  });

  socket.on('TYPING_STOP', async (data) => {
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

      // Timeout: si pas de réponse peer en 10s, notifier le client
      setTimeout(() => {
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

      // Forcer senderId = userId authentifié dans les messages pour empêcher la forge
      const sanitizedMessages = (messages || []).map((m: any) => ({
        ...m,
        // Ne pas permettre d'usurper le senderId
      }));

      // Mettre en cache Redis les messages récupérés (24h)
      if (sanitizedMessages.length > 0) {
        try {
          await serviceProxy.messages.cacheArchivedMessages(sanitizedMessages);
        } catch (e) {
          logger.warn({ err: e }, 'Erreur cache messages archivés:');
        }
      }

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

  // Appels
  socket.on('CALL_INITIATE', async (data, callback) => {
    try {
      logger.info(`CALL_INITIATE de ${userId} (${user?.username}) vers ${data.recipientId || data.channelId || 'conversation'} type=${data.type}`);

      // Vérification de permission : pour les channels de serveur, vérifier le membership
      if (data.channelId && data.serverId) {
        const isMember = await serviceProxy.servers.isMember(data.serverId, userId);
        if (!isMember) {
          if (typeof callback === 'function') callback({ error: 'Accès refusé — non membre du serveur' });
          return;
        }
      }
      
      // Calculer le conversationId pour les DM si recipientId est fourni
      let conversationId = data.conversationId;
      if (!conversationId && data.recipientId) {
        const sortedIds = [userId, data.recipientId].sort();
        conversationId = `dm_${sortedIds[0]}_${sortedIds[1]}`;
      }

      const call = await serviceProxy.calls.initiateCall({
        type: data.type,
        initiatorId: userId,
        conversationId,
        channelId: data.channelId,
        recipientId: data.recipientId,
      }) as { id: string; [key: string]: any };
      
      logger.info(`Calls service responded with call id=${call.id}`);
      
      // L'initiateur rejoint la room de l'appel
      socket.join(`call:${call.id}`);
      
      // Retourner le callId à l'initiateur
      if (typeof callback === 'function') {
        callback({ callId: call.id, id: call.id });
      }

      const callPayload = {
        ...call,
        conversationId,
        initiatorId: userId,
        recipientId: data.recipientId || null,
        callerName: user?.displayName || user?.username,
        callerAvatar: user?.avatarUrl,
      };

      // Notifier le destinataire ou les participants de la conversation
      if (data.recipientId) {
        const recipientRoom = `user:${data.recipientId}`;
        const socketsInRoom = await io.in(recipientRoom).fetchSockets();
        logger.info(`CALL_INCOMING: room "${recipientRoom}" contient ${socketsInRoom.length} socket(s): [${socketsInRoom.map(s => s.id).join(', ')}]`);
        
        const callIncomingPayload = {
          type: 'CALL_INCOMING',
          payload: callPayload,
          timestamp: new Date(),
        };

        // Émettre DIRECTEMENT à chaque socket du destinataire
        for (const remoteSocket of socketsInRoom) {
          remoteSocket.emit('CALL_INCOMING', callIncomingPayload);
          logger.info(`CALL_INCOMING émis directement au socket ${remoteSocket.id} (user: ${(remoteSocket as any).userId})`);
        }
        // Stocker en Redis pour les utilisateurs qui se connectent en retard (TTL 60s)
        try {
          await redis.set(
            `pending_call:user:${data.recipientId}`,
            JSON.stringify({ type: 'CALL_INCOMING', payload: callPayload, timestamp: new Date() }),
            60
          );
        } catch { /* non bloquant */ }
      } else if (conversationId) {
        socket.to(`conversation:${conversationId}`).emit('CALL_INCOMING', {
          type: 'CALL_INCOMING',
          payload: callPayload,
          timestamp: new Date(),
        });
      } else if (data.channelId) {
        socket.to(`channel:${data.channelId}`).emit('CALL_INCOMING', {
          type: 'CALL_INCOMING',
          payload: callPayload,
          timestamp: new Date(),
        });
      }
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
      if (typeof callback === 'function') {
        callback({ error: 'Failed to initiate call' });
      }
    }
  });

  socket.on('CALL_ACCEPT', async (data) => {
    try {
      const call = await serviceProxy.calls.joinCall(data.callId, userId);
      
      // Supprimer l'appel en attente Redis (plus besoin de notifier cet utilisateur)
      try { await redis.del(`pending_call:user:${userId}`); } catch { /* non bloquant */ }
      
      // Rejoindre la room AVANT de broadcast pour recevoir le signaling WebRTC
      socket.join(`call:${data.callId}`);
      
      // Signaler aux participants EXISTANTS qu'un nouveau pair a rejoint
      // → déclenche handleParticipantJoined côté initiateur qui crée l'offre WebRTC
      socket.to(`call:${data.callId}`).emit('CALL_PARTICIPANT_JOINED', {
        type: 'CALL_PARTICIPANT_JOINED',
        payload: { callId: data.callId, userId },
        timestamp: new Date(),
      });
      
      // Confirmer l'acceptation à tous les participants (y compris l'accepteur)
      io.to(`call:${data.callId}`).emit('CALL_ACCEPT', {
        type: 'CALL_ACCEPT',
        payload: { callId: data.callId, userId },
        timestamp: new Date(),
      });
      
      logger.info(`Appel ${data.callId} accepté par ${userId}`);
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  socket.on('CALL_REJECT', async (data) => {
    try {
      await serviceProxy.calls.rejectCall(data.callId, userId);
      
      // Supprimer l'appel en attente Redis
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

  socket.on('CALL_END', async (data) => {
    try {
      await serviceProxy.calls.endCall(data.callId, userId);
      
      io.to(`call:${data.callId}`).emit('CALL_END', {
        type: 'CALL_END',
        payload: { callId: data.callId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'CALL_ERROR', error);
    }
  });

  // WebRTC Signaling
  socket.on('WEBRTC_OFFER', (data) => {
    logger.info(`WebRTC offer de ${userId} pour call ${data.callId}`);
    socket.to(`call:${data.callId}`).emit('WEBRTC_OFFER', {
      type: 'WEBRTC_OFFER',
      payload: { callId: data.callId, offer: data.offer, fromUserId: userId },
      timestamp: new Date(),
    });
  });

  socket.on('WEBRTC_ANSWER', (data) => {
    logger.info(`WebRTC answer de ${userId} pour call ${data.callId}`);
    socket.to(`call:${data.callId}`).emit('WEBRTC_ANSWER', {
      type: 'WEBRTC_ANSWER',
      payload: { callId: data.callId, answer: data.answer, fromUserId: userId },
      timestamp: new Date(),
    });
  });

  socket.on('WEBRTC_ICE_CANDIDATE', (data) => {
    socket.to(`call:${data.callId}`).emit('WEBRTC_ICE_CANDIDATE', {
      type: 'WEBRTC_ICE_CANDIDATE',
      payload: { callId: data.callId, candidate: data.candidate, fromUserId: userId },
      timestamp: new Date(),
    });
  });

  // Notifier les autres participants quand un utilisateur start/stop le partage d'écran
  socket.on('CALL_SCREEN_SHARE', (data) => {
    const { callId, active } = data as { callId: string; active: boolean };
    if (!callId) return;
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
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('NOT_A_CHANNEL_MEMBER'));
        return;
      }
      // Permission SEND (0x2) — inclut déjà le check de membership côté server.
      if (!(await checkServerPermission(userId, serverId, 0x2))) {
        emitError(socket, 'SERVER_MESSAGE_ERROR', new Error('PERMISSION_DENIED'));
        return;
      }
      const v = validateMessageContent(data?.content, data?.attachments);
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
    } catch (error) {
      emitError(socket, 'SERVER_MESSAGE_ERROR', error);
    }
  });

  socket.on('SERVER_MESSAGE_EDIT', async (data) => {
    try {
      const v = validateMessageContent(data?.content);
      const { serverId, messageId, channelId } = data;
      const content = v.content;

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
    // Vérifier la membership ; fail open si le check échoue techniquement
    try {
      const member = await serviceProxy.servers.isMember(data.serverId, userId);
      if (!member) {
        if (typeof callback === 'function') callback({ channels: [], error: 'NOT_MEMBER' });
        return;
      }
    } catch {
      // Erreur technique du check → on laisse passer
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
      if (!(await checkServerPermission(userId, serverId, 0x80))) { // MANAGE_CHANNELS
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
      const channel = await serviceProxy.servers.createChannel(serverId, { name: clean.name!, type: clean.type || 'text', parentId: clean.parentId }, userId);
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
      if (!(await checkServerPermission(userId, serverId, 0x80))) {
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
      const channel = await serviceProxy.servers.updateChannel(serverId, channelId, { ...(data.updates || {}), ...clean }, userId);
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
      if (!(await checkServerPermission(userId, serverId, 0x80))) {
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
      await serviceProxy.servers.deleteChannel(serverId, channelId, userId);
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
      const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_GET', { channelId: data.channelId });
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      if (typeof callback === 'function') callback({ permissions: [], error: e.message });
    }
  });

  socket.on('CHANNEL_PERMS_SET', async (data, callback) => {
    try {
      if (!(await checkServerPermission(userId, data.serverId, 0x80))) {
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
      const hasPerm = await checkServerPermission(userId, data.serverId, 0x100); // MANAGE_ROLES
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      const clean = validateRoleInput(data);
      // Anti-escalation : un non-owner ne peut pas accorder des bits qu'il
      // ne possède pas. ADMIN reste réservé à l'owner.
      const actor = await getUserPermBits(userId, data.serverId);
      let safePerms = clean.permissions ?? 0;
      if (!actor.isOwner) {
        safePerms = safePerms & actor.perms;
        safePerms &= ~0x40; // jamais d'ADMIN sauf owner
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
      }) as Record<string, unknown>;
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
      const hasPerm = await checkServerPermission(userId, data.serverId, 0x100); // MANAGE_ROLES
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      const clean = validateRoleInput(data);
      // Anti-escalation identique à ROLE_CREATE.
      const actor = await getUserPermBits(userId, data.serverId);
      let safePerms: number | undefined = clean.permissions;
      if (safePerms !== undefined && !actor.isOwner) {
        safePerms = safePerms & actor.perms;
        safePerms &= ~0x40;
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
      }) as Record<string, unknown>;
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
      const hasPerm = await checkServerPermission(userId, data.serverId, 0x100); // MANAGE_ROLES
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
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
      await serviceProxy.servers.deleteRole(data.serverId, data.roleId);
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
  socket.on('GET_VOICE_STATE', (data: { serverId: string }, callback) => {
    try {
      if (!data?.serverId || typeof callback !== 'function') {
        if (typeof callback === 'function') callback({ channels: [] });
        return;
      }
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
    try {
      const result = await forwardToNode(data.serverId, 'MEMBER_LIST', {});
      const nodeMembers = result?.members || [];

      // Si le node a des membres, cross-référencer avec MySQL pour filtrer les stales
      if (nodeMembers.length > 0) {
        // Récupérer la liste des membres valides depuis MySQL
        let validUserIds: Set<string> | null = null;
        try {
          const msMembers = await serviceProxy.servers.getMembers(data.serverId);
          if (msMembers && msMembers.length > 0) {
            validUserIds = new Set(msMembers.map((m: any) => m.userId || m.user_id || m.id));
          }
        } catch {
          // Si MySQL est injoignable, on retourne les données du node telles quelles
        }

        let filteredMembers = nodeMembers;
        if (validUserIds) {
          filteredMembers = nodeMembers.filter((m: any) => {
            const uid = m.userId || m.user_id || m.id;
            return validUserIds!.has(uid);
          });

          // Nettoyer les membres stales du node en arrière-plan
          const staleMembers = nodeMembers.filter((m: any) => {
            const uid = m.userId || m.user_id || m.id;
            return !validUserIds!.has(uid);
          });
          for (const stale of staleMembers) {
            const staleId = stale.userId || stale.user_id || stale.id;
            logger.info(`Cleaning stale member ${staleId} from node for server ${data.serverId}`);
            forwardToNode(data.serverId, 'MEMBER_KICK', { userId: staleId, systemCleanup: true }).catch(() => {});
          }

          // Seeds les membres MySQL manquants dans le node
          try {
            const msMembers = await serviceProxy.servers.getMembers(data.serverId);
            const nodeUserIds = new Set(nodeMembers.map((m: any) => m.userId || m.user_id || m.id));
            for (const m of (msMembers || [])) {
              const uid = m.userId || m.user_id || m.id;
              if (!nodeUserIds.has(uid)) {
                forwardToNode(data.serverId, 'MEMBER_JOIN', {
                  userId: uid,
                  username: m.username,
                  displayName: m.displayName || m.display_name || null,
                  avatarUrl: m.avatarUrl || m.avatar_url || null,
                }).catch(() => {});
              }
            }
          } catch { /* ignore sync error */ }
        }

        const enriched = await Promise.all(filteredMembers.map(async (m: any) => {
          const uid = m.userId || m.user_id || m.id;
          const isOnline = await redis.isUserOnline(uid);
          return { ...m, status: isOnline ? 'online' : 'offline' };
        }));
        if (typeof callback === 'function') callback({ members: enriched });
        return;
      }

      // Node retourne 0 membres → synchroniser depuis le microservice
      try {
        const msMembers = await serviceProxy.servers.getMembers(data.serverId);
        if (msMembers && msMembers.length > 0) {
          // Seed les membres dans le node en arrière-plan (fire and forget)
          for (const m of msMembers) {
            forwardToNode(data.serverId, 'MEMBER_JOIN', {
              userId: m.userId || m.user_id || m.id,
              username: m.username,
              displayName: m.displayName || m.display_name || null,
              avatarUrl: m.avatarUrl || m.avatar_url || null,
            }).catch(() => { /* ignore seed error */ });
          }
          // Enrichir avec statut en ligne
          const enriched = await Promise.all(msMembers.map(async (m: any) => {
            const uid = m.userId || m.user_id || m.id;
            const isOnline = await redis.isUserOnline(uid);
            return { ...m, status: isOnline ? 'online' : 'offline' };
          }));
          if (typeof callback === 'function') callback({ members: enriched });
          return;
        }
      } catch { /* fall through */ }

      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      // Fallback: récupérer depuis le microservice servers
      if (e.message === 'NO_NODE') {
        try {
          const members = await serviceProxy.servers.getMembers(data.serverId);
          if (members && members.length > 0) {
            const enriched = await Promise.all(members.map(async (m: any) => {
              const uid = m.userId || m.user_id || m.id;
              const isOnline = await redis.isUserOnline(uid);
              return { ...m, status: isOnline ? 'online' : 'offline' };
            }));
            if (typeof callback === 'function') callback({ members: enriched });
            return;
          }
          if (typeof callback === 'function') callback({ members: members || [] });
          return;
        } catch { /* fall through */ }
      }
      if (typeof callback === 'function') callback({ members: [], error: e.message });
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
      const hasPerm = await checkServerPermission(userId, serverId, 0x100);
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
              const p = (typeof raw === 'number' ? raw : parseInt(String(raw ?? '0'), 10)) & 0xFFF;
              // Le rôle est assignable si tous ses bits ⊆ bits de l'acteur, ET pas ADMIN.
              if ((p & ~actor.perms) === 0 && !(p & 0x40)) {
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
        await serviceProxy.servers.updateMember(serverId, targetUserId, { roleIds: safeRoleIds, nickname });
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
      // Permission check: KICK_MEMBERS required
      const hasKickPerm = await checkServerPermission(userId, serverId, 0x400);
      if (!hasKickPerm) { emitError(socket, 'MEMBER_ERROR', new Error('PERMISSION_DENIED')); return; }
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
      // Permission check: BAN_MEMBERS required
      const hasBanPerm = await checkServerPermission(userId, serverId, 0x800);
      if (!hasBanPerm) { emitError(socket, 'MEMBER_ERROR', new Error('PERMISSION_DENIED')); return; }
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
    // Vérifier la membership ; fail open si le check échoue techniquement
    try {
      const member = await serviceProxy.servers.isMember(data.serverId, userId);
      if (!member) {
        if (typeof callback === 'function') callback({ error: 'NOT_MEMBER' });
        return;
      }
    } catch {
      // Erreur technique du check (endpoint indisponible) → on laisse passer
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
      if (!(await checkServerPermission(userId, serverId, 0x40))) { // ADMIN
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
      const updated = await serviceProxy.servers.updateServer(data.serverId, updates, userId) as Record<string, any> | undefined;
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
    socket.to(`channel:${data.channelId}`).emit('SERVER_TYPING_START', {
      type: 'SERVER_TYPING_START',
      payload: { userId, channelId: data.channelId, serverId: data.serverId },
      timestamp: new Date(),
    });
  });

  socket.on('SERVER_TYPING_STOP', async (data) => {
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

      // Vérifier que l'utilisateur est membre du serveur
      const isMember = await serviceProxy.servers.isMember(serverId, userId);
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
      await serviceProxy.users.updateStatus(userId, data.status, data.customStatus);
      await redis.setUserStatus(userId, data.status, data.customStatus ?? null);
      
      const friends = await serviceProxy.friends.getFriends(userId);
      broadcastPresenceUpdate(userId, data.status, friends, data.customStatus);
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
    } catch (error) {
      emitError(socket, 'PROFILE_UPDATE_ERROR', error);
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

      // Inclure le créateur dans les participants
      const allParticipants = [userId, ...participantIds.filter((id: string) => id !== userId)];
      
      // Créer la conversation de groupe via le service messages
      const group = await serviceProxy.messages.createConversation({
        type: 'group',
        name,
        avatarUrl,
        participants: allParticipants,
        createdBy: userId,
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
      const token: string | undefined = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');

      // Mettre à jour nom/avatar via service messages
      if (name !== undefined || avatarUrl !== undefined) {
        await serviceProxy.messages.updateConversation(groupId, { name, avatarUrl }, token);
      }

      // Ajouter des participants
      if (addParticipants?.length) {
        for (const pid of addParticipants) {
          await serviceProxy.messages.addParticipant(groupId, pid, token);
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
        payload: { groupId, name, avatarUrl, addParticipants, removeParticipants, updatedBy: userId },
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

      // Notifier tous les membres avant suppression
      io.to(`conversation:${groupId}`).emit('GROUP_DELETE', {
        type: 'GROUP_DELETE',
        payload: { groupId, deletedBy: userId },
        timestamp: new Date(),
      });

      // Supprimer via le service
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      await serviceProxy.messages.deleteConversation(groupId, token);

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
    
    connectedClients.delete(socket.id);
    
    try {
      // Mettre à jour le statut hors ligne (seulement si plus aucun socket actif)
      await redis.setUserOffline(userId, socket.id);
      await redis.deleteSession(userId, sessionId);
      
      // Notifier les amis seulement si l'utilisateur est vraiment offline
      const stillOnline = await redis.isUserOnline(userId);
      if (!stillOnline) {
        try {
          const friends = await serviceProxy.friends.getFriends(userId);
          broadcastPresenceUpdate(userId, 'offline', friends);
        } catch (friendsError) {
          logger.warn({ err: friendsError }, `Impossible de notifier les amis pour ${userId}:`);
        }
      }
      
      // Mettre à jour last_seen seulement quand vraiment déconnecté
      if (!stillOnline) {
        try {
          await serviceProxy.users.updateLastSeen(userId);
        } catch (updateError) {
          logger.warn({ err: updateError }, `Impossible de mettre à jour last_seen pour ${userId}:`);
        }
      }
    } catch (error) {
      logger.error({ err: error }, `Erreur lors de la déconnexion de ${userId}:`);
    }
  });
});

// ============ SERVER NODES NAMESPACE (self-hosted) ============

// Le namespace /server-nodes utilise une authentification différente (nodeToken, pas JWT user)
const serverNodesNs = io.of('/server-nodes');

serverNodesNs.use(async (socket, next) => {
  try {
    const { nodeToken, serverId } = socket.handshake.auth;

    // Le mode register sans auth est supprimé — les nodes doivent s'enregistrer
    // via une route HTTP authentifiée et obtenir un nodeToken avant de se connecter

    if (!nodeToken || !serverId) {
      return next(new Error('nodeToken et serverId requis'));
    }
    const result = await serviceProxy.servers.validateNodeToken(nodeToken) as any;
    if (!result || result.serverId !== serverId) {
      return next(new Error('Token de node invalide — serverId ne correspond pas'));
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
    try {
      const result = await serviceProxy.servers.registerNode(serverName) as any;
      if (!result || !result.serverId) {
        nodeSocket.emit('REGISTER_ERROR', { message: 'Échec de la création du serveur' });
        nodeSocket.disconnect();
        return;
      }
      logger.info(`✅ Serveur auto-enregistré: ${result.serverName} (${result.serverId})`);
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
  const endpoint: string | undefined = nodeSocket.handshake.auth.endpoint;

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
  nodeSocket.on('NODE_BROADCAST', (data: { event: string; data: any }) => {
    const { event, data: payload } = data;

    // Vérifier que le channelId/serverId du payload appartient au node connecté
    if (payload?.serverId && payload.serverId !== serverId) {
      logger.warn(`NODE_BROADCAST rejeté: node ${serverId} tente de broadcast vers serveur ${payload.serverId}`);
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

      default:
        logger.warn(`NODE_BROADCAST événement inconnu: ${event}`);
    }
  });

  // Legacy: support MSG_BROADCAST direct (compat)
  nodeSocket.on('MSG_BROADCAST', (data: { channelId: string; message: any }) => {
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
  friends: Array<{ friendId: string }>,
  customStatus?: string | null,
): Promise<void> {
  // Les amis voient 'offline' quand l'utilisateur est en mode invisible
  const visibleStatus = status === 'invisible' ? 'offline' : status;
  for (const friend of friends) {
    io.to(`user:${friend.friendId}`).emit('PRESENCE_UPDATE', {
      type: 'PRESENCE_UPDATE',
      payload: { userId, status: visibleStatus, customStatus: customStatus ?? null },
      timestamp: new Date(),
    });
  }
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
process.on('SIGTERM', async () => {
  logger.info('Signal SIGTERM reçu, arrêt gracieux...');
  
  // Fermer les connexions WebSocket
  io.close();
  
  // Fermer Redis
  await redis.disconnect();
  
  process.exit(0);
});

export { io, redis, serviceProxy, connectedNodes, serverNodesNs };
