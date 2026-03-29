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
import dotenv from 'dotenv';
import { GatewayEvent, GatewayEventType, User } from './types/gateway';
import { logger } from './utils/logger';
import { RedisClient } from './utils/redis';
import { ServiceProxy } from './services/proxy';
import { monitoringDB } from './utils/monitoring-db';
import { serviceRegistry, ServiceType } from './utils/service-registry';

dotenv.config();

const app = express();
const httpServer = createServer(app);

// Configuration CORS
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:4000')
  .split(',')
  .map((o) => o.trim());

const corsOptions = {
  origin: (origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void) => {
    // Autoriser les requêtes sans origin (apps natives, Postman…)
    if (!origin) return cb(null, true);
    // Autoriser localhost sur n'importe quel port (Flutter web dev, …)
    if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origine non autorisée — ${origin}`));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(helmet());

// ============ RATE LIMITING & IP BAN (HTTP) ============
let redis: RedisClient;

const RATE_LIMIT_WINDOW = parseInt(process.env.RATE_LIMIT_WINDOW || '60'); // secondes
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '100'); // requêtes par fenêtre

// Trusted reverse-proxy IPs (load balancer / nginx on same host or LAN)
// Set TRUSTED_PROXIES env var as comma-separated CIDR list or exact IPs.
// When empty, we always use the direct socket address.
const TRUSTED_PROXIES = new Set(
  (process.env.TRUSTED_PROXIES || '127.0.0.1,::1').split(',').map((s) => s.trim()).filter(Boolean)
);

function getClientIP(req: express.Request): string {
  const remoteAddr = req.socket.remoteAddress || '0.0.0.0';
  // Only trust X-Forwarded-For if the direct connection comes from a trusted proxy
  if (TRUSTED_PROXIES.has(remoteAddr)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  }
  return remoteAddr;
}

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

// Middleware : rate limiting HTTP par IP
app.use(async (req, res, next) => {
  if (!redis) return next();
  const ip = getClientIP(req);
  try {
    const count = await redis.incrementRateLimit(ip, RATE_LIMIT_WINDOW);
    res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, RATE_LIMIT_MAX - count)));
    if (count > RATE_LIMIT_MAX) {
      await redis.incrementRateLimitBlocked();
      logger.warn(`Rate limit HTTP dépassé: ${ip} (${count}/${RATE_LIMIT_MAX})`);
      return res.status(429).json({ error: 'Trop de requêtes, réessayez plus tard' });
    }
  } catch {
    // En cas d'erreur Redis, laisser passer
  }
  next();
});

// Ne pas parser le JSON sur /api/media/* (multipart/form-data) ni les uploads multipart vers les nodes
app.use((req, res, next) => {
  if (req.path.startsWith('/api/media')) return next();
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data') && req.path.startsWith('/api/servers/')) return next();
  express.json()(req, res, next);
});

// ============ ROUTES API REST (PROXY) ============
const USERS_URL = process.env.USERS_SERVICE_URL || 'https://users.alfychat.eu';
const MESSAGES_URL = process.env.MESSAGES_SERVICE_URL || 'https://messages.alfychat.eu';
const FRIENDS_URL = process.env.FRIENDS_SERVICE_URL || 'https://friends.s.backend.alfychat.app';
const CALLS_URL = process.env.CALLS_SERVICE_URL || 'https://calls.s.backend.alfychat.app';
const SERVERS_URL = process.env.SERVERS_SERVICE_URL || 'https://servers.s.backend.alfychat.app';
const BOTS_URL = process.env.BOTS_SERVICE_URL || 'https://bots.s.backend.alfychat.app';
const MEDIA_URL = process.env.MEDIA_SERVICE_URL || 'https://media.s.backend.alfychat.app';

// Secret partagé pour les enregistrements internes de services
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'alfychat-internal-secret-dev';

/**
 * Retourne l'URL du meilleur nœud disponible pour un type de service.
 * Si le registre ne contient aucune instance saine, on utilise l'URL de fallback (env var).
 * Un endpoint localhost ne sera jamais préféré à un fallback HTTPS externe.
 */
function getServiceUrl(serviceType: ServiceType, fallback: string): string {
  const best = serviceRegistry.selectBest(serviceType);
  if (!best) return fallback;
  // Ne pas utiliser un endpoint localhost/127.0.0.1 quand le fallback est externe (HTTPS)
  const isLocalEndpoint = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(best.endpoint);
  if (isLocalEndpoint && fallback.startsWith('https://')) return fallback;
  return best.endpoint;
}

// Décoder le JWT depuis le header Authorization (sans lever d'erreur)
function extractUserIdFromJWT(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as any;
    return decoded.userId || decoded.id || null;
  } catch {
    return null;
  }
}

// Proxy HTTP vers les microservices
async function proxyRequest(targetUrl: string, req: express.Request, res: express.Response, fallbackUrl?: string) {
  const SKIP_USERID_INJECT = ['/friends/request'];
  const userId = extractUserIdFromJWT(req.headers.authorization);
  const skipInject = SKIP_USERID_INJECT.some(path => req.originalUrl.replace(/^\/api/, '').startsWith(path));
  let bodyToSend = req.body;
  if (userId && req.method !== 'GET' && req.method !== 'HEAD' && !skipInject) {
    bodyToSend = { ...req.body, userId, ownerId: userId };
  }

  const doFetch = async (baseUrl: string) => {
    const url = `${baseUrl}${req.originalUrl.replace(/^\/api/, '')}`;
    return fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
      ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
    });
  };

  const sendResponse = async (response: Response) => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await safeJson(response);
      res.status(response.status).json(data ?? { error: 'Réponse vide' });
    } else {
      const text = await response.text();
      if (!text) {
        res.status(response.status).json({ success: response.ok });
      } else {
        logger.error(`Service ${targetUrl} retourne du non-JSON:`, text);
        res.status(response.status).json({ error: 'Service non disponible' });
      }
    }
  };

  try {
    const response = await doFetch(targetUrl);
    return sendResponse(response);
  } catch (primaryError) {
    // Si l'endpoint du registre est injoignable et qu'on a un fallback différent, réessayer
    if (fallbackUrl && fallbackUrl !== targetUrl) {
      logger.warn(`Proxy vers ${targetUrl} échoué, fallback vers ${fallbackUrl}`);
      try {
        const response = await doFetch(fallbackUrl);
        return sendResponse(response);
      } catch (fallbackError) {
        logger.error(`Proxy fallback ${fallbackUrl} aussi échoué:`, fallbackError);
      }
    } else {
      logger.error('Erreur proxy:', primaryError);
    }
    res.status(502).json({ error: 'Service indisponible' });
  }
}

// Routes Auth & Users
app.all('/api/auth/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
app.all('/api/users/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
app.all('/api/users', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
app.all('/api/rgpd/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));

// ============ INTERNAL : ENREGISTREMENT & HEARTBEAT DES SERVICES ============

/**
 * POST /api/internal/service/register
 * Enregistre (ou met à jour) une instance de microservice dans le registre.
 * Protégé par le secret partagé INTERNAL_SECRET.
 *
 * Body: { secret, id, serviceType, endpoint, domain, location, metrics }
 */
app.post('/api/internal/service/register', express.json(), (req, res) => {
  const { secret, id, serviceType, endpoint, domain, location, metrics } = req.body ?? {};

  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Secret invalide' });
  }

  const VALID_TYPES: ServiceType[] = ['users', 'messages', 'friends', 'calls', 'servers', 'bots', 'media'];
  if (!id || !VALID_TYPES.includes(serviceType) || !endpoint || !domain || !location) {
    return res.status(400).json({ error: 'Paramètres manquants ou invalides (id, serviceType, endpoint, domain, location)' });
  }

  const defaultMetrics = {
    ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 100,
    bandwidthUsage: 0, requestCount20min: 0,
  };

  const instance = serviceRegistry.register({
    id: String(id),
    serviceType: serviceType as ServiceType,
    endpoint: String(endpoint),
    domain: String(domain),
    location: String(location).toUpperCase(),
    metrics: metrics ?? defaultMetrics,
  });

  // Persist to DB (non-blocking)
  monitoringDB.upsertServiceInstance({
    id: String(id),
    serviceType: String(serviceType),
    endpoint: String(endpoint),
    domain: String(domain),
    location: String(location).toUpperCase(),
  }).catch(() => {});

  res.json({ success: true, instance });
});

/**
 * POST /api/internal/service/heartbeat
 * Met à jour les métriques d'une instance déjà enregistrée.
 *
 * Body: { secret, id, metrics }
 */
app.post('/api/internal/service/heartbeat', express.json(), (req, res) => {
  const { secret, id, metrics } = req.body ?? {};

  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Secret invalide' });
  }

  if (!id || !metrics) {
    return res.status(400).json({ error: 'id et metrics requis' });
  }

  const updated = serviceRegistry.heartbeat(String(id), metrics);
  if (!updated) {
    // Instance inconnue : peut arriver au redémarrage du gateway ; renvoyer 404
    // pour que le service se ré-enregistre
    return res.status(404).json({ error: 'Instance inconnue, veuillez vous enregistrer d\'abord' });
  }

  res.json({ success: true });
});

/**
 * POST /api/internal/service/deregister
 * Retire manuellement une instance du registre (ex : arrêt gracieux).
 */
app.post('/api/internal/service/deregister', express.json(), (req, res) => {
  const { secret, id } = req.body ?? {};
  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Secret invalide' });
  }
  if (!id) return res.status(400).json({ error: 'id requis' });
  const removed = serviceRegistry.remove(String(id));
  if (removed) monitoringDB.removeServiceInstance(String(id)).catch(() => {});
  res.json({ success: removed });
});

/**
 * GET /api/internal/service/list
 * Retourne toutes les instances enregistrées avec leurs métriques et scores.
 * Protégé par X-Internal-Secret header ou ?secret=... query param.
 */
app.get('/api/internal/service/list', (req, res) => {
  const secret = (req.headers['x-internal-secret'] as string | undefined) ?? (req.query.secret as string | undefined);
  if (!secret || secret !== INTERNAL_SECRET) {
    return res.status(401).json({ error: 'Secret invalide' });
  }
  const instances = serviceRegistry.getAll().map((inst) => ({
    ...inst,
    score: serviceRegistry.computeScore(inst),
  }));
  res.json({
    count: instances.length,
    healthy: instances.filter((i) => i.healthy).length,
    instances,
  });
});

// ============ ADMIN : GESTION IP BANS (gateway direct) ============

app.get('/api/admin/gateway/stats', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  // Vérifier le rôle admin via le service users
  try {
    const userRes = await fetch(`${getServiceUrl('users', USERS_URL)}/users/${userId}`, {
      headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
    });
    const userData = await safeJson(userRes) as any;
    if (!userData || userData.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  } catch {
    return res.status(502).json({ error: 'Service indisponible' });
  }
  try {
    const bannedIPs = await redis.getBannedIPs();
    const rateLimitStats = await redis.getRateLimitStats();
    res.json({
      bannedIPs,
      rateLimitStats,
      config: { window: RATE_LIMIT_WINDOW, max: RATE_LIMIT_MAX },
    });
  } catch (error) {
    logger.error('Erreur stats gateway:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/gateway/ban-ip', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const userRes = await fetch(`${getServiceUrl('users', USERS_URL)}/users/${userId}`, {
      headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
    });
    const userData = await safeJson(userRes) as any;
    if (!userData || userData.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  } catch {
    return res.status(502).json({ error: 'Service indisponible' });
  }
  const { ip, reason } = req.body;
  if (!ip || typeof ip !== 'string') return res.status(400).json({ error: 'IP requise' });
  try {
    await redis.banIP(ip.trim(), reason || 'Banni par un administrateur', userId);
    logger.info(`IP bannie: ${ip} par ${userId} — raison: ${reason || 'non spécifiée'}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur ban IP:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/admin/gateway/ban-ip/:ip', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const userRes = await fetch(`${getServiceUrl('users', USERS_URL)}/users/${userId}`, {
      headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
    });
    const userData = await safeJson(userRes) as any;
    if (!userData || userData.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  } catch {
    return res.status(502).json({ error: 'Service indisponible' });
  }
  const ip = decodeURIComponent(req.params.ip);
  try {
    await redis.unbanIP(ip);
    logger.info(`IP débannie: ${ip} par ${userId}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Erreur unban IP:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** GET /api/admin/monitoring — current status + last 24h stats */
app.get('/api/admin/monitoring', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const [latestServices, userHistory, peakUsers] = await Promise.all([
      monitoringDB.getLatestServiceStatus(),
      monitoringDB.getUserStatsHistory(24),
      monitoringDB.getPeakUsers(24),
    ]);
    res.json({
      services: latestServices,
      connectedUsers: {
        current: connectedClients.size,
        peak24h: peakUsers,
        history: userHistory,
      },
      checkedAt: new Date(),
    });
  } catch (err) {
    logger.error('Erreur /api/admin/monitoring:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** GET /api/admin/monitoring/service/:name?hours=24 — history for a specific service */
app.get('/api/admin/monitoring/service/:name', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const hours = Math.min(parseInt(String(req.query.hours) || '24'), 168); // max 7 days
    const history = await monitoringDB.getServiceHistory(req.params.name, hours);
    res.json({ service: req.params.name, hours, history });
  } catch (err) {
    logger.error('Erreur /api/admin/monitoring/service:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** GET /api/admin/monitoring/users/chart?period=30min|10min|hour|day|month */
app.get('/api/admin/monitoring/users/chart', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const period = req.query.period as string;
  if (!['30min', '10min', 'hour', 'day', 'month'].includes(period)) {
    return res.status(400).json({ error: 'period must be 30min, 10min, hour, day or month' });
  }
  try {
    const data = await monitoringDB.getUserStatsAggregated(period as any);
    res.json({ period, data });
  } catch (err) {
    logger.error('Erreur /api/admin/monitoring/users/chart:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Public status endpoint ───────────────────────────────────────────────────

/** GET /api/status — public: current service statuses + active incidents + 90-day uptime */
app.get('/api/status', async (_req, res) => {
  try {
    const [latestStatuses, activeIncidents] = await Promise.all([
      monitoringDB.getLatestServiceStatus(),
      monitoringDB.getIncidents(false),
    ]);

    // Fetch 90-day uptime per service
    const serviceNames = [...new Set(latestStatuses.map((s) => s.service))];
    const uptimeByService: Record<string, import('./utils/monitoring-db').ServiceUptimeDay[]> = {};
    await Promise.all(
      serviceNames.map(async (name) => {
        uptimeByService[name] = await monitoringDB.getServiceUptimeDaily(name, 90);
      }),
    );

    // Public-safe subset of service instances (no metrics, no internal endpoints)
    const publicInstances = serviceRegistry.getAll().map((inst) => ({
      serviceType: inst.serviceType,
      domain: inst.domain,
      location: inst.location,
      healthy: inst.healthy,
      lastHeartbeat: inst.lastHeartbeat,
      score: serviceRegistry.computeScore(inst),
    }));

    res.json({ services: latestStatuses, incidents: activeIncidents, uptime: uptimeByService, instances: publicInstances });
  } catch (err) {
    logger.error('Erreur /api/status:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Admin: incident CRUD ──────────────────────────────────────────────────────

/** GET /api/admin/status/incidents?includeResolved=true */
app.get('/api/admin/status/incidents', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const includeResolved = req.query.includeResolved === 'true';
    const incidents = await monitoringDB.getIncidents(includeResolved);
    res.json({ incidents });
  } catch (err) {
    logger.error('Erreur GET /api/admin/status/incidents:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** POST /api/admin/status/incidents */
app.post('/api/admin/status/incidents', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const { title, message, severity, services, status } = req.body;
    if (!title || !severity) return res.status(400).json({ error: 'title et severity requis' });
    const createdBy = extractUserIdFromJWT(req.headers.authorization) ?? undefined;
    const id = await monitoringDB.createIncident({ title, message, severity, services, status, createdBy });
    if (!id) return res.status(500).json({ error: 'Erreur création incident' });
    res.status(201).json({ id });
  } catch (err) {
    logger.error('Erreur POST /api/admin/status/incidents:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** PATCH /api/admin/status/incidents/:id */
app.patch('/api/admin/status/incidents/:id', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });
    const { title, message, severity, services, status } = req.body;
    const ok = await monitoringDB.updateIncident(id, { title, message, severity, services, status });
    if (!ok) return res.status(500).json({ error: 'Erreur mise à jour' });
    res.json({ success: true });
  } catch (err) {
    logger.error('Erreur PATCH /api/admin/status/incidents:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/** DELETE /api/admin/status/incidents/:id */
app.delete('/api/admin/status/incidents/:id', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID invalide' });
    const ok = await monitoringDB.deleteIncident(id);
    if (!ok) return res.status(500).json({ error: 'Erreur suppression' });
    res.json({ success: true });
  } catch (err) {
    logger.error('Erreur DELETE /api/admin/status/incidents:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Admin: service registry management ───────────────────────────────────────

/** GET /api/admin/services — liste toutes les instances connues */
app.get('/api/admin/services', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const instances = serviceRegistry.getAll().map((i) => ({
    ...i,
    score: serviceRegistry.computeScore(i),
  }));
  res.json({ instances });
});

/** GET /api/admin/services/:type — instances d'un type donné */
app.get('/api/admin/services/:type', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const instances = serviceRegistry.getInstances(req.params.type as ServiceType, true).map((i) => ({
    ...i,
    score: serviceRegistry.computeScore(i),
  }));
  res.json({ instances });
});

/** POST /api/admin/services — ajoute manuellement une instance (sans métriques) */
app.post('/api/admin/services', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const { id, serviceType, endpoint, domain, location } = req.body ?? {};
  const VALID_TYPES: ServiceType[] = ['users', 'messages', 'friends', 'calls', 'servers', 'bots', 'media'];
  if (!id || !VALID_TYPES.includes(serviceType) || !endpoint || !domain || !location) {
    return res.status(400).json({ error: 'id, serviceType, endpoint, domain, location requis' });
  }
  const instance = serviceRegistry.register({
    id: String(id),
    serviceType: serviceType as ServiceType,
    endpoint: String(endpoint),
    domain: String(domain),
    location: String(location).toUpperCase(),
    metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 100, bandwidthUsage: 0, requestCount20min: 0 },
  });
  // Persist to DB (non-blocking)
  monitoringDB.upsertServiceInstance({
    id: String(id),
    serviceType: String(serviceType),
    endpoint: String(endpoint),
    domain: String(domain),
    location: String(location).toUpperCase(),
  }).catch(() => {});
  res.status(201).json({ success: true, instance });
});

/** DELETE /api/admin/services/:id — retire une instance */
app.delete('/api/admin/services/:id', async (req, res) => {
  if (!await requireAdmin(req, res)) return;
  const decodedId = decodeURIComponent(req.params.id);
  const removed = serviceRegistry.remove(decodedId);
  if (!removed) return res.status(404).json({ error: 'Instance introuvable' });
  monitoringDB.removeServiceInstance(decodedId).catch(() => {});
  res.json({ success: true });
});

app.all('/api/admin/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
app.all('/api/admin', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));

// Routes Messages
app.all('/api/messages/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));
app.all('/api/messages', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));
app.all('/api/conversations/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));
app.all('/api/conversations', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));

// Routes Archive DM (système hybride)
app.all('/api/archive/*', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));
app.all('/api/archive', (req, res) => proxyRequest(getServiceUrl('messages', MESSAGES_URL), req, res, MESSAGES_URL));

// Routes Friends
// Route spécifique : envoi demande d'ami via HTTP → proxy + notification WS au destinataire
app.post('/api/friends/request', async (req, res) => {
  const fromUserId = extractUserIdFromJWT(req.headers.authorization);
  try {
    const url = `${FRIENDS_URL}/friends/request`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(fromUserId && { 'X-User-Id': fromUserId }),
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json() as any;
    res.status(response.status).json(data);
    // Notifier le destinataire via WS si succès
    if (response.ok && data.toUserId) {
      io.to(`user:${data.toUserId}`).emit('FRIEND_REQUEST', {
        type: 'FRIEND_REQUEST',
        payload: { id: data.id, fromUserId, toUserId: data.toUserId },
        timestamp: new Date(),
      });
    }
  } catch (error) {
    logger.error('Erreur envoi demande ami:', error);
    res.status(502).json({ error: 'Service indisponible' });
  }
});
// Route spécifique : acceptation demande d'ami → proxy + notification WS aux deux utilisateurs
app.post('/api/friends/requests/:requestId/accept', async (req, res) => {
  const acceptorUserId = extractUserIdFromJWT(req.headers.authorization);
  const { requestId } = req.params;
  try {
    const url = `${FRIENDS_URL}/friends/requests/${requestId}/accept`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(acceptorUserId && { 'X-User-Id': acceptorUserId }),
      },
      body: JSON.stringify({ ...req.body, userId: acceptorUserId }),
    });
    const data = await response.json() as any;
    res.status(response.status).json(data);
    if (response.ok) {
      const fromUserId = data.user_id || data.userId;
      const toUserId = data.friend_id || data.friendId;
      if (fromUserId) io.to(`user:${fromUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
      if (toUserId) io.to(`user:${toUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
    }
  } catch (error) {
    logger.error('Erreur accept ami:', error);
    res.status(502).json({ error: 'Service indisponible' });
  }
});

// Helper : parse JSON sans planter si la réponse n'est pas du JSON
async function safeJson(response: Response): Promise<any> {
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

// GET /api/friends → GET /friends/
app.get('/api/friends', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/`, {
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
    });
    const data = await safeJson(response);
    res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
  } catch (error) {
    logger.error('Erreur getFriends:', error);
    res.status(502).json({ error: 'Service indisponible' });
  }
});

// GET /api/friends/requests → GET /friends/requests
app.get('/api/friends/requests', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/requests`, {
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
    });
    const data = await safeJson(response);
    // Le frontend attend { received: [], sent: [] }
    const normalized = response.ok
      ? (Array.isArray(data) ? { received: data, sent: [] } : (data ?? { received: [], sent: [] }))
      : (data ?? { error: 'Erreur service' });
    res.status(response.status).json(normalized);
  } catch (error) {
    logger.error('Erreur getFriendRequests:', error);
    res.status(502).json({ received: [], sent: [] });
  }
});

// GET /api/friends/blocked → GET /friends/blocked
app.get('/api/friends/blocked', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/blocked`, {
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
    });
    const data = await safeJson(response);
    res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
  } catch (error) {
    logger.error('Erreur getBlockedUsers:', error);
    res.status(502).json({ error: 'Service indisponible' });
  }
});

// DELETE /api/friends/:friendId → DELETE /friends/:friendId
app.delete('/api/friends/:friendId', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  const { friendId } = req.params;
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/${friendId}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
      body: JSON.stringify({ userId }),
    });
    const data = await safeJson(response);
    if (response.ok) {
      io.to(`user:${userId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId }, timestamp: new Date() });
      io.to(`user:${friendId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId: userId }, timestamp: new Date() });
    }
    res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
  } catch (error) {
    logger.error('Erreur removeFriend:', error);
    res.status(502).json({ success: false, error: 'Service indisponible' });
  }
});

// POST /api/friends/:targetId/block → POST /friends/:targetId/block
app.post('/api/friends/:targetId/block', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  const { targetId } = req.params;
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/${targetId}/block`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
      body: JSON.stringify({ userId, blockedUserId: targetId }),
    });
    const data = await safeJson(response);
    res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
  } catch (error) {
    logger.error('Erreur blockUser:', error);
    res.status(502).json({ success: false, error: 'Service indisponible' });
  }
});

// POST /api/friends/:targetId/unblock → POST /friends/:targetId/unblock
app.post('/api/friends/:targetId/unblock', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  const { targetId } = req.params;
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/${targetId}/unblock`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
      body: JSON.stringify({ userId }),
    });
    const data = await safeJson(response);
    res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
  } catch (error) {
    logger.error('Erreur unblockUser:', error);
    res.status(502).json({ success: false, error: 'Service indisponible' });
  }
});

// Décline d'une demande d'ami  
app.post('/api/friends/requests/:requestId/decline', async (req, res) => {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) return res.status(401).json({ error: 'Non authentifié' });
  const { requestId } = req.params;
  try {
    const response = await fetch(`${FRIENDS_URL}/friends/requests/${requestId}/decline`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        'X-User-Id': userId,
      },
      body: JSON.stringify({ userId }),
    });
    const data = await safeJson(response) ?? {};
    res.status(response.status).json({ success: response.ok, ...(data as object) });
  } catch (error) {
    logger.error('Erreur declineFriendRequest:', error);
    res.status(502).json({ success: false, error: 'Service indisponible' });
  }
});

app.all('/api/friends/*', (req, res) => proxyRequest(getServiceUrl('friends', FRIENDS_URL), req, res, FRIENDS_URL));
app.all('/api/friends', (req, res) => proxyRequest(getServiceUrl('friends', FRIENDS_URL), req, res, FRIENDS_URL));

// Routes Calls
app.all('/api/calls/*', (req, res) => proxyRequest(getServiceUrl('calls', CALLS_URL), req, res, CALLS_URL));
app.all('/api/calls', (req, res) => proxyRequest(getServiceUrl('calls', CALLS_URL), req, res, CALLS_URL));

// Routes Servers — proxy intelligent : redirige vers le server-node si connecté
// Les routes « annuaire » vont toujours vers le microservice central :
app.all('/api/servers/join', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/invite/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/invites/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/public/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/discover/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/badges/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/admin/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
// GET /api/servers — liste des serveurs, enrichie avec les infos des nodes connectés
app.get('/api/servers', async (req, res) => {
  try {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    const url = `${getServiceUrl('servers', SERVERS_URL)}/servers?userId=${userId || ''}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({ error: 'Service indisponible' }));
      return res.status(response.status).json(data);
    }

    const servers = await response.json();
    if (!Array.isArray(servers)) return res.json(servers);

    // Enrichir chaque serveur avec les infos du node connecté (icon, banner, etc.)
    const enriched = await Promise.all(
      servers.map(async (server: any) => {
        try {
          const nodeInfo = await forwardToNode(server.id, 'SERVER_INFO', {});
          if (nodeInfo) {
            // Les données du node ont la priorité
            if (nodeInfo.iconUrl) server.iconUrl = nodeInfo.iconUrl;
            if (nodeInfo.bannerUrl) server.bannerUrl = nodeInfo.bannerUrl;
            if (nodeInfo.name) server.name = nodeInfo.name;
            if (nodeInfo.description) server.description = nodeInfo.description;
          }
        } catch {
          // Pas de node connecté → on garde les données du microservice
        }
        return server;
      })
    );

    res.json(enriched);
  } catch (error) {
    logger.error('Erreur proxy GET /api/servers:', error);
    res.status(502).json({ error: 'Service indisponible' });
  }
});
app.post('/api/servers', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));

// Routes qui restent TOUJOURS vers le microservice même pour un serverId
app.all('/api/servers/:serverId/leave', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/:serverId/node-token', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/:serverId/claim-admin', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
app.all('/api/servers/:serverId/domain/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));

// Proxy dédié vers un server-node : réécriture d'URL automatique
async function proxyToNode(nodeEndpoint: string, nodePath: string, req: express.Request, res: express.Response) {
  try {
    const url = `${nodeEndpoint}${nodePath}`;
    const userId = extractUserIdFromJWT(req.headers.authorization);
    let bodyToSend = req.body;
    if (userId && req.method !== 'GET' && req.method !== 'HEAD') {
      bodyToSend = { ...req.body, userId, ownerId: userId };
    }

    const response = await fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
      ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
    });

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      res.status(response.status).json(data);
    } else if (contentType && (contentType.startsWith('image/') || contentType.startsWith('video/') || contentType.startsWith('audio/') || contentType.startsWith('application/octet-stream') || contentType.startsWith('application/pdf'))) {
      // Fichier binaire (image, video, etc.) — transférer en tant que buffer
      const buffer = Buffer.from(await response.arrayBuffer());
      res.setHeader('Content-Type', contentType);
      const cacheControl = response.headers.get('cache-control');
      if (cacheControl) res.setHeader('Cache-Control', cacheControl);
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      res.status(response.status).send(buffer);
    } else {
      res.status(response.status).json({ error: 'Node non disponible' });
    }
  } catch (error) {
    logger.error('Erreur proxy node:', error);
    res.status(502).json({ error: 'Server node indisponible' });
  }
}

// Proxy multipart/form-data vers un server-node (fichiers, images)
async function proxyToNodeMultipart(nodeEndpoint: string, nodePath: string, req: express.Request, res: express.Response) {
  try {
    const url = `${nodeEndpoint}${nodePath}`;
    const userId = extractUserIdFromJWT(req.headers.authorization);

    // Ajouter userId en query si non présent
    const separator = url.includes('?') ? '&' : '?';
    const finalUrl = userId ? `${url}${separator}senderId=${userId}` : url;

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;

        const response = await fetch(finalUrl, {
          method: req.method,
          headers,
          body,
        });

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const data = await response.json();
          res.status(response.status).json(data);
        } else {
          const text = await response.text();
          res.status(response.status).send(text);
        }
      } catch (error) {
        logger.error('Erreur proxy node multipart:', error);
        res.status(502).json({ error: 'Server node indisponible' });
      }
    });
  } catch (error) {
    logger.error('Erreur proxy node multipart:', error);
    res.status(502).json({ error: 'Server node indisponible' });
  }
}

// Réécriture d'URL : /api/servers/:id/X → /X (pour le node)
function rewriteNodePath(req: express.Request, serverId: string): string {
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

// Proxy multipart brut vers un microservice (fallback upload sans node)
async function proxyMultipartToService(targetUrl: string, targetPath: string, req: express.Request, res: express.Response) {
  try {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    const sep = targetPath.includes('?') ? '&' : '?';
    const finalUrl = userId ? `${targetUrl}${targetPath}${sep}senderId=${userId}` : `${targetUrl}${targetPath}`;

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;

        const response = await fetch(finalUrl, { method: 'POST', headers, body });
        const data = await response.json() as any;
        res.status(response.status).json(data);
      } catch (err) {
        logger.error('Erreur proxy multipart service:', err);
        res.status(502).json({ error: 'Service indisponible' });
      }
    });
  } catch (err) {
    logger.error('Erreur proxy multipart service:', err);
    res.status(502).json({ error: 'Service indisponible' });
  }
}

// Route spécifique upload fichiers serveur (avant le catch-all /:serverId/*)
app.post('/api/servers/:serverId/files', (req, res) => {
  const { serverId } = req.params;
  const node = connectedNodes.get(serverId);
  const query = req.originalUrl.includes('?') ? '?' + req.originalUrl.split('?')[1] : '';

  if (node?.endpoint) {
    proxyToNodeMultipart(node.endpoint, `/files${query}`, req, res);
    return;
  }
  // Fallback sans node : vers le servers microservice
  proxyMultipartToService(getServiceUrl('servers', SERVERS_URL), `/servers/${serverId}/files${query}`, req, res);
});

// Serve fichiers uploadés (fallback sans node)
app.get('/api/servers/:serverId/files/:filename', async (req, res) => {
  const { serverId, filename } = req.params;
  const node = connectedNodes.get(serverId);

  if (node?.endpoint) {
    // Proxy vers le node
    try {
      const response = await fetch(`${node.endpoint}/files/${filename}`);
      if (!response.ok) { res.status(response.status).json({ error: 'Fichier non trouvé' }); return; }
      const ct = response.headers.get('content-type');
      if (ct) res.setHeader('Content-Type', ct);
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      res.send(Buffer.from(await response.arrayBuffer()));
    } catch { res.status(502).json({ error: 'Node indisponible' }); }
    return;
  }
  // Fallback vers le servers microservice
  try {
    const response = await fetch(`${getServiceUrl('servers', SERVERS_URL)}/servers/${serverId}/files/${filename}`);
    if (!response.ok) { res.status(response.status).json({ error: 'Fichier non trouvé' }); return; }
    const ct = response.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.send(Buffer.from(await response.arrayBuffer()));
  } catch { res.status(502).json({ error: 'Service indisponible' }); }
});

// Routes serveur-spécifiques : /api/servers/:serverId/...
app.all('/api/servers/:serverId/*', (req, res) => {
  const { serverId } = req.params;
  const node = connectedNodes.get(serverId);

  if (node?.endpoint) {
    const contentType = req.headers['content-type'] || '';
    // Multipart/form-data → proxy brut (fichiers)
    if (contentType.includes('multipart/form-data')) {
      proxyToNodeMultipart(node.endpoint, rewriteNodePath(req, serverId), req, res);
      return;
    }
    const nodePath = rewriteNodePath(req, serverId);
    proxyToNode(node.endpoint, nodePath, req, res);
    return;
  }

  // Aucun node connecté → microservice central
  proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res);
});

// /api/servers/:serverId (sans sous-chemin) → /server sur le node
app.all('/api/servers/:serverId', (req, res) => {
  const { serverId } = req.params;
  const node = connectedNodes.get(serverId);

  if (node?.endpoint) {
    proxyToNode(node.endpoint, '/server', req, res);
    return;
  }

  proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res);
});

// Fallback
app.all('/api/servers', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res));

// Routes Bots
app.all('/api/bots/*', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res));
app.all('/api/bots', (req, res) => proxyRequest(getServiceUrl('bots', BOTS_URL), req, res));

// ============ ROUTES MÉDIA — Routage géo-distribué ============
//
// Structure d'URL pour les médias :
//   Upload  : POST /api/media/upload/:type?location=EU
//   Download: GET  /api/media/:location/:serviceId/:folder/:filename
//             ex.  GET /api/media/EU/media-eu-1/avatars/user123-abc.webp
//
// Si aucune instance n'est enregistrée dans le registre, fallback vers MEDIA_URL.

/** Proxy brut multipart/JSON vers un endpoint media */
async function proxyToMedia(targetEndpoint: string, mediaPath: string, req: express.Request, res: express.Response) {
  try {
    const url = `${targetEndpoint}${mediaPath}`;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;

        const response = await fetch(url, {
          method: req.method,
          headers,
          ...(req.method !== 'GET' && req.method !== 'HEAD' && { body }),
        });

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          res.status(response.status).json(data);
        } else if (
          contentType.startsWith('image/') ||
          contentType.startsWith('video/') ||
          contentType.startsWith('audio/') ||
          contentType.startsWith('application/octet-stream')
        ) {
          const buffer = Buffer.from(await response.arrayBuffer());
          res.setHeader('Content-Type', contentType);
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
          const cc = response.headers.get('cache-control');
          if (cc) res.setHeader('Cache-Control', cc);
          res.status(response.status).send(buffer);
        } else {
          res.status(response.status).send(await response.text());
        }
      } catch (err) {
        logger.error('Erreur proxy média:', err);
        res.status(502).json({ error: 'Service média indisponible' });
      }
    });
  } catch (err) {
    logger.error('Erreur proxy média:', err);
    res.status(502).json({ error: 'Service média indisponible' });
  }
}

// ── Download : GET /api/media/:location/:serviceId/:folder/:filename ──────────
//   Route spécifique avant le catch-all upload
app.get('/api/media/:location/:serviceId/:folder/:filename', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  const { location, serviceId, folder, filename } = req.params;

  // 1. Chercher l'instance par serviceId dans le registre
  let instance = serviceRegistry.getById(serviceId);

  // 2. Fallback : chercher une instance saine dans la même région
  if (!instance || !instance.healthy) {
    const regional = serviceRegistry.selectBestByLocation('media', location);
    if (regional) {
      logger.warn(`MediaProxy: instance ${serviceId} introuvable/hors-ligne, fallback sur ${regional.id}`);
      instance = regional;
    }
  }

  const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
  const mediaPath = `/uploads/${folder}/${filename}`;

  try {
    const response = await fetch(`${targetEndpoint}${mediaPath}`);
    if (!response.ok) {
      res.status(response.status).json({ error: 'Fichier non trouvé' });
      return;
    }
    const contentType = response.headers.get('content-type');
    const cacheControl = response.headers.get('cache-control');
    if (contentType) res.setHeader('Content-Type', contentType);
    if (cacheControl) res.setHeader('Cache-Control', cacheControl);
    res.send(Buffer.from(await response.arrayBuffer()));
  } catch (err) {
    logger.error('Erreur download média:', err);
    res.status(502).json({ error: 'Service média indisponible' });
  }
});

// ── Upload : POST/PATCH /api/media/upload/* → meilleur serveur par localisation ──
app.all('/api/media/upload/*', async (req, res) => {
  // Localisation préférée : header X-Media-Location ou query ?location=EU
  const preferredLocation = (req.headers['x-media-location'] as string | undefined)
    ?? (req.query.location as string | undefined);

  const instance = serviceRegistry.selectBestByLocation('media', preferredLocation)
    ?? null;
  const targetEndpoint = instance?.endpoint ?? MEDIA_URL;

  // Réécrire l'URL vers /media/upload/:type (le préfixe /api est retiré)
  const mediaPath = req.originalUrl.replace(/^\/api/, '');
  proxyToMedia(targetEndpoint, mediaPath, req, res);
});

// ── Catch-all /api/media/* — redirige vers la meilleure instance ──────────────
app.all('/api/media/*', async (req, res) => {
  const preferredLocation = (req.headers['x-media-location'] as string | undefined)
    ?? (req.query.location as string | undefined);
  const instance = serviceRegistry.selectBestByLocation('media', preferredLocation) ?? null;
  const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
  const mediaPath = req.originalUrl.replace(/^\/api/, '');
  proxyToMedia(targetEndpoint, mediaPath, req, res);
});

// Routes Uploads — proxy des fichiers statiques depuis le service média
// (compatibilité avec les anciennes URLs /uploads/*)
app.get('/uploads/*', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  try {
    // Chercher une instance média quelconque saine
    const instance = serviceRegistry.selectBest('media');
    const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
    const url = `${targetEndpoint}${req.originalUrl}`;
    const response = await fetch(url);

    if (!response.ok) {
      res.status(response.status).json({ error: 'Fichier non trouvé' });
      return;
    }

    const contentType = response.headers.get('content-type');
    const cacheControl = response.headers.get('cache-control');
    if (contentType) res.setHeader('Content-Type', contentType);
    if (cacheControl) res.setHeader('Cache-Control', cacheControl);

    const buffer = Buffer.from(await response.arrayBuffer());
    res.send(buffer);
  } catch (error) {
    logger.error('Erreur proxy uploads:', error);
    res.status(502).json({ error: 'Service média indisponible' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'gateway', timestamp: new Date() });
});

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

interface ConnectedClient {
  socketId: string;
  userId: string;
  sessionId: string;
  connectedAt: Date;
}

// ============ MIDDLEWARE D'AUTHENTIFICATION ============

io.use(async (socket: AuthenticatedSocket, next) => {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return next(new Error('Token d\'authentification requis'));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'alfychat-super-secret-key-dev-2026') as { userId: string };
    
    // Vérifier l'utilisateur via le service users
    const user = await serviceProxy.users.getUser(decoded.userId) as User | null;
    
    if (!user) {
      return next(new Error('Utilisateur non trouvé'));
    }

    socket.userId = decoded.userId;
    socket.sessionId = uuidv4();
    socket.user = user;
    
    next();
  } catch (error) {
    logger.error('Erreur d\'authentification WebSocket:', error);
    next(new Error('Token invalide'));
  }
});

// ============ GESTION DES CONNEXIONS ============

const connectedClients = new Map<string, ConnectedClient>();

// ── Message rate limiting ──
// userId → array of timestamps (last N messages)
const messageRateLimit = new Map<string, number[]>();
const MSG_RATE_WINDOW = 5000; // 5 seconds
const MSG_RATE_MAX = 5;       // max 5 messages per window

// Registry des server-nodes self-hostés connectés (keyed by serverId)
const connectedNodes = new Map<string, { socketId: string; serverId: string; endpoint?: string; connectedAt: Date }>();

// ── Voice state tracking ──
// channelId → Map<userId, { socketId, muted, deafened, serverId }>
interface VoiceParticipant {
  socketId: string;
  userId: string;
  username: string;
  avatarUrl?: string;
  muted: boolean;
  deafened: boolean;
  serverId: string;
}
const voiceChannels = new Map<string, Map<string, VoiceParticipant>>();
// userId → channelId (each user can only be in one voice channel)
const userVoiceChannel = new Map<string, string>();

// ── Helper : forward un événement au server-node via acknowledge callback ────
// Retourne null si aucun node n'est connecté (fallback vers microservice)
function getNodeSocket(serverId: string): Socket | null {
  const node = connectedNodes.get(serverId);
  if (!node) return null;
  const ns = io.of('/server-nodes');
  return ns.sockets.get(node.socketId) || null;
}

function forwardToNode(
  serverId: string,
  event: string,
  data: any,
  timeoutMs = 15000,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const nodeSocket = getNodeSocket(serverId);
    if (!nodeSocket) return reject(new Error('NO_NODE'));
    const timer = setTimeout(() => {
      reject(new Error('NODE_TIMEOUT'));
    }, timeoutMs);
    nodeSocket.emit(event, data, (response: any) => {
      clearTimeout(timer);
      if (response?.error) return reject(new Error(response.error));
      resolve(response);
    });
  });
}

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
          combinedPerms |= p;
        }
      }
    }

    // 5. ADMIN implies all
    if (combinedPerms & 0x40) return true;

    // 6. Check required bits
    return (combinedPerms & requiredPerms) === requiredPerms;
  } catch (err) {
    logger.warn('checkServerPermission error:', err);
    return false;
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

  // Joindre automatiquement tous les serveurs dont l'utilisateur est membre
  try {
    const userServers = await serviceProxy.servers.getUserServers(userId);
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

  // Notifier les amis de la connexion
  broadcastPresenceUpdate(userId, 'online', friends);

  // Envoyer les pings en attente (messages reçus hors ligne)
  try {
    const pendingPings = await redis.getPendingPings(userId);
    if (Object.keys(pendingPings).length > 0) {
      socket.emit('PENDING_PINGS', {
        type: 'PENDING_PINGS',
        payload: pendingPings,
        timestamp: new Date(),
      });
      await redis.clearPendingPings(userId);
    }
  } catch { /* non bloquant */ }

  // ============ GESTIONNAIRES D'ÉVÉNEMENTS ============

  // Heartbeat
  socket.on('HEARTBEAT', () => {
    emitToSocket(socket, 'HEARTBEAT_ACK', { timestamp: Date.now() });
  });

  // Messages
  socket.on('MESSAGE_CREATE', async (data) => {
    try {
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
  socket.on('message:send', (data) => {
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

      // Filet de sécurité DM : router aussi directement vers le destinataire
      if (data.recipientId) {
        io.to(`user:${data.recipientId}`).emit('message:new', messageForClient);
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
        // Archive DM si quota atteint
        if (message?.archiveEvent) {
          io.to(`conversation:${conversationId}`).emit('DM_ARCHIVE_PUSH', {
            type: 'DM_ARCHIVE_PUSH',
            payload: message.archiveEvent,
            timestamp: new Date(),
          });
        }
        // Ping hors ligne (non bloquant)
        if (data.recipientId) {
          redis.isUserOnline(data.recipientId as string)
            .then((isOnline: boolean) => {
              if (!isOnline) {
                redis.addPendingPing(
                  data.recipientId as string,
                  conversationId,
                  user.displayName || user.username,
                ).catch(() => {});
              }
            }).catch(() => {});
        }
      }).catch((err: Error) => {
        // La DB a échoué : notifier l'expéditeur pour afficher une erreur sur le message
        console.error('❌ DB write failed for message:', messageId, err);
        socket.emit('message:failed', {
          messageId,
          error: 'Échec de la sauvegarde — veuillez réessayer',
        });
      });

    } catch (error) {
      console.error('❌ Error in message:send:', error);
      socket.emit('message:error', { error: error instanceof Error ? error.message : 'Unknown error' });
    }
  });

  socket.on('MESSAGE_UPDATE', async (data) => {
    try {
      const message = await serviceProxy.messages.updateMessage(data.messageId, data.content, userId);
      
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
  socket.on('message:edit', async (data: { messageId: string; content: string }) => {
    try {
      const updated = await serviceProxy.messages.updateMessage(data.messageId, data.content, userId) as any;
      if (!updated) return;
      const conversationId = updated.conversationId;
      io.to(`conversation:${conversationId}`).emit('message:edited', {
        messageId: updated.id,
        content: updated.content,
        updatedAt: updated.updatedAt,
        isEdited: true,
      });
    } catch (error) {
      console.error('❌ Error editing message:', error);
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
    try {
      await serviceProxy.messages.deleteMessage(data.messageId, userId);
      // Broadcast to conversation. If conversationId not provided, we still need
      // to notify the sender — they can derive it client-side.
      const room = data.conversationId ? `conversation:${data.conversationId}` : `user:${userId}`;
      io.to(room).emit('message:deleted', { messageId: data.messageId });
      // Also notify own socket in case they didn't join the conversation room
      socket.emit('message:deleted', { messageId: data.messageId });
    } catch (error) {
      console.error('❌ Error deleting message:', error);
    }
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

      // Mettre en cache Redis les messages récupérés (24h)
      if (messages && messages.length > 0) {
        try {
          await serviceProxy.messages.cacheArchivedMessages(messages);
        } catch (e) {
          logger.warn('Erreur cache messages archivés:', e);
        }
      }

      // Renvoyer au client demandeur
      io.to(`user:${requesterId}`).emit('DM_ARCHIVE_RESPONSE', {
        type: 'DM_ARCHIVE_RESPONSE',
        payload: {
          conversationId,
          messages: messages || [],
          fromPeerId: userId,
          requestId,
        },
        timestamp: new Date(),
      });

      logger.info(`📨 Peer ${userId} a fourni ${messages?.length || 0} msg archivés pour ${requesterId}`);
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

  // Reconnexion à un appel (après perte de connexion WebSocket)
  socket.on('CALL_REJOIN', (data) => {
    try {
      const { callId } = data;
      if (!callId) return;
      socket.join(`call:${callId}`);
      // Notifier les autres participants pour relancer la négociation WebRTC
      socket.to(`call:${callId}`).emit('CALL_PEER_RECONNECTED', {
        type: 'CALL_PEER_RECONNECTED',
        payload: { callId, userId },
        timestamp: new Date(),
      });
      logger.info(`${userId} rejoint la room call:${callId} après reconnexion`);
    } catch (error) {
      logger.warn('CALL_REJOIN error:', error);
    }
  });

  // ============ SERVEURS P2P ============

  socket.on('SERVER_JOIN', async (data) => {
    try {
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
      await serviceProxy.servers.leaveServer(data.serverId, userId);
      socket.leave(`server:${data.serverId}`);

      // Notifier le node si connecté (avec retry)
      try {
        await forwardToNode(data.serverId, 'MEMBER_KICK', { userId });
        logger.info(`Member ${userId} removed from node for server ${data.serverId}`);
      } catch (nodeErr: any) {
        logger.warn(`Failed to remove member ${userId} from node for server ${data.serverId}: ${nodeErr?.message}`);
        // Retry une fois après 500ms
        setTimeout(async () => {
          try {
            await forwardToNode(data.serverId, 'MEMBER_KICK', { userId });
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
      const { serverId, channelId, content, attachments, replyToId, tags } = data;

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
      const { serverId, messageId, content, channelId } = data;

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
        const result = await forwardToNode(serverId, 'MSG_HISTORY', { channelId, before, limit });
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
      try {
        const result = await forwardToNode(serverId, 'CHANNEL_CREATE', {
          name: data.name, type: data.type || 'text', topic: data.topic, parentId: data.parentId,
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
      const channel = await serviceProxy.servers.createChannel(serverId, { name: data.name, type: data.type, parentId: data.parentId }, userId);
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
      try {
        await forwardToNode(serverId, 'CHANNEL_UPDATE', {
          channelId, name: data.name, topic: data.topic, position: data.position, type: data.type, parentId: data.parentId,
        });
        // Le node broadcast via NODE_BROADCAST
        return;
      } catch (e: any) {
        if (e.message !== 'NO_NODE') { emitError(socket, 'CHANNEL_ERROR', e); return; }
      }
      const channel = await serviceProxy.servers.updateChannel(channelId, data.updates || data, userId);
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
      try {
        await forwardToNode(serverId, 'CHANNEL_DELETE', { channelId });
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
      const result = await forwardToNode(data.serverId, 'CHANNEL_PERMS_SET', {
        channelId: data.channelId,
        roleId: data.roleId,
        allow: data.allow,
        deny: data.deny,
      });
      if (typeof callback === 'function') callback(result);
    } catch (e: any) {
      emitError(socket, 'CHANNEL_ERROR', e);
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
      const result = await forwardToNode(data.serverId, 'ROLE_CREATE', {
        name: data.name, color: data.color, permissions: data.permissions, mentionable: data.mentionable,
      });
      if (result?.role) {
        io.to(`server:${data.serverId}`).emit('ROLE_CREATE', {
          type: 'ROLE_CREATE',
          payload: { ...result.role, serverId: data.serverId },
          timestamp: new Date(),
        });
      }
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
    }
  });

  socket.on('ROLE_UPDATE', async (data) => {
    try {
      const hasPerm = await checkServerPermission(userId, data.serverId, 0x100); // MANAGE_ROLES
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      const result = await forwardToNode(data.serverId, 'ROLE_UPDATE', {
        roleId: data.roleId, name: data.name, color: data.color,
        permissions: data.permissions, position: data.position, mentionable: data.mentionable,
      });
      if (result?.role) {
        io.to(`server:${data.serverId}`).emit('ROLE_UPDATE', {
          type: 'ROLE_UPDATE',
          payload: { ...result.role, serverId: data.serverId },
          timestamp: new Date(),
        });
      }
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
    }
  });

  socket.on('ROLE_DELETE', async (data) => {
    try {
      const hasPerm = await checkServerPermission(userId, data.serverId, 0x100); // MANAGE_ROLES
      if (!hasPerm) { emitError(socket, 'ROLE_ERROR', new Error('PERMISSION_DENIED')); return; }
      await forwardToNode(data.serverId, 'ROLE_DELETE', { roleId: data.roleId });
      io.to(`server:${data.serverId}`).emit('ROLE_DELETE', {
        type: 'ROLE_DELETE',
        payload: { roleId: data.roleId, serverId: data.serverId },
        timestamp: new Date(),
      });
    } catch (error) {
      emitError(socket, 'ROLE_ERROR', error);
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
            forwardToNode(data.serverId, 'MEMBER_KICK', { userId: staleId }).catch(() => {});
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
      const { serverId, targetUserId, roleIds, nickname } = data;

      // Permission check: MANAGE_ROLES required
      const hasPerm = await checkServerPermission(userId, serverId, 0x100);
      if (!hasPerm) {
        if (typeof callback === 'function') callback({ error: 'PERMISSION_DENIED' });
        return;
      }

      try {
        const result = await forwardToNode(serverId, 'MEMBER_UPDATE', {
          userId: targetUserId, roleIds, nickname,
        });
        // Node broadcasts via NODE_BROADCAST relay
        if (typeof callback === 'function') callback(result);
      } catch (e: any) {
        if (e.message !== 'NO_NODE') {
          if (typeof callback === 'function') callback({ error: e.message });
          return;
        }
        // Fallback: update MySQL directly
        await serviceProxy.servers.updateMember(serverId, targetUserId, { roleIds, nickname });
        // Broadcast to all server members
        io.to(`server:${serverId}`).emit('MEMBER_UPDATE', {
          type: 'MEMBER_UPDATE',
          payload: { userId: targetUserId, serverId, roleIds, nickname },
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
      try {
        await forwardToNode(serverId, 'MEMBER_KICK', { userId: targetUserId || data.userId });
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
      try {
        await forwardToNode(serverId, 'MEMBER_BAN', { userId: targetUserId || data.userId, reason });
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
      logger.warn('SERVER_OWNER_JOINED error:', error);
    }
  });

  socket.on('SERVER_UPDATE_NODE', async (data) => {
    try {
      const { serverId } = data;
      try {
        const result = await forwardToNode(serverId, 'SERVER_UPDATE', {
          name: data.name, description: data.description,
          iconUrl: data.iconUrl, bannerUrl: data.bannerUrl, isPublic: data.isPublic,
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
    try {
      const result = await forwardToNode(data.serverId, 'INVITE_CREATE', {
        creatorId: userId, maxUses: data.maxUses, expiresIn: data.expiresIn,
        customSlug: data.customSlug, isPermanent: data.isPermanent,
      });
      // Synchroniser l'invitation dans le MySQL central pour que le lien HTTP fonctionne
      if (result && result.code) {
        try {
          await serviceProxy.servers.createInvite(data.serverId, {
            creatorId: userId,
            code: result.code,
            id: result.id,
            maxUses: data.maxUses,
            expiresIn: data.expiresIn,
            customSlug: data.customSlug,
            isPermanent: data.isPermanent,
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
          creatorId: userId, maxUses: data.maxUses, expiresIn: data.expiresIn,
          customSlug: data.customSlug, isPermanent: data.isPermanent,
        });
        if (typeof callback === 'function') callback(invite);
      } catch {
        if (typeof callback === 'function') callback({ error: e.message });
      }
    }
  });

  socket.on('INVITE_VERIFY', async (data, callback) => {
    try {
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
    socket.join(`channel:${data.channelId}`);
    logger.info(`${userId} rejoint channel:${data.channelId}`);
  });

  socket.on('CHANNEL_LEAVE', async (data) => {
    socket.leave(`channel:${data.channelId}`);
  });

  // Mise à jour de présence
  socket.on('PRESENCE_UPDATE', async (data) => {
    try {
      await serviceProxy.users.updateStatus(userId, data.status, data.customStatus);
      
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
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      const updatedUser = await serviceProxy.users.updateProfile(userId, data, token);

      // Mettre à jour l'objet user local
      Object.assign(socket as AuthenticatedSocket, { user: { ...user, ...data } });

      // Notifier le client
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
        logger.warn('Erreur notification profil amis:', e);
      }
    } catch (error) {
      emitError(socket, 'PROFILE_UPDATE_ERROR', error);
    }
  });

  // ============ GROUPES DE DISCUSSION ============

  // Créer un groupe
  socket.on('GROUP_CREATE', async (data) => {
    try {
      const { name, participantIds, avatarUrl } = data;
      
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
      const { groupId, name, avatarUrl, addParticipants, removeParticipants } = data;
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
  socket.on('VOICE_JOIN', (data) => {
    const { serverId, channelId } = data;
    if (!serverId || !channelId) return;

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
      // Mettre à jour le statut hors ligne
      await redis.setUserOffline(userId);
      await redis.deleteSession(userId, sessionId);
      
      // Notifier les amis (avec gestion d'erreur)
      try {
        const friends = await serviceProxy.friends.getFriends(userId);
        broadcastPresenceUpdate(userId, 'offline', friends);
      } catch (friendsError) {
        logger.warn(`Impossible de notifier les amis pour ${userId}:`, friendsError);
      }
      
      // Mettre à jour last_seen
      try {
        await serviceProxy.users.updateLastSeen(userId);
      } catch (updateError) {
        logger.warn(`Impossible de mettre à jour last_seen pour ${userId}:`, updateError);
      }
    } catch (error) {
      logger.error(`Erreur lors de la déconnexion de ${userId}:`, error);
    }
  });
});

// ============ SERVER NODES NAMESPACE (self-hosted) ============

// Le namespace /server-nodes utilise une authentification différente (nodeToken, pas JWT user)
const serverNodesNs = io.of('/server-nodes');

serverNodesNs.use(async (socket, next) => {
  try {
    const { nodeToken, serverId, register } = socket.handshake.auth;

    // Mode enregistrement automatique : pas de credentials requis
    if (register === true) {
      (socket as any).registerMode = true;
      return next();
    }

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
    logger.error('Erreur authentification server-node:', err?.message || err);
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
      logger.error('Erreur lors de l\'auto-enregistrement du server-node:', err);
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
  const setupCode = Math.random().toString(36).substring(2, 10).toUpperCase();
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
  nodeSocket.on('NODE_BROADCAST', (data: { event: string; data: any }) => {
    const { event, data: payload } = data;

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
  for (const friend of friends) {
    io.to(`user:${friend.friendId}`).emit('PRESENCE_UPDATE', {
      type: 'PRESENCE_UPDATE',
      payload: { userId, status, customStatus: customStatus ?? null },
      timestamp: new Date(),
    });
  }
}

// ============ ROUTES HTTP ============

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'gateway',
    uptime: process.uptime(),
    connections: connectedClients.size,
  });
});

app.get('/stats', (req, res) => {
  res.json({
    connections: connectedClients.size,
    rooms: io.sockets.adapter.rooms.size,
  });
});

// ============ MONITORING SYSTEM ============

const MONITORED_SERVICES: { name: string; url: string }[] = [
  { name: 'website',  url: `${process.env.FRONTEND_URL         || 'https://alfychat.app'}` },
  { name: 'users',    url: `${process.env.USERS_SERVICE_URL    || 'http://localhost:3001'}/health` },
  { name: 'messages', url: `${process.env.MESSAGES_SERVICE_URL || 'http://localhost:3002'}/health` },
  { name: 'friends',  url: `${process.env.FRIENDS_SERVICE_URL  || 'http://localhost:3003'}/health` },
  { name: 'calls',    url: `${process.env.CALLS_SERVICE_URL    || 'http://localhost:3004'}/health` },
  { name: 'servers',  url: `${process.env.SERVERS_SERVICE_URL  || 'http://localhost:3005'}/health` },
  { name: 'bots',     url: `${process.env.BOTS_SERVICE_URL     || 'http://localhost:3006'}/health` },
  { name: 'media',    url: `${process.env.MEDIA_SERVICE_URL    || 'http://localhost:3007'}/health` },
];

const MONITORING_INTERVAL_MS = parseInt(process.env.MONITORING_INTERVAL || '60000'); // 60s default

async function runMonitoringCycle(): Promise<void> {
  const now = new Date();

  // 1. Check each service health (via /health, pour le statut up/down)
  const snapshots = await Promise.all(
    MONITORED_SERVICES.map(async (svc) => {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(svc.url, { signal: controller.signal });
        clearTimeout(timeout);
        const ms = Date.now() - start;
        const status = resp.ok ? 'up' : 'degraded';
        return {
          service: svc.name,
          status: status as 'up' | 'degraded' | 'down',
          responseTimeMs: ms,
          statusCode: resp.status,
          checkedAt: now,
        };
      } catch {
        return {
          service: svc.name,
          status: 'down' as const,
          responseTimeMs: null,
          statusCode: null,
          checkedAt: now,
        };
      }
    }),
  );

  // 2. Poll /metrics de chaque instance enregistrée dans le registre
  //    → met à jour CPU/RAM/req/debit en temps réel pour toutes les instances
  const registeredInstances = serviceRegistry.getAll();
  await Promise.all(
    registeredInstances.map(async (instance) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const resp = await fetch(`${instance.endpoint}/metrics`, { signal: controller.signal });
        clearTimeout(timeout);
        if (!resp.ok) return;
        const data = await resp.json() as any;
        // Mettre à jour les métriques dans le registre si les données sont valides
        if (typeof data.cpuUsage === 'number' && typeof data.ramUsage === 'number') {
          serviceRegistry.heartbeat(instance.id, {
            ramUsage: data.ramUsage ?? 0,
            ramMax: data.ramMax ?? 0,
            cpuUsage: data.cpuUsage ?? 0,
            cpuMax: data.cpuMax ?? 100,
            bandwidthUsage: data.bandwidthUsage ?? 0,
            requestCount20min: data.requestCount20min ?? 0,
            responseTimeMs: data.responseTimeMs,
          });
        }
      } catch {
        // Pas bloquant — le heartbeat push prend le relais si /metrics est indisponible
      }
    }),
  );

  // 3. Add gateway itself (measure own /health response time)
  const gwStart = Date.now();
  try {
    await fetch(`http://localhost:${PORT}/health`, { signal: AbortSignal.timeout(2000) });
  } catch { /* ignore */ }
  snapshots.push({
    service: 'gateway',
    status: 'up',
    responseTimeMs: Date.now() - gwStart,
    statusCode: 200,
    checkedAt: now,
  });

  // 4. Save to DB
  await monitoringDB.saveServiceSnapshot(snapshots);

  // 5. Save connected user count
  await monitoringDB.saveUserStats(connectedClients.size);

  logger.info(`[Monitoring] Cycle terminé — ${connectedClients.size} users connectés — services: ${snapshots.map(s => `${s.service}:${s.status}`).join(', ')} — instances polled: ${registeredInstances.length}`);
}

// Admin monitoring API — requires admin role
async function requireAdmin(req: express.Request, res: express.Response): Promise<string | null> {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) { res.status(401).json({ error: 'Non authentifié' }); return null; }
  try {
    const userRes = await fetch(`${getServiceUrl('users', USERS_URL)}/users/${userId}`, {
      headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
    });
    const userData = await safeJson(userRes) as any;
    if (!userData || userData.role !== 'admin') { res.status(403).json({ error: 'Accès refusé' }); return null; }
  } catch {
    res.status(502).json({ error: 'Service indisponible' });
    return null;
  }
  return userId;
}

// ============ DÉMARRAGE ============

const PORT = process.env.PORT || 3000;

/**
 * Charge les instances de service depuis la DB MySQL et les enregistre dans le registre.
 * Fallback sur les URL d'environnement si la DB n'est pas disponible.
 */
async function loadInstancesFromDB(): Promise<void> {
  const rows = await monitoringDB.loadServiceInstances();
  if (rows.length > 0) {
    for (const row of rows) {
      serviceRegistry.register({
        id: row.id,
        serviceType: row.serviceType as ServiceType,
        endpoint: row.endpoint,
        domain: row.domain,
        location: row.location,
        metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 0, bandwidthUsage: 0, requestCount20min: 0 },
      });
    }
    logger.info(`ServiceRegistry: ${rows.length} instances chargées depuis la DB`);
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
  // First cycle immediately, then every MONITORING_INTERVAL_MS
  runMonitoringCycle().catch((err) => logger.error('Monitoring cycle error:', err));
  setInterval(() => {
    runMonitoringCycle().catch((err) => logger.error('Monitoring cycle error:', err));
    // Prune data older than 30 days every 24h
  }, MONITORING_INTERVAL_MS);
  // Daily prune at startup + every 24h
  monitoringDB.prune(30).catch(() => {});
  setInterval(() => monitoringDB.prune(30).catch(() => {}), 24 * 60 * 60 * 1000);
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
