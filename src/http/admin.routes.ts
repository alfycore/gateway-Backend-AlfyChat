import type { Express } from 'express';
import { runtime } from '../state/runtime';
import { extractUserIdFromJWT, safeJson, getServiceUrl } from './helpers';
import { proxyRequest } from './proxy';
import { requireAdmin } from '../monitoring/admin-guard';
import { monitoringDB } from '../utils/monitoring-db';
import type { ServiceUptimeDay } from '../utils/monitoring-db';
import { serviceRegistry, type ServiceType } from '../utils/service-registry';
import { logger } from '../utils/logger';
import { connectedClients } from '../state/connections';
import { serviceKeyHashes, bannedServiceIds, allowedServiceIds, generateServiceKey } from '../state/service-keys';
import {
  USERS_URL, RATE_LIMIT_WINDOW, RATE_LIMIT_ANON, RATE_LIMIT_USER, RATE_LIMIT_ADMIN, IP_ENDPOINT_RE,
} from '../config/env';

export function registerAdminRoutes(app: Express): void {
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
      const bannedIPs = await runtime.redis.getBannedIPs();
      const rateLimitStats = await runtime.redis.getRateLimitStats();
      res.json({
        bannedIPs,
        rateLimitStats,
        config: { window: RATE_LIMIT_WINDOW, anon: RATE_LIMIT_ANON, user: RATE_LIMIT_USER, admin: RATE_LIMIT_ADMIN },
      });
    } catch (error) {
      logger.error({ err: error }, 'Erreur stats gateway:');
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
      await runtime.redis.banIP(ip.trim(), reason || 'Banni par un administrateur', userId);
      logger.info(`IP bannie: ${ip} par ${userId} — raison: ${reason || 'non spécifiée'}`);
      res.json({ success: true });
    } catch (error) {
      logger.error({ err: error }, 'Erreur ban IP:');
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
      await runtime.redis.unbanIP(ip);
      logger.info(`IP débannie: ${ip} par ${userId}`);
      res.json({ success: true });
    } catch (error) {
      logger.error({ err: error }, 'Erreur unban IP:');
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
      logger.error({ err: err }, 'Erreur /api/admin/monitoring:');
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
      logger.error({ err: err }, 'Erreur /api/admin/monitoring/service:');
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
      logger.error({ err: err }, 'Erreur /api/admin/monitoring/users/chart:');
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
      const uptimeByService: Record<string, ServiceUptimeDay[]> = {};
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
      logger.error({ err: err }, 'Erreur /api/status:');
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
      logger.error({ err: err }, 'Erreur GET /api/admin/status/incidents:');
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
      logger.error({ err: err }, 'Erreur POST /api/admin/status/incidents:');
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
      logger.error({ err: err }, 'Erreur PATCH /api/admin/status/incidents:');
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
      logger.error({ err: err }, 'Erreur DELETE /api/admin/status/incidents:');
      res.status(500).json({ error: 'Erreur serveur' });
    }
  });

  // ── Admin: service registry management ───────────────────────────────────────

  /** GET /api/admin/services — liste toutes les instances connues (y compris désactivées) */
  app.get('/api/admin/services', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const instances = serviceRegistry.getAll().map((i) => ({
      ...i,
      score: serviceRegistry.computeScore(i),
    }));
    res.json({ instances });
  });

  /** GET /api/admin/services/:type — instances d'un type donné (y compris désactivées) */
  app.get('/api/admin/services/:type', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const instances = serviceRegistry.getInstances(req.params.type as ServiceType, true, true).map((i) => ({
      ...i,
      score: serviceRegistry.computeScore(i),
    }));
    res.json({ instances });
  });

  /** POST /api/admin/services — ajoute manuellement une instance */
  app.post('/api/admin/services', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const { id, serviceType, endpoint, domain, location } = req.body ?? {};
    const VALID_TYPES: ServiceType[] = ['users', 'messages', 'friends', 'calls', 'servers', 'bots', 'media'];
    if (!id || !VALID_TYPES.includes(serviceType) || !endpoint || !domain || !location) {
      return res.status(400).json({ error: 'id, serviceType, endpoint, domain, location requis' });
    }
    // Rejeter les endpoints IP
    if (IP_ENDPOINT_RE.test(String(endpoint))) {
      return res.status(400).json({ error: 'Adresse IP non autorisée — utilisez un nom de domaine' });
    }
    const instance = serviceRegistry.register({
      id: String(id),
      serviceType: serviceType as ServiceType,
      endpoint: String(endpoint),
      domain: String(domain),
      location: String(location).toUpperCase(),
      metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 100, bandwidthUsage: 0, requestCount20min: 0 },
      enabled: true,
    });
    monitoringDB.upsertServiceInstance({
      id: String(id), serviceType: String(serviceType),
      endpoint: String(endpoint), domain: String(domain),
      location: String(location).toUpperCase(),
    }).catch(() => {});
    // Générer une clé unique pour ce service
    const { rawKey, hash } = generateServiceKey();
    serviceKeyHashes.set(String(id), hash);
    monitoringDB.storeServiceKeyHash(String(id), rawKey).catch(() => {});
    // Ajouter à la whitelist et retirer des blacklists
    allowedServiceIds.add(String(id));
    bannedServiceIds.delete(String(id));
    logger.info(`Admin: service "${id}" ajouté avec une clé unique`);
    res.status(201).json({ success: true, instance, serviceKey: rawKey });
  });

  /**
   * PATCH /api/admin/services/:id — active ou désactive une instance (persiste en DB).
   * Body: { enabled: boolean }
   * Ne bannit pas → le service peut continuer à heartbeater mais ne reçoit plus de trafic.
   */
  app.patch('/api/admin/services/:id', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const decodedId = decodeURIComponent(req.params.id);
    const { enabled } = req.body ?? {};
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'Le champ "enabled" (boolean) est requis' });
    }
    const ok = serviceRegistry.setEnabled(decodedId, enabled);
    if (!ok) return res.status(404).json({ error: 'Instance introuvable' });
    // Persister l'état en DB
    monitoringDB.setInstanceEnabled(decodedId, enabled).catch(() => {});
    // Synchroniser la blacklist mémoire
    if (enabled) bannedServiceIds.delete(decodedId);
    else bannedServiceIds.add(decodedId);
    logger.info(`Admin: instance "${decodedId}" ${enabled ? 'activée' : 'désactivée'}`);
    res.json({ success: true, enabled });
  });

  /**
   * DELETE /api/admin/services/:id — supprime définitivement une instance.
   * Ban en mémoire (jusqu'au prochain redémarrage du gateway) + suppression DB.
   */
  app.delete('/api/admin/services/:id', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const decodedId = decodeURIComponent(req.params.id);
    const removed = serviceRegistry.remove(decodedId);
    if (!removed) return res.status(404).json({ error: 'Instance introuvable' });
    bannedServiceIds.add(decodedId);
    allowedServiceIds.delete(decodedId);  // Retirer de la whitelist → plus jamais de ré-enregistrement
    logger.info(`ServiceRegistry: instance "${decodedId}" supprimée et bannie par un admin`);
    monitoringDB.removeServiceInstance(decodedId).catch(() => {});
    res.json({ success: true });
  });

  /**
   * POST /api/admin/services/:id/rotate-key
   * Régénère la clé de service pour une instance existante.
   * Retourne la nouvelle clé (affichée une seule fois) — mettre à jour le .env du service.
   */
  app.post('/api/admin/services/:id/rotate-key', async (req, res) => {
    if (!await requireAdmin(req, res)) return;
    const decodedId = decodeURIComponent(req.params.id);
    if (!serviceRegistry.getAll().find(i => i.id === decodedId)) {
      return res.status(404).json({ error: 'Instance introuvable' });
    }
    const { rawKey, hash } = generateServiceKey();
    serviceKeyHashes.set(decodedId, hash);
    monitoringDB.storeServiceKeyHash(decodedId, rawKey).catch(() => {});
    logger.info(`Admin: clé régénérée pour le service "${decodedId}"`);
    res.json({ success: true, serviceKey: rawKey });
  });

  // Proxy helpdesk → users service (must be before /api/admin catch-all)
  app.all('/api/helpdesk/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
  app.all('/api/helpdesk', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));

  app.all('/api/admin/*', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
  app.all('/api/admin', (req, res) => proxyRequest(getServiceUrl('users', USERS_URL), req, res, USERS_URL));
}
