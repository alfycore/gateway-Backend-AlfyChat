import express, { type Express } from 'express';
import { serviceRegistry, type ServiceType } from '../utils/service-registry';
import { monitoringDB } from '../utils/monitoring-db';
import { logger } from '../utils/logger';
import { validateServiceSecret, bannedServiceIds, allowedServiceIds } from '../state/service-keys';
import { INTERNAL_SECRET, IP_ENDPOINT_RE } from '../config/env';

export function registerInternalRoutes(app: Express): void {
  /**
   * POST /api/internal/service/register
   * Enregistre (ou met à jour) une instance de microservice dans le registre.
   * Protégé par le secret partagé INTERNAL_SECRET.
   *
   * Body: { secret, id, serviceType, endpoint, domain, location, metrics }
   */
  app.post('/api/internal/service/register', express.json(), (req, res) => {
    const { secret, id, serviceType, endpoint, domain, location, metrics } = req.body ?? {};

    if (!secret || !id || !validateServiceSecret(String(id), String(secret))) {
      return res.status(401).json({ error: 'Secret invalide' });
    }

    const VALID_TYPES: ServiceType[] = ['users', 'messages', 'friends', 'calls', 'servers', 'bots', 'media'];
    if (!id || !VALID_TYPES.includes(serviceType) || !endpoint || !domain || !location) {
      return res.status(400).json({ error: 'Paramètres manquants ou invalides (id, serviceType, endpoint, domain, location)' });
    }

    // Rejeter les instances bannies/désactivées par un admin
    if (bannedServiceIds.has(String(id))) {
      return res.status(403).json({ error: 'Instance désactivée — contactez un administrateur' });
    }

    // Rejeter les IDs non pré-enregistrés par un admin (whitelist)
    if (allowedServiceIds.size > 0 && !allowedServiceIds.has(String(id))) {
      logger.warn(`ServiceRegistry: tentative d'enregistrement non autorisée — ID "${id}" non connu (${endpoint})`);
      return res.status(403).json({ error: 'Instance non autorisée — seul un administrateur peut ajouter de nouveaux services' });
    }

    // Rejeter les endpoints avec une adresse IP (seuls les noms de domaine sont acceptés)
    if (IP_ENDPOINT_RE.test(String(endpoint))) {
      logger.warn(`ServiceRegistry: endpoint IP refusé pour "${id}" — (${endpoint}) — utilisez un nom de domaine`);
      return res.status(400).json({ error: 'Adresse IP non autorisée — utilisez un nom de domaine (ex: service.alfychat.eu)' });
    }

    const resolvedEndpoint = String(endpoint);
    const resolvedDomain   = String(domain);

    const defaultMetrics = {
      ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 100,
      bandwidthUsage: 0, requestCount20min: 0,
    };

    const instance = serviceRegistry.register({
      id: String(id),
      serviceType: serviceType as ServiceType,
      endpoint: resolvedEndpoint,
      domain: resolvedDomain,
      location: String(location).toUpperCase(),
      metrics: metrics ?? defaultMetrics,
    });

    // Persist to DB (non-blocking)
    monitoringDB.upsertServiceInstance({
      id: String(id),
      serviceType: String(serviceType),
      endpoint: resolvedEndpoint,
      domain: resolvedDomain,
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

    if (!secret || !id || !validateServiceSecret(String(id), String(secret))) {
      return res.status(401).json({ error: 'Secret invalide' });
    }

    if (!id || !metrics) {
      return res.status(400).json({ error: 'id et metrics requis' });
    }

    // Rejeter le heartbeat des instances bannies par un admin
    if (bannedServiceIds.has(String(id))) {
      return res.status(403).json({ error: 'Instance bannie — supprimée par un administrateur' });
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
}
