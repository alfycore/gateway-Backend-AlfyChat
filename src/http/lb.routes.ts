// ==========================================
// ALFYCHAT — LB Routes
// Endpoints utilisés par les microservices
// pour s'enregistrer et envoyer leurs métriques
// ==========================================

import type { Express } from 'express';
import { lbRegistry, type ServiceMetrics } from '../lb/registry';
import { gatewayRegistry } from '../lb/gateway-registry';
import { monitoringDB } from '../utils/monitoring-db';
import { logger } from '../utils/logger';

const GATEWAY_ID           = process.env.GATEWAY_ID || 'gateway-default';
const HEARTBEAT_INTERVAL   = 30_000;

export function registerLBRoutes(app: Express): void {

  /**
   * POST /api/lb/register
   * Un microservice s'enregistre avec sa SERVICE_KEY.
   * Header : X-Service-Key: sk_xxx
   * Body   : { endpoint: string, domain?: string }
   * Retour : { serviceId, gatewayId, heartbeatIntervalMs }
   */
  app.post('/api/lb/register', (req, res) => {
    const key = req.headers['x-service-key'] as string | undefined;
    if (!key?.startsWith('sk_')) {
      return res.status(401).json({ error: 'X-Service-Key requis (format sk_...)' });
    }
    const { endpoint, domain } = req.body ?? {};
    if (!endpoint || typeof endpoint !== 'string') {
      return res.status(400).json({ error: 'endpoint requis' });
    }

    const entry = lbRegistry.registerWithKey(key, {
      endpoint,
      domain:    domain || undefined,
      gatewayId: GATEWAY_ID,
    });

    if (!entry) {
      return res.status(403).json({ error: 'Clé invalide ou service désactivé — vérifiez SERVICE_KEY dans votre .env' });
    }

    monitoringDB.updateServiceEndpoint(entry.id, endpoint).catch(() => {});
    gatewayRegistry.touch(GATEWAY_ID);

    logger.info(`LB: "${entry.id}" (${entry.serviceType}) connecté via [${GATEWAY_ID}]`);
    res.json({
      success:             true,
      serviceId:           entry.id,
      serviceType:         entry.serviceType,
      gatewayId:           GATEWAY_ID,
      heartbeatIntervalMs: HEARTBEAT_INTERVAL,
    });
  });

  /**
   * POST /api/lb/heartbeat
   * Heartbeat périodique avec métriques système.
   * Header : X-Service-Key: sk_xxx
   * Body   : { metrics: { cpuUsage, cpuMax, ramUsage, ramMax, bandwidthUsage, requestCount20min } }
   */
  app.post('/api/lb/heartbeat', (req, res) => {
    const key = req.headers['x-service-key'] as string | undefined;
    if (!key) return res.status(401).json({ error: 'X-Service-Key requis' });

    const serviceId = lbRegistry.validateKey(key);
    if (!serviceId) return res.status(403).json({ error: 'Clé invalide' });

    const { metrics } = req.body ?? {};
    if (!metrics || typeof metrics !== 'object') {
      return res.status(400).json({ error: 'metrics requis' });
    }

    const ok = lbRegistry.heartbeat(serviceId, metrics as ServiceMetrics);
    if (!ok) {
      return res.status(404).json({ error: 'Service introuvable — ré-enregistrez-vous via /api/lb/register' });
    }

    gatewayRegistry.touch(GATEWAY_ID);
    res.json({ success: true });
  });

  /**
   * POST /api/lb/deregister
   * Déconnexion gracieuse (arrêt propre du service).
   * Header : X-Service-Key: sk_xxx
   */
  app.post('/api/lb/deregister', (req, res) => {
    const key = req.headers['x-service-key'] as string | undefined;
    if (!key) return res.status(401).json({ error: 'X-Service-Key requis' });

    const serviceId = lbRegistry.validateKey(key);
    if (!serviceId) return res.status(403).json({ error: 'Clé invalide' });

    const entry = lbRegistry.getById(serviceId);
    if (entry) {
      entry.status  = 'offline';
      entry.healthy = false;
      logger.info(`LB: "${serviceId}" déconnecté gracieusement`);
    }
    res.json({ success: true });
  });
}
