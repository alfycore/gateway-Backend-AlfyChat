import express, { type Express } from 'express';
import { timingSafeEqual } from 'crypto';
import { serviceRegistry, type ServiceType } from '../utils/service-registry';
import { monitoringDB } from '../utils/monitoring-db';
import { logger } from '../utils/logger';
import { validateServiceSecret, bannedServiceIds, allowedServiceIds } from '../state/service-keys';
import { INTERNAL_SECRET, IP_ENDPOINT_RE } from '../config/env';

function safeCompare(a: string, b: string): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function registerInternalRoutes(app: Express): void {
  /**
   * POST /api/internal/service/register
   * Désactivé : l'auto-enregistrement des services n'est plus autorisé.
   * Un administrateur doit ajouter les instances manuellement via POST /api/admin/services.
   */
  app.post('/api/internal/service/register', express.json(), (req, res) => {
    const { id } = req.body ?? {};
    logger.warn(`ServiceRegistry: tentative d'auto-enregistrement refusée pour "${id || 'unknown'}" — admin-only`);
    return res.status(403).json({
      error: 'Auto-enregistrement désactivé — un administrateur doit ajouter ce service via /api/admin/services',
    });
  });

  /**
   * POST /api/internal/service/heartbeat
   * Met à jour les métriques d'une instance déjà enregistrée.
   *
   * Body: { secret, id, metrics }
   */
  app.post('/api/internal/service/heartbeat', express.json(), (req, res) => {
    const { secret, id, metrics } = req.body ?? {};

    if (INTERNAL_SECRET && (!secret || !validateServiceSecret(String(id), String(secret)))) {
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
    if (!secret || !safeCompare(String(secret), INTERNAL_SECRET)) {
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
    const secret = req.headers['x-internal-secret'] as string | undefined;
    if (!secret || !safeCompare(String(secret), INTERNAL_SECRET)) {
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
