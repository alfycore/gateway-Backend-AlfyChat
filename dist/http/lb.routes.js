"use strict";
// ==========================================
// ALFYCHAT — LB Routes
// Endpoints utilisés par les microservices
// pour s'enregistrer et envoyer leurs métriques
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerLBRoutes = registerLBRoutes;
const registry_1 = require("../lb/registry");
const gateway_registry_1 = require("../lb/gateway-registry");
const monitoring_db_1 = require("../utils/monitoring-db");
const logger_1 = require("../utils/logger");
const env_1 = require("../config/env");
const GATEWAY_ID = process.env.GATEWAY_ID || 'gateway-default';
const HEARTBEAT_INTERVAL = 30_000;
function registerLBRoutes(app) {
    /**
     * POST /api/lb/register
     * Un microservice s'enregistre avec sa SERVICE_KEY.
     * Header : X-Service-Key: sk_xxx
     * Body   : { endpoint: string, domain?: string }
     * Retour : { serviceId, gatewayId, heartbeatIntervalMs }
     */
    app.post('/api/lb/register', (req, res) => {
        const key = req.headers['x-service-key'];
        const internalSecret = req.headers['x-internal-secret'];
        const { endpoint, domain, serviceId: bodyServiceId } = req.body ?? {};
        if (!endpoint || typeof endpoint !== 'string') {
            return res.status(400).json({ error: 'endpoint requis' });
        }
        let entry;
        // Fallback : INTERNAL_SECRET + serviceId dans le body (SERVICE_KEY absent)
        if (!key?.startsWith('sk_')) {
            if (!internalSecret || internalSecret !== env_1.INTERNAL_SECRET) {
                return res.status(401).json({ error: 'X-Service-Key requis (format sk_...) ou X-Internal-Secret valide' });
            }
            if (!bodyServiceId || typeof bodyServiceId !== 'string') {
                return res.status(400).json({ error: 'serviceId requis dans le body quand SERVICE_KEY absent' });
            }
            entry = registry_1.lbRegistry.registerById(bodyServiceId, { endpoint, domain: domain || undefined, gatewayId: GATEWAY_ID });
            if (!entry) {
                return res.status(403).json({ error: 'Service introuvable ou désactivé — vérifiez SERVICE_ID dans votre .env' });
            }
        }
        else {
            entry = registry_1.lbRegistry.registerWithKey(key, { endpoint, domain: domain || undefined, gatewayId: GATEWAY_ID });
            if (!entry) {
                return res.status(403).json({ error: 'Clé invalide ou service désactivé — vérifiez SERVICE_KEY dans votre .env' });
            }
        }
        monitoring_db_1.monitoringDB.updateServiceEndpoint(entry.id, endpoint).catch(() => { });
        gateway_registry_1.gatewayRegistry.touch(GATEWAY_ID);
        logger_1.logger.info(`LB: "${entry.id}" (${entry.serviceType}) connecté via [${GATEWAY_ID}]`);
        res.json({
            success: true,
            serviceId: entry.id,
            serviceType: entry.serviceType,
            gatewayId: GATEWAY_ID,
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
        const key = req.headers['x-service-key'];
        const internalSecret = req.headers['x-internal-secret'];
        let serviceId = null;
        if (key) {
            serviceId = registry_1.lbRegistry.validateKey(key);
        }
        else if (internalSecret === env_1.INTERNAL_SECRET) {
            serviceId = req.body?.serviceId ?? null;
        }
        if (!serviceId)
            return res.status(403).json({ error: 'Clé invalide ou serviceId manquant' });
        const { metrics } = req.body ?? {};
        if (!metrics || typeof metrics !== 'object') {
            return res.status(400).json({ error: 'metrics requis' });
        }
        const ok = registry_1.lbRegistry.heartbeat(serviceId, metrics);
        if (!ok) {
            return res.status(404).json({ error: 'Service introuvable — ré-enregistrez-vous via /api/lb/register' });
        }
        gateway_registry_1.gatewayRegistry.touch(GATEWAY_ID);
        res.json({ success: true });
    });
    /**
     * POST /api/lb/deregister
     * Déconnexion gracieuse (arrêt propre du service).
     * Header : X-Service-Key: sk_xxx
     */
    app.post('/api/lb/deregister', (req, res) => {
        const key = req.headers['x-service-key'];
        const internalSecret = req.headers['x-internal-secret'];
        let serviceId = null;
        if (key) {
            serviceId = registry_1.lbRegistry.validateKey(key);
        }
        else if (internalSecret === env_1.INTERNAL_SECRET) {
            serviceId = req.body?.serviceId ?? null;
        }
        if (!serviceId)
            return res.status(403).json({ error: 'Clé invalide ou serviceId manquant' });
        const entry = registry_1.lbRegistry.getById(serviceId);
        if (entry) {
            entry.status = 'offline';
            entry.healthy = false;
            logger_1.logger.info(`LB: "${serviceId}" déconnecté gracieusement`);
        }
        res.json({ success: true });
    });
}
//# sourceMappingURL=lb.routes.js.map