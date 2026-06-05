"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerInternalRoutes = registerInternalRoutes;
const express_1 = __importDefault(require("express"));
const crypto_1 = require("crypto");
const service_registry_1 = require("../utils/service-registry");
const monitoring_db_1 = require("../utils/monitoring-db");
const logger_1 = require("../utils/logger");
const service_keys_1 = require("../state/service-keys");
const env_1 = require("../config/env");
function safeCompare(a, b) {
    if (!a || !b)
        return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length)
        return false;
    return (0, crypto_1.timingSafeEqual)(bufA, bufB);
}
function registerInternalRoutes(app) {
    /**
     * POST /api/internal/service/register
     * Désactivé : l'auto-enregistrement des services n'est plus autorisé.
     * Un administrateur doit ajouter les instances manuellement via POST /api/admin/services.
     */
    app.post('/api/internal/service/register', express_1.default.json(), (req, res) => {
        const { id } = req.body ?? {};
        logger_1.logger.warn(`ServiceRegistry: tentative d'auto-enregistrement refusée pour "${id || 'unknown'}" — admin-only`);
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
    app.post('/api/internal/service/heartbeat', express_1.default.json(), (req, res) => {
        const { secret, id, metrics } = req.body ?? {};
        if (env_1.INTERNAL_SECRET && (!secret || !(0, service_keys_1.validateServiceSecret)(String(id), String(secret)))) {
            return res.status(401).json({ error: 'Secret invalide' });
        }
        if (!id || !metrics) {
            return res.status(400).json({ error: 'id et metrics requis' });
        }
        // Rejeter le heartbeat des instances bannies par un admin
        if (service_keys_1.bannedServiceIds.has(String(id))) {
            return res.status(403).json({ error: 'Instance bannie — supprimée par un administrateur' });
        }
        const updated = service_registry_1.serviceRegistry.heartbeat(String(id), metrics);
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
    app.post('/api/internal/service/deregister', express_1.default.json(), (req, res) => {
        const { secret, id } = req.body ?? {};
        if (!secret || !safeCompare(String(secret), env_1.INTERNAL_SECRET)) {
            return res.status(401).json({ error: 'Secret invalide' });
        }
        if (!id)
            return res.status(400).json({ error: 'id requis' });
        const removed = service_registry_1.serviceRegistry.remove(String(id));
        if (removed)
            monitoring_db_1.monitoringDB.removeServiceInstance(String(id)).catch(() => { });
        res.json({ success: removed });
    });
    /**
     * GET /api/internal/service/list
     * Retourne toutes les instances enregistrées avec leurs métriques et scores.
     * Protégé par X-Internal-Secret header ou ?secret=... query param.
     */
    app.get('/api/internal/service/list', (req, res) => {
        const secret = req.headers['x-internal-secret'];
        if (!secret || !safeCompare(String(secret), env_1.INTERNAL_SECRET)) {
            return res.status(401).json({ error: 'Secret invalide' });
        }
        const instances = service_registry_1.serviceRegistry.getAll().map((inst) => ({
            ...inst,
            score: service_registry_1.serviceRegistry.computeScore(inst),
        }));
        res.json({
            count: instances.length,
            healthy: instances.filter((i) => i.healthy).length,
            instances,
        });
    });
}
//# sourceMappingURL=internal.routes.js.map