"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerAdminRoutes = registerAdminRoutes;
const runtime_1 = require("../state/runtime");
const helpers_1 = require("./helpers");
const proxy_1 = require("./proxy");
const admin_guard_1 = require("../monitoring/admin-guard");
const monitoring_db_1 = require("../utils/monitoring-db");
const service_registry_1 = require("../utils/service-registry");
const logger_1 = require("../utils/logger");
const connections_1 = require("../state/connections");
const service_keys_1 = require("../state/service-keys");
const env_1 = require("../config/env");
function registerAdminRoutes(app) {
    // ============ ADMIN : GESTION IP BANS (gateway direct) ============
    app.get('/api/admin/gateway/stats', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        // Vérifier le rôle admin via le service users
        try {
            const userRes = await fetch(`${(0, helpers_1.getServiceUrl)('users', env_1.USERS_URL)}/users/${userId}`, {
                headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
            });
            const userData = await (0, helpers_1.safeJson)(userRes);
            if (!userData || userData.role !== 'admin')
                return res.status(403).json({ error: 'Accès refusé' });
        }
        catch {
            return res.status(502).json({ error: 'Service indisponible' });
        }
        try {
            const bannedIPs = await runtime_1.runtime.redis.getBannedIPs();
            const rateLimitStats = await runtime_1.runtime.redis.getRateLimitStats();
            res.json({
                bannedIPs,
                rateLimitStats,
                config: { window: env_1.RATE_LIMIT_WINDOW, anon: env_1.RATE_LIMIT_ANON, user: env_1.RATE_LIMIT_USER, admin: env_1.RATE_LIMIT_ADMIN },
            });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur stats gateway:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    app.post('/api/admin/gateway/ban-ip', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        try {
            const userRes = await fetch(`${(0, helpers_1.getServiceUrl)('users', env_1.USERS_URL)}/users/${userId}`, {
                headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
            });
            const userData = await (0, helpers_1.safeJson)(userRes);
            if (!userData || userData.role !== 'admin')
                return res.status(403).json({ error: 'Accès refusé' });
        }
        catch {
            return res.status(502).json({ error: 'Service indisponible' });
        }
        const { ip, reason } = req.body;
        if (!ip || typeof ip !== 'string')
            return res.status(400).json({ error: 'IP requise' });
        try {
            await runtime_1.runtime.redis.banIP(ip.trim(), reason || 'Banni par un administrateur', userId);
            logger_1.logger.info(`IP bannie: ${ip} par ${userId} — raison: ${reason || 'non spécifiée'}`);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur ban IP:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    app.delete('/api/admin/gateway/ban-ip/:ip', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        try {
            const userRes = await fetch(`${(0, helpers_1.getServiceUrl)('users', env_1.USERS_URL)}/users/${userId}`, {
                headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
            });
            const userData = await (0, helpers_1.safeJson)(userRes);
            if (!userData || userData.role !== 'admin')
                return res.status(403).json({ error: 'Accès refusé' });
        }
        catch {
            return res.status(502).json({ error: 'Service indisponible' });
        }
        const ip = decodeURIComponent(req.params.ip);
        try {
            await runtime_1.runtime.redis.unbanIP(ip);
            logger_1.logger.info(`IP débannie: ${ip} par ${userId}`);
            res.json({ success: true });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur unban IP:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** GET /api/admin/monitoring — current status + last 24h stats */
    app.get('/api/admin/monitoring', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const [latestServices, userHistory, peakUsers] = await Promise.all([
                monitoring_db_1.monitoringDB.getLatestServiceStatus(),
                monitoring_db_1.monitoringDB.getUserStatsHistory(24),
                monitoring_db_1.monitoringDB.getPeakUsers(24),
            ]);
            res.json({
                services: latestServices,
                connectedUsers: {
                    current: connections_1.connectedClients.size,
                    peak24h: peakUsers,
                    history: userHistory,
                },
                checkedAt: new Date(),
            });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur /api/admin/monitoring:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** GET /api/admin/monitoring/service/:name?hours=24 — history for a specific service */
    app.get('/api/admin/monitoring/service/:name', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const hours = Math.min(parseInt(String(req.query.hours) || '24'), 168); // max 7 days
            const history = await monitoring_db_1.monitoringDB.getServiceHistory(req.params.name, hours);
            res.json({ service: req.params.name, hours, history });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur /api/admin/monitoring/service:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** GET /api/admin/monitoring/users/chart?period=30min|10min|hour|day|month */
    app.get('/api/admin/monitoring/users/chart', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const period = req.query.period;
        if (!['30min', '10min', 'hour', 'day', 'month'].includes(period)) {
            return res.status(400).json({ error: 'period must be 30min, 10min, hour, day or month' });
        }
        try {
            const data = await monitoring_db_1.monitoringDB.getUserStatsAggregated(period);
            res.json({ period, data });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur /api/admin/monitoring/users/chart:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    // ── Public status endpoint ───────────────────────────────────────────────────
    /** GET /api/status — public: current service statuses + active incidents + 90-day uptime */
    app.get('/api/status', async (_req, res) => {
        try {
            const [latestStatuses, activeIncidents] = await Promise.all([
                monitoring_db_1.monitoringDB.getLatestServiceStatus(),
                monitoring_db_1.monitoringDB.getIncidents(false),
            ]);
            // Fetch 90-day uptime per service
            const serviceNames = [...new Set(latestStatuses.map((s) => s.service))];
            const uptimeByService = {};
            await Promise.all(serviceNames.map(async (name) => {
                uptimeByService[name] = await monitoring_db_1.monitoringDB.getServiceUptimeDaily(name, 90);
            }));
            // Public-safe subset of service instances (no metrics, no internal endpoints)
            const publicInstances = service_registry_1.serviceRegistry.getAll().map((inst) => ({
                serviceType: inst.serviceType,
                domain: inst.domain,
                location: inst.location,
                healthy: inst.healthy,
                lastHeartbeat: inst.lastHeartbeat,
                score: service_registry_1.serviceRegistry.computeScore(inst),
            }));
            res.json({ services: latestStatuses, incidents: activeIncidents, uptime: uptimeByService, instances: publicInstances });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur /api/status:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    // ── Admin: incident CRUD ──────────────────────────────────────────────────────
    /** GET /api/admin/status/incidents?includeResolved=true */
    app.get('/api/admin/status/incidents', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const includeResolved = req.query.includeResolved === 'true';
            const incidents = await monitoring_db_1.monitoringDB.getIncidents(includeResolved);
            res.json({ incidents });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur GET /api/admin/status/incidents:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** POST /api/admin/status/incidents */
    app.post('/api/admin/status/incidents', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const { title, message, severity, services, status } = req.body;
            if (!title || !severity)
                return res.status(400).json({ error: 'title et severity requis' });
            const createdBy = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization) ?? undefined;
            const id = await monitoring_db_1.monitoringDB.createIncident({ title, message, severity, services, status, createdBy });
            if (!id)
                return res.status(500).json({ error: 'Erreur création incident' });
            res.status(201).json({ id });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur POST /api/admin/status/incidents:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** PATCH /api/admin/status/incidents/:id */
    app.patch('/api/admin/status/incidents/:id', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id))
                return res.status(400).json({ error: 'ID invalide' });
            const { title, message, severity, services, status } = req.body;
            const ok = await monitoring_db_1.monitoringDB.updateIncident(id, { title, message, severity, services, status });
            if (!ok)
                return res.status(500).json({ error: 'Erreur mise à jour' });
            res.json({ success: true });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur PATCH /api/admin/status/incidents:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    /** DELETE /api/admin/status/incidents/:id */
    app.delete('/api/admin/status/incidents/:id', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id))
                return res.status(400).json({ error: 'ID invalide' });
            const ok = await monitoring_db_1.monitoringDB.deleteIncident(id);
            if (!ok)
                return res.status(500).json({ error: 'Erreur suppression' });
            res.json({ success: true });
        }
        catch (err) {
            logger_1.logger.error({ err: err }, 'Erreur DELETE /api/admin/status/incidents:');
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });
    // ── Admin: service registry management ───────────────────────────────────────
    /** GET /api/admin/services — liste toutes les instances connues (y compris désactivées) */
    app.get('/api/admin/services', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const instances = service_registry_1.serviceRegistry.getAll().map((i) => ({
            ...i,
            score: service_registry_1.serviceRegistry.computeScore(i),
        }));
        res.json({ instances });
    });
    /** GET /api/admin/services/:type — instances d'un type donné (y compris désactivées) */
    app.get('/api/admin/services/:type', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const instances = service_registry_1.serviceRegistry.getInstances(req.params.type, true, true).map((i) => ({
            ...i,
            score: service_registry_1.serviceRegistry.computeScore(i),
        }));
        res.json({ instances });
    });
    /** POST /api/admin/services — ajoute manuellement une instance */
    app.post('/api/admin/services', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const { id, serviceType, endpoint, domain, location } = req.body ?? {};
        const VALID_TYPES = ['users', 'messages', 'friends', 'calls', 'servers', 'bots', 'media'];
        if (!id || !VALID_TYPES.includes(serviceType) || !endpoint || !domain || !location) {
            return res.status(400).json({ error: 'id, serviceType, endpoint, domain, location requis' });
        }
        // Rejeter les endpoints IP
        if (env_1.IP_ENDPOINT_RE.test(String(endpoint))) {
            return res.status(400).json({ error: 'Adresse IP non autorisée — utilisez un nom de domaine' });
        }
        const instance = service_registry_1.serviceRegistry.register({
            id: String(id),
            serviceType: serviceType,
            endpoint: String(endpoint),
            domain: String(domain),
            location: String(location).toUpperCase(),
            metrics: { ramUsage: 0, ramMax: 0, cpuUsage: 0, cpuMax: 100, bandwidthUsage: 0, requestCount20min: 0 },
            enabled: true,
        });
        monitoring_db_1.monitoringDB.upsertServiceInstance({
            id: String(id), serviceType: String(serviceType),
            endpoint: String(endpoint), domain: String(domain),
            location: String(location).toUpperCase(),
        }).catch(() => { });
        // Générer une clé unique pour ce service
        const { rawKey, hash } = (0, service_keys_1.generateServiceKey)();
        service_keys_1.serviceKeyHashes.set(String(id), hash);
        monitoring_db_1.monitoringDB.storeServiceKeyHash(String(id), rawKey).catch(() => { });
        // Ajouter à la whitelist et retirer des blacklists
        service_keys_1.allowedServiceIds.add(String(id));
        service_keys_1.bannedServiceIds.delete(String(id));
        logger_1.logger.info(`Admin: service "${id}" ajouté avec une clé unique`);
        res.status(201).json({ success: true, instance, serviceKey: rawKey });
    });
    /**
     * POST /api/admin/services/:id/restore
     * Restaure une instance dégradée (validation admin ou technicien).
     * Retire le flag degraded → l'instance reprend le trafic normal.
     */
    app.post('/api/admin/services/:id/restore', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const decodedId = decodeURIComponent(req.params.id);
        const ok = service_registry_1.serviceRegistry.restoreInstance(decodedId);
        if (!ok)
            return res.status(404).json({ error: 'Instance introuvable' });
        logger_1.logger.info(`Admin: instance "${decodedId}" restaurée manuellement`);
        res.json({ success: true, message: `Instance "${decodedId}" remise en service` });
    });
    /**
     * GET /api/admin/services/degraded — liste les instances dégradées
     */
    app.get('/api/admin/services/degraded', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const degraded = service_registry_1.serviceRegistry.getDegraded().map((i) => ({
            id: i.id,
            serviceType: i.serviceType,
            endpoint: i.endpoint,
            domain: i.domain,
            degradedAt: i.degradedAt,
            degradedReason: i.degradedReason,
        }));
        res.json({ degraded });
    });
    /**
     * PATCH /api/admin/services/:id — active ou désactive une instance (persiste en DB).
     * Body: { enabled: boolean }
     * Ne bannit pas → le service peut continuer à heartbeater mais ne reçoit plus de trafic.
     */
    app.patch('/api/admin/services/:id', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const decodedId = decodeURIComponent(req.params.id);
        const { enabled } = req.body ?? {};
        if (typeof enabled !== 'boolean') {
            return res.status(400).json({ error: 'Le champ "enabled" (boolean) est requis' });
        }
        const ok = service_registry_1.serviceRegistry.setEnabled(decodedId, enabled);
        if (!ok)
            return res.status(404).json({ error: 'Instance introuvable' });
        // Persister l'état en DB
        monitoring_db_1.monitoringDB.setInstanceEnabled(decodedId, enabled).catch(() => { });
        // Synchroniser la blacklist mémoire
        if (enabled)
            service_keys_1.bannedServiceIds.delete(decodedId);
        else
            service_keys_1.bannedServiceIds.add(decodedId);
        logger_1.logger.info(`Admin: instance "${decodedId}" ${enabled ? 'activée' : 'désactivée'}`);
        res.json({ success: true, enabled });
    });
    /**
     * DELETE /api/admin/services/:id — supprime définitivement une instance.
     * Ban en mémoire (jusqu'au prochain redémarrage du gateway) + suppression DB.
     */
    app.delete('/api/admin/services/:id', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const decodedId = decodeURIComponent(req.params.id);
        const removed = service_registry_1.serviceRegistry.remove(decodedId);
        if (!removed)
            return res.status(404).json({ error: 'Instance introuvable' });
        service_keys_1.bannedServiceIds.add(decodedId);
        service_keys_1.allowedServiceIds.delete(decodedId); // Retirer de la whitelist → plus jamais de ré-enregistrement
        logger_1.logger.info(`ServiceRegistry: instance "${decodedId}" supprimée et bannie par un admin`);
        monitoring_db_1.monitoringDB.removeServiceInstance(decodedId).catch(() => { });
        res.json({ success: true });
    });
    /**
     * POST /api/admin/services/:id/rotate-key
     * Régénère la clé de service pour une instance existante.
     * Retourne la nouvelle clé (affichée une seule fois) — mettre à jour le .env du service.
     */
    app.post('/api/admin/services/:id/rotate-key', async (req, res) => {
        if (!await (0, admin_guard_1.requireAdmin)(req, res))
            return;
        const decodedId = decodeURIComponent(req.params.id);
        if (!service_registry_1.serviceRegistry.getAll().find(i => i.id === decodedId)) {
            return res.status(404).json({ error: 'Instance introuvable' });
        }
        const { rawKey, hash } = (0, service_keys_1.generateServiceKey)();
        service_keys_1.serviceKeyHashes.set(decodedId, hash);
        monitoring_db_1.monitoringDB.storeServiceKeyHash(decodedId, rawKey).catch(() => { });
        logger_1.logger.info(`Admin: clé régénérée pour le service "${decodedId}"`);
        res.json({ success: true, serviceKey: rawKey });
    });
    // Proxy helpdesk → users service (must be before /api/admin catch-all)
    app.all('/api/helpdesk/*', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('users', env_1.USERS_URL), req, res, env_1.USERS_URL));
    app.all('/api/helpdesk', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('users', env_1.USERS_URL), req, res, env_1.USERS_URL));
    app.all('/api/admin/*', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('users', env_1.USERS_URL), req, res, env_1.USERS_URL));
    app.all('/api/admin', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('users', env_1.USERS_URL), req, res, env_1.USERS_URL));
}
//# sourceMappingURL=admin.routes.js.map