"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerStatsRoutes = registerStatsRoutes;
const helpers_1 = require("./helpers");
const connections_1 = require("../state/connections");
const env_1 = require("../config/env");
const CACHE_TTL = 60_000; // 1 min
let cache = null;
function registerStatsRoutes(app) {
    /**
     * GET /api/stats
     * Retourne les statistiques publiques agrégées de la plateforme.
     * Pas d'authentification requise.
     */
    app.get('/api/stats', async (_req, res) => {
        res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=120');
        if (cache && Date.now() - cache.ts < CACHE_TTL) {
            return res.json(cache.data);
        }
        const headers = { 'x-internal-secret': env_1.INTERNAL_SECRET, 'Content-Type': 'application/json' };
        const [usersRes, serversRes] = await Promise.allSettled([
            fetch(`${(0, helpers_1.getServiceUrl)('users', env_1.USERS_URL)}/internal/stats`, { headers }),
            fetch(`${(0, helpers_1.getServiceUrl)('servers', env_1.SERVERS_URL)}/servers/internal/stats`, { headers }),
        ]);
        const users = usersRes.status === 'fulfilled' && usersRes.value.ok ? await usersRes.value.json() : null;
        const servers = serversRes.status === 'fulfilled' && serversRes.value.ok ? await serversRes.value.json() : null;
        const data = {
            totalUsers: users?.totalUsers ?? null,
            onlineUsers: users?.onlineUsers ?? connections_1.connectedClients.size,
            totalServers: servers?.totalServers ?? null,
            totalMembers: servers?.totalMembers ?? null,
            connectedWS: connections_1.connectedClients.size,
            generatedAt: new Date().toISOString(),
        };
        cache = { data, ts: Date.now() };
        res.json(data);
    });
}
//# sourceMappingURL=stats.routes.js.map