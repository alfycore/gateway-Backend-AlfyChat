import type { Express } from 'express';
import { getServiceUrl } from './helpers';
import { connectedClients } from '../state/connections';
import { INTERNAL_SECRET, USERS_URL, SERVERS_URL } from '../config/env';

const CACHE_TTL = 60_000; // 1 min
interface StatsData {
  totalUsers: number | null;
  onlineUsers: number;
  totalServers: number | null;
  totalMembers: number | null;
  connectedWS: number;
  generatedAt: string;
}
let cache: { data: StatsData; ts: number } | null = null;

export function registerStatsRoutes(app: Express): void {
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

    const headers = { 'x-internal-secret': INTERNAL_SECRET, 'Content-Type': 'application/json' };

    const [usersRes, serversRes] = await Promise.allSettled([
      fetch(`${getServiceUrl('users', USERS_URL)}/internal/stats`, { headers }),
      fetch(`${getServiceUrl('servers', SERVERS_URL)}/servers/internal/stats`, { headers }),
    ]);

    const users   = usersRes.status   === 'fulfilled' && usersRes.value.ok   ? await usersRes.value.json()   as any : null;
    const servers = serversRes.status === 'fulfilled' && serversRes.value.ok ? await serversRes.value.json() as any : null;

    const data = {
      totalUsers:    users?.totalUsers    ?? null,
      onlineUsers:   users?.onlineUsers   ?? connectedClients.size,
      totalServers:  servers?.totalServers ?? null,
      totalMembers:  servers?.totalMembers ?? null,
      connectedWS:   connectedClients.size,
      generatedAt:   new Date().toISOString(),
    };

    cache = { data, ts: Date.now() };
    res.json(data);
  });
}
