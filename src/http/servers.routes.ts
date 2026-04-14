import type { Express } from 'express';
import { proxyRequest, proxyToNode, proxyToNodeMultipart, proxyMultipartToService } from './proxy';
import { extractUserIdFromJWT, getServiceUrl, rewriteNodePath } from './helpers';
import { forwardToNode } from '../services/forward';
import { connectedNodes } from '../state/connections';
import { logger } from '../utils/logger';
import { SERVERS_URL, allowedOrigins } from '../config/env';

export function registerServersRoutes(app: Express): void {
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
      logger.error({ err: error }, 'Erreur proxy GET /api/servers:');
      res.status(502).json({ error: 'Service indisponible' });
    }
  });
  app.post('/api/servers', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));

  // Routes qui restent TOUJOURS vers le microservice même pour un serverId
  app.all('/api/servers/:serverId/leave', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
  app.all('/api/servers/:serverId/node-token', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
  app.all('/api/servers/:serverId/claim-admin', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
  app.all('/api/servers/:serverId/domain/*', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));

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
        res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
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
      res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
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
    proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL);
  });

  // /api/servers/:serverId (sans sous-chemin) → /server sur le node
  app.all('/api/servers/:serverId', (req, res) => {
    const { serverId } = req.params;
    const node = connectedNodes.get(serverId);

    if (node?.endpoint) {
      proxyToNode(node.endpoint, '/server', req, res);
      return;
    }

    proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL);
  });

  // Fallback
  app.all('/api/servers', (req, res) => proxyRequest(getServiceUrl('servers', SERVERS_URL), req, res, SERVERS_URL));
}
