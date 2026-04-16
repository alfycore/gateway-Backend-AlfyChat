import type { Express } from 'express';
import { proxyToMedia } from './proxy';
import { serviceRegistry } from '../utils/service-registry';
import { logger } from '../utils/logger';
import { MEDIA_URL, allowedOrigins } from '../config/env';

export function registerMediaRoutes(app: Express): void {
  // ============ ROUTES MÉDIA — Routage géo-distribué ============
  //
  // Structure d'URL pour les médias :
  //   Upload  : POST /api/media/upload/:type?location=EU
  //   Download: GET  /api/media/:location/:serviceId/:folder/:filename
  //             ex.  GET /api/media/EU/media-eu-1/avatars/user123-abc.webp
  //
  // Si aucune instance n'est enregistrée dans le registre, fallback vers MEDIA_URL.

  // ── Download : GET /api/media/:location/:serviceId/:folder/:filename ──────────
  //   Route spécifique avant le catch-all upload
  app.get('/api/media/:location/:serviceId/:folder/:filename', async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

    const { location, serviceId, folder, filename } = req.params;

    // 1. Chercher l'instance par serviceId dans le registre
    let instance = serviceRegistry.getById(serviceId);

    // 1b. Si l'instance enregistrée est sur localhost, elle est inaccessible depuis le gateway
    //     en environnement distribué/Docker → ignorer et utiliser le fallback distant si disponible.
    const LOCAL_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/;
    if (instance?.isLocal && MEDIA_URL && !LOCAL_RE.test(MEDIA_URL)) {
      logger.warn(`MediaProxy: instance ${serviceId} a un endpoint local (${instance.endpoint}), fallback sur MEDIA_URL distant`);
      instance = undefined;
    }

    // 2. Fallback : chercher une instance saine dans la même région
    if (!instance || !instance.healthy) {
      const regional = serviceRegistry.selectBestByLocation('media', location);
      if (regional) {
        logger.warn(`MediaProxy: instance ${serviceId} introuvable/hors-ligne, fallback sur ${regional.id}`);
        instance = regional;
      }
    }

    const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
    const mediaPath = `/uploads/${folder}/${filename}`;

    try {
      const response = await fetch(`${targetEndpoint}${mediaPath}`);
      if (!response.ok) {
        res.status(response.status).json({ error: 'Fichier non trouvé' });
        return;
      }
      const contentType = response.headers.get('content-type');
      const cacheControl = response.headers.get('cache-control');
      if (contentType) res.setHeader('Content-Type', contentType);
      if (cacheControl) res.setHeader('Cache-Control', cacheControl);
      res.send(Buffer.from(await response.arrayBuffer()));
    } catch (err) {
      logger.error({ err: err }, 'Erreur download média:');
      res.status(502).json({ error: 'Service média indisponible' });
    }
  });

  // ── Upload : POST/PATCH /api/media/upload/* → meilleur serveur par localisation ──
  app.all('/api/media/upload/*', async (req, res) => {
    // Localisation préférée : header X-Media-Location ou query ?location=EU
    const preferredLocation = (req.headers['x-media-location'] as string | undefined)
      ?? (req.query.location as string | undefined);

    const instance = serviceRegistry.selectBestByLocation('media', preferredLocation)
      ?? null;
    const targetEndpoint = instance?.endpoint ?? MEDIA_URL;

    // Réécrire l'URL vers /media/upload/:type (le préfixe /api est retiré)
    const mediaPath = req.originalUrl.replace(/^\/api/, '');
    proxyToMedia(targetEndpoint, mediaPath, req, res);
  });

  // ── Catch-all /api/media/* — redirige vers la meilleure instance ──────────────
  app.all('/api/media/*', async (req, res) => {
    const preferredLocation = (req.headers['x-media-location'] as string | undefined)
      ?? (req.query.location as string | undefined);
    const instance = serviceRegistry.selectBestByLocation('media', preferredLocation) ?? null;
    const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
    const mediaPath = req.originalUrl.replace(/^\/api/, '');
    proxyToMedia(targetEndpoint, mediaPath, req, res);
  });

  // Routes Uploads — proxy des fichiers statiques depuis le service média
  // (compatibilité avec les anciennes URLs /uploads/*)
  app.get('/uploads/*', async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    try {
      // Chercher une instance média quelconque saine
      const instance = serviceRegistry.selectBest('media');
      const targetEndpoint = instance?.endpoint ?? MEDIA_URL;
      const url = `${targetEndpoint}${req.originalUrl}`;
      const response = await fetch(url);

      if (!response.ok) {
        res.status(response.status).json({ error: 'Fichier non trouvé' });
        return;
      }

      const contentType = response.headers.get('content-type');
      const cacheControl = response.headers.get('cache-control');
      if (contentType) res.setHeader('Content-Type', contentType);
      if (cacheControl) res.setHeader('Cache-Control', cacheControl);

      const buffer = Buffer.from(await response.arrayBuffer());
      res.send(buffer);
    } catch (error) {
      logger.error({ err: error }, 'Erreur proxy uploads:');
      res.status(502).json({ error: 'Service média indisponible' });
    }
  });
}
