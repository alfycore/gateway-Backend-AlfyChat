import type { Express } from 'express';
import { proxyToMedia } from './proxy';
import { serviceRegistry } from '../utils/service-registry';
import { logger } from '../utils/logger';
import { MEDIA_URL, allowedOrigins } from '../config/env';

/** Résout l'endpoint d'un service média en ignorant les instances localhost quand MEDIA_URL est distant. */
const LOCAL_HOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/;
function resolveMediaEndpoint(preferredLocation?: string): string {
  const mediaUrlIsDistant = !!MEDIA_URL && !LOCAL_HOST_RE.test(MEDIA_URL);
  // Chercher une instance saine en priorité, sinon n'importe quelle instance connue
  const instance = serviceRegistry.selectBestByLocation('media', preferredLocation)
    ?? serviceRegistry.getAll().find(i => i.serviceType === 'media' && !i.isLocal)
    ?? serviceRegistry.getAll().find(i => i.serviceType === 'media')
    ?? null;
  if (instance && instance.isLocal && mediaUrlIsDistant) {
    logger.warn(`MediaProxy: seule instance locale disponible (${instance.endpoint}), fallback sur MEDIA_URL distant`);
    return MEDIA_URL;
  }
  return instance?.endpoint ?? MEDIA_URL;
}

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

    // Détermine si une instance doit être ignorée car son endpoint localhost
    // est injoignable depuis le gateway en environnement Docker/distribué,
    // c'est-à-dire : l'instance est locale ET MEDIA_URL pointe vers un host distant.
    const LOCAL_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/;
    const mediaUrlIsDistant = !!MEDIA_URL && !LOCAL_RE.test(MEDIA_URL);
    const isUnreachableLocal = (inst: { isLocal: boolean } | undefined): boolean =>
      !!inst?.isLocal && mediaUrlIsDistant;

    // 1. Chercher l'instance par serviceId dans le registre (même si unhealthy — pour les fichiers déjà uploadés, le statut de santé ne doit pas bloquer la récupération)
    let instance = serviceRegistry.getById(serviceId);
    if (isUnreachableLocal(instance)) {
      logger.warn(`MediaProxy: instance ${serviceId} a un endpoint local (${instance!.endpoint}), fallback sur endpoint distant`);
      instance = undefined;
    }

    // 2. Si l'instance n'est pas trouvée du tout, chercher n'importe quelle instance de la même région
    //    (healthy ou non, car un service peut être marqué unhealthy juste pour absence de heartbeat)
    if (!instance) {
      const regional = serviceRegistry.selectBestByLocation('media', location)
        ?? serviceRegistry.getAll().find(i => i.serviceType === 'media' && i.location.toUpperCase() === location.toUpperCase() && !isUnreachableLocal(i))
        ?? serviceRegistry.getAll().find(i => i.serviceType === 'media' && !isUnreachableLocal(i));
      if (regional) {
        logger.warn(`MediaProxy: instance ${serviceId} introuvable, fallback sur ${regional.id}`);
        instance = regional;
      }
    }

    // Si toutes les instances connues sont locales et MEDIA_URL est distant → utiliser MEDIA_URL directement
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

    const targetEndpoint = resolveMediaEndpoint(preferredLocation);

    // Réécrire l'URL vers /media/upload/:type (le préfixe /api est retiré)
    const mediaPath = req.originalUrl.replace(/^\/api/, '');
    proxyToMedia(targetEndpoint, mediaPath, req, res);
  });

  // ── Catch-all /api/media/* — redirige vers la meilleure instance ──────────────
  app.all('/api/media/*', async (req, res) => {
    const preferredLocation = (req.headers['x-media-location'] as string | undefined)
      ?? (req.query.location as string | undefined);
    const targetEndpoint = resolveMediaEndpoint(preferredLocation);
    const mediaPath = req.originalUrl.replace(/^\/api/, '');
    proxyToMedia(targetEndpoint, mediaPath, req, res);
  });

  // Routes Uploads — proxy des fichiers statiques depuis le service média
  // (compatibilité avec les anciennes URLs /uploads/*)
  app.get('/uploads/*', async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    try {
      // Chercher une instance média quelconque saine (exclure les instances locales si MEDIA_URL est distant)
      const rawInstance = serviceRegistry.selectBest('media');
      const targetEndpoint = (rawInstance && rawInstance.isLocal && MEDIA_URL && !LOCAL_HOST_RE.test(MEDIA_URL))
        ? MEDIA_URL
        : (rawInstance?.endpoint ?? MEDIA_URL);
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
