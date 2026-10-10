// ==========================================
// ALFYCHAT — HTTP Proxy Functions
// ==========================================

import express from 'express';
import { extractUserIdFromJWT, safeJson, apiPath, clientIpHeaders, setSafeFileHeaders } from './helpers';
import { allowedOrigins, IS_PRODUCTION } from '../config/env';
import { logger } from '../utils/logger';
import { serviceRegistry, type ServiceType } from '../utils/service-registry';
import { deriveNodeSecret } from '../utils/node-endpoint';

/** Un node ou un service qui ne répond pas ne doit pas immobiliser la requête. */
const NODE_TIMEOUT_MS = 20_000;
const UPLOAD_TIMEOUT_MS = 120_000;

/** Plafond de taille des corps bruts relayés (upload). Au-delà : 413. */
const MAX_RAW_BODY = 64 * 1024 * 1024; // 64 Mo

/**
 * Lit le corps brut d'une requête avec un plafond de taille et une gestion
 * explicite des erreurs de flux. Sans cela, un upload interrompu laissait une
 * promesse pendante, et un `'error'` non écouté sur `req` faisait tomber le
 * process.
 */
function readRawBody(req: express.Request, limit = MAX_RAW_BODY): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] || 0);
    if (Number.isFinite(declared) && declared > limit) {
      reject(Object.assign(new Error('PAYLOAD_TOO_LARGE'), { statusCode: 413 }));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    const cleanup = () => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAborted);
    };
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        cleanup();
        req.pause();
        reject(Object.assign(new Error('PAYLOAD_TOO_LARGE'), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => { cleanup(); resolve(Buffer.concat(chunks)); };
    const onError = (err: Error) => { cleanup(); reject(err); };
    const onAborted = () => { cleanup(); reject(new Error('CLIENT_ABORTED')); };
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);
  });
}

/** Traduit une erreur de lecture de corps en réponse HTTP. */
function sendBodyError(res: express.Response, err: any, context: string): void {
  if (err?.statusCode === 413) {
    if (!res.headersSent) res.status(413).json({ error: 'Fichier trop volumineux' });
    return;
  }
  if (err?.message === 'CLIENT_ABORTED') return; // le client est parti, rien à renvoyer
  logger.error({ err }, context);
  if (!res.headersSent) res.status(502).json({ error: 'Service indisponible' });
}

/** Proxy JSON HTTP request to a microservice with failover to other healthy instances */
export async function proxyRequest(
  targetUrl: string,
  req: express.Request,
  res: express.Response,
  fallbackUrl?: string,
  serviceType?: ServiceType,
) {
  const SKIP_USERID_INJECT = ['/friends/request'];
  const userId = extractUserIdFromJWT(req.headers.authorization);
  const servicePath = apiPath(req).replace(/^\/api/, '');
  const skipInject = SKIP_USERID_INJECT.some(path => servicePath.toLowerCase().startsWith(path));
  let bodyToSend = req.body;
  if (req.method !== 'GET' && req.method !== 'HEAD' && !skipInject && bodyToSend && typeof bodyToSend === 'object' && !Array.isArray(bodyToSend)) {
    // Le `userId` du corps est TOUJOURS celui du jeton : sans jeton, il est
    // retiré (il passait auparavant tel que fourni par le client). `ownerId`
    // n'est jamais transmis : aucun service ne doit le lire dans le corps.
    const { userId: _clientUserId, ownerId: _clientOwnerId, ...rest } = bodyToSend as Record<string, unknown>;
    bodyToSend = userId ? { ...rest, userId } : rest;
  }

  const doFetch = async (baseUrl: string) => {
    const url = `${baseUrl}${servicePath}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
      return await fetch(url, {
        method: req.method,
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          ...(userId && { 'X-User-Id': userId }),
          ...clientIpHeaders(req),
          ...(req.headers['user-agent'] && { 'user-agent': String(req.headers['user-agent']).slice(0, 512) }),
        },
        ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  };

  const sendResponse = async (response: Response) => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await safeJson(response);
      res.status(response.status).json(data ?? { error: 'Réponse vide' });
    } else {
      const text = await response.text();
      if (!text) {
        res.status(response.status).json({ success: response.ok });
      } else {
        logger.error({ err: text }, `Service ${targetUrl} retourne du non-JSON:`);
        res.status(response.status).json({ error: 'Service non disponible' });
      }
    }
  };

  // Essaye une URL — retourne la Response ou lève une exception pour 5XX
  const tryUrl = async (baseUrl: string): Promise<Response> => {
    const response = await doFetch(baseUrl);
    if (response.status >= 500) {
      throw Object.assign(new Error(`${response.status}`), { statusCode: response.status, response });
    }
    return response;
  };

  // Construire la liste des URLs à essayer : primaire + autres instances du registry
  if (!targetUrl) {
    logger.error(`[Proxy] Aucune instance LB disponible pour ${serviceType ?? req.originalUrl}`);
    res.status(503).json({ error: 'Service indisponible — aucune instance active' });
    return;
  }
  // Le basculement ne concerne que les méthodes idempotentes. Rejouer un POST
  // après un timeout réseau créait des doublons : le service a très bien pu
  // committer avant que la réponse ne se perde (message envoyé deux fois,
  // adhésion comptée deux fois…).
  const isIdempotent = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';

  const urlsToTry: string[] = [targetUrl];
  if (serviceType && isIdempotent) {
    const others = serviceRegistry.getInstances(serviceType)
      .filter((i) => i.endpoint !== targetUrl && !i.degraded)
      .sort((a, b) => serviceRegistry.computeScore(b) - serviceRegistry.computeScore(a))
      .map((i) => i.endpoint);
    urlsToTry.push(...others);
  }
  // En production, le LB est la seule source — pas de fallback .env.
  if (!IS_PRODUCTION && fallbackUrl && isIdempotent && !urlsToTry.includes(fallbackUrl)) {
    urlsToTry.push(fallbackUrl);
  }

  // Dédupliquer
  const seen = new Set<string>();
  const uniqueUrls = urlsToTry.filter((u) => { if (seen.has(u)) return false; seen.add(u); return true; });

  let lastError: any;
  for (const baseUrl of uniqueUrls) {
    try {
      const response = await tryUrl(baseUrl);
      return sendResponse(response);
    } catch (err: any) {
      lastError = err;
      if (err?.statusCode >= 500) {
        // 5XX → marquer dégradé si dans le registry et essayer le suivant
        const inst = serviceRegistry.getAll().find((i) => i.endpoint === baseUrl);
        if (inst && serviceType) {
          serviceRegistry.markDegraded(inst.id, `HTTP ${err.statusCode} sur proxyRequest`);
          logger.warn(`[Proxy] Instance ${inst.id} dégradée (${err.statusCode}), bascule vers suivant…`);
        } else {
          logger.warn(`[Proxy] ${baseUrl} → ${err.statusCode}, essai suivant…`);
        }
      } else {
        // Erreur réseau / timeout → essayer le suivant
        logger.warn(`[Proxy] Erreur réseau ${baseUrl}: ${err?.message}, essai suivant…`);
      }
    }
  }

  logger.error({ err: lastError }, '[Proxy] Tous les endpoints épuisés');
  res.status(502).json({ error: 'Service indisponible' });
}

/** Proxy JSON toward a self-hosted server-node (binary passthrough for images) */
export async function proxyToNode(
  nodeEndpoint: string,
  nodePath: string,
  req: express.Request,
  res: express.Response,
  serverId: string,
) {
  try {
    const url = `${nodeEndpoint}${nodePath}`;
    const userId = extractUserIdFromJWT(req.headers.authorization);
    let bodyToSend = req.body;
    if (userId && req.method !== 'GET' && req.method !== 'HEAD') {
      bodyToSend = { ...req.body, userId };
    }

    // Le node vérifie son propre JWT_SECRET local — jamais le même que le token de
    // session du client. On ne transmet donc pas l'Authorization du client (le node la
    // rejetterait avec 401 sans jamais retomber sur le fallback x-user-id/x-internal-secret) :
    // le gateway a déjà authentifié l'utilisateur, on le prouve au node via un secret
    // DÉRIVÉ du secret interne pour ce serveur précis. Le secret maître ne quitte
    // jamais le gateway : un node compromis n'obtient rien sur les autres services.
    const response = await fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        'x-internal-secret': deriveNodeSecret(serverId),
        ...(userId && { 'X-User-Id': userId }),
      },
      ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
      signal: AbortSignal.timeout(NODE_TIMEOUT_MS),
    });

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      res.status(response.status).json(data);
    } else if (contentType && (contentType.startsWith('image/') || contentType.startsWith('video/') || contentType.startsWith('audio/') || contentType.startsWith('application/octet-stream') || contentType.startsWith('application/pdf'))) {
      const buffer = Buffer.from(await response.arrayBuffer());
      // Contenu fourni par un node tiers : jamais rendu tel quel (SVG, etc.).
      setSafeFileHeaders(res, contentType);
      const cacheControl = response.headers.get('cache-control');
      if (cacheControl) res.setHeader('Cache-Control', cacheControl);
      res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      res.status(response.status).send(buffer);
    } else {
      res.status(response.status).json({ error: 'Node non disponible' });
    }
  } catch (error) {
    logger.error({ err: error }, 'Erreur proxy node:');
    res.status(502).json({ error: 'Server node indisponible' });
  }
}

/** Proxy multipart/form-data to a server-node (file uploads) */
export async function proxyToNodeMultipart(
  nodeEndpoint: string,
  nodePath: string,
  req: express.Request,
  res: express.Response,
  serverId: string,
) {
  const url = `${nodeEndpoint}${nodePath}`;
  const userId = extractUserIdFromJWT(req.headers.authorization);
  const separator = url.includes('?') ? '&' : '?';
  // `senderId` en query est ignoré par le node (il lit req.user) mais conservé
  // pour compatibilité avec les nodes non encore mis à jour.
  const finalUrl = userId ? `${url}${separator}senderId=${encodeURIComponent(userId)}` : url;

  let body: Buffer;
  try {
    body = await readRawBody(req);
  } catch (err) {
    return sendBodyError(res, err, 'Erreur lecture upload node multipart:');
  }

  try {
    // Comme dans proxyToNode : le node ne peut pas vérifier le JWT de session du
    // client (secret local différent) — on prouve l'identité au node via le secret
    // DÉRIVÉ pour ce serveur + X-User-Id.
    const headers: Record<string, string> = { 'x-internal-secret': deriveNodeSecret(serverId) };
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
    if (userId) headers['x-user-id'] = userId;

    const response = await fetch(finalUrl, {
      method: req.method,
      headers,
      body,
      signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
    });
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      res.status(response.status).json(data);
    } else {
      const text = await response.text();
      res.status(response.status).send(text);
    }
  } catch (error) {
    logger.error({ err: error }, 'Erreur proxy node multipart:');
    if (!res.headersSent) res.status(502).json({ error: 'Server node indisponible' });
  }
}

/** Proxy raw multipart to a microservice (fallback upload without node) */
export async function proxyMultipartToService(
  targetUrl: string,
  targetPath: string,
  req: express.Request,
  res: express.Response,
) {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  const sep = targetPath.includes('?') ? '&' : '?';
  const finalUrl = userId
    ? `${targetUrl}${targetPath}${sep}senderId=${encodeURIComponent(userId)}`
    : `${targetUrl}${targetPath}`;

  let body: Buffer;
  try {
    body = await readRawBody(req);
  } catch (err) {
    return sendBodyError(res, err, 'Erreur lecture upload service multipart:');
  }

  try {
    const headers: Record<string, string> = {};
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
    if (req.headers.authorization) headers['authorization'] = req.headers.authorization;

    const response = await fetch(finalUrl, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
    });
    const data = await safeJson(response);
    res.status(response.status).json(data ?? { success: response.ok });
  } catch (err) {
    logger.error({ err: err }, 'Erreur proxy multipart service:');
    if (!res.headersSent) res.status(502).json({ error: 'Service indisponible' });
  }
}

/** Proxy raw multipart/JSON to a media service endpoint */
export async function proxyToMedia(
  targetEndpoint: string,
  mediaPath: string,
  req: express.Request,
  res: express.Response,
) {
  const url = `${targetEndpoint}${mediaPath}`;
  const isWrite = req.method !== 'GET' && req.method !== 'HEAD';

  let body: Buffer | undefined;
  if (isWrite) {
    try {
      body = await readRawBody(req);
    } catch (err) {
      return sendBodyError(res, err, 'Erreur lecture upload média:');
    }
  }

  try {
    const headers: Record<string, string> = {};
    if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
    if (req.headers.authorization) headers['authorization'] = req.headers.authorization;

    const response = await fetch(url, {
      method: req.method,
      headers,
      ...(body ? { body } : {}),
      signal: AbortSignal.timeout(isWrite ? UPLOAD_TIMEOUT_MS : NODE_TIMEOUT_MS),
    });

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await safeJson(response);
      res.status(response.status).json(data ?? { success: response.ok });
    } else if (
      contentType.startsWith('image/') ||
      contentType.startsWith('video/') ||
      contentType.startsWith('audio/') ||
      contentType.startsWith('application/octet-stream')
    ) {
      setSafeFileHeaders(res, contentType);
      res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      const cc = response.headers.get('cache-control');
      if (cc) res.setHeader('Cache-Control', cc);
      const len = response.headers.get('content-length');
      if (len) res.setHeader('Content-Length', len);
      res.status(response.status);
      // Diffusion en flux : ne jamais charger un média entier en mémoire.
      await pipeResponseBody(response, res);
    } else {
      // Tout autre type (text/html, image/svg+xml…) est servi en pièce jointe.
      setSafeFileHeaders(res, contentType);
      res.status(response.status).send(Buffer.from(await response.arrayBuffer()));
    }
  } catch (err) {
    logger.error({ err: err }, 'Erreur proxy média:');
    if (!res.headersSent) res.status(502).json({ error: 'Service média indisponible' });
  }
}

/**
 * Relaie un webhook de paiement SANS toucher au corps : les prestataires signent
 * les octets exacts (Stripe : `stripe-signature`, Tebex : `x-signature`, PayPal :
 * `paypal-*`). L'ancien proxy JSON réencodait le corps et perdait ces en-têtes.
 */
const WEBHOOK_HEADERS = [
  'content-type', 'stripe-signature', 'x-signature',
  'paypal-transmission-id', 'paypal-transmission-time', 'paypal-transmission-sig',
  'paypal-cert-url', 'paypal-auth-algo', 'user-agent',
];

export async function proxyRawWebhook(targetUrl: string, req: express.Request, res: express.Response) {
  let body: Buffer;
  try {
    body = await readRawBody(req, 2 * 1024 * 1024);
  } catch (err) {
    return sendBodyError(res, err, 'Erreur lecture webhook:');
  }
  try {
    const headers: Record<string, string> = {};
    for (const h of WEBHOOK_HEADERS) {
      const v = req.headers[h];
      if (typeof v === 'string') headers[h] = v;
    }
    const response = await fetch(`${targetUrl}${apiPath(req).replace(/^\/api/, '')}`, {
      method: req.method,
      headers,
      ...(req.method !== 'GET' && req.method !== 'HEAD' ? { body } : {}),
      signal: AbortSignal.timeout(NODE_TIMEOUT_MS),
    });
    const text = await response.text();
    res.status(response.status);
    const ct = response.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    res.send(text);
  } catch (err) {
    logger.error({ err }, 'Erreur proxy webhook:');
    if (!res.headersSent) res.status(502).json({ error: 'Service indisponible' });
  }
}

/** Relaie le corps d'une réponse fetch vers la réponse Express, en flux. */
async function pipeResponseBody(response: Response, res: express.Response): Promise<void> {
  if (!response.body) { res.end(); return; }
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(Buffer.from(value))) {
        await new Promise<void>((resolve) => res.once('drain', resolve));
      }
    }
    res.end();
  } catch (err) {
    logger.warn({ err }, 'Flux média interrompu');
    res.destroy();
  }
}
