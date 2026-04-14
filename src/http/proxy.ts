// ==========================================
// ALFYCHAT — HTTP Proxy Functions
// ==========================================

import express from 'express';
import { extractUserIdFromJWT, safeJson } from './helpers';
import { allowedOrigins } from '../config/env';
import { logger } from '../utils/logger';

/** Proxy JSON HTTP request to a microservice with optional fallback URL */
export async function proxyRequest(
  targetUrl: string,
  req: express.Request,
  res: express.Response,
  fallbackUrl?: string,
) {
  const SKIP_USERID_INJECT = ['/friends/request'];
  const userId = extractUserIdFromJWT(req.headers.authorization);
  const skipInject = SKIP_USERID_INJECT.some(path => req.originalUrl.replace(/^\/api/, '').startsWith(path));
  let bodyToSend = req.body;
  if (userId && req.method !== 'GET' && req.method !== 'HEAD' && !skipInject) {
    bodyToSend = { ...req.body, userId, ownerId: userId };
  }

  const doFetch = async (baseUrl: string) => {
    const url = `${baseUrl}${req.originalUrl.replace(/^\/api/, '')}`;
    return fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
      ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
    });
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

  try {
    const response = await doFetch(targetUrl);
    return sendResponse(response);
  } catch (primaryError) {
    if (fallbackUrl && fallbackUrl !== targetUrl) {
      logger.warn(`Proxy vers ${targetUrl} échoué, fallback vers ${fallbackUrl}`);
      try {
        const response = await doFetch(fallbackUrl);
        return sendResponse(response);
      } catch (fallbackError) {
        logger.error({ err: fallbackError }, `Proxy fallback ${fallbackUrl} aussi échoué:`);
      }
    } else {
      logger.error({ err: primaryError }, 'Erreur proxy:');
    }
    res.status(502).json({ error: 'Service indisponible' });
  }
}

/** Proxy JSON toward a self-hosted server-node (binary passthrough for images) */
export async function proxyToNode(
  nodeEndpoint: string,
  nodePath: string,
  req: express.Request,
  res: express.Response,
) {
  try {
    const url = `${nodeEndpoint}${nodePath}`;
    const userId = extractUserIdFromJWT(req.headers.authorization);
    let bodyToSend = req.body;
    if (userId && req.method !== 'GET' && req.method !== 'HEAD') {
      bodyToSend = { ...req.body, userId, ownerId: userId };
    }

    const response = await fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...(req.headers.authorization && { authorization: req.headers.authorization }),
        ...(userId && { 'X-User-Id': userId }),
      },
      ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
    });

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      res.status(response.status).json(data);
    } else if (contentType && (contentType.startsWith('image/') || contentType.startsWith('video/') || contentType.startsWith('audio/') || contentType.startsWith('application/octet-stream') || contentType.startsWith('application/pdf'))) {
      const buffer = Buffer.from(await response.arrayBuffer());
      res.setHeader('Content-Type', contentType);
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
) {
  try {
    const url = `${nodeEndpoint}${nodePath}`;
    const userId = extractUserIdFromJWT(req.headers.authorization);
    const separator = url.includes('?') ? '&' : '?';
    const finalUrl = userId ? `${url}${separator}senderId=${userId}` : url;

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;

        const response = await fetch(finalUrl, { method: req.method, headers, body });
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
        res.status(502).json({ error: 'Server node indisponible' });
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Erreur proxy node multipart:');
    res.status(502).json({ error: 'Server node indisponible' });
  }
}

/** Proxy raw multipart to a microservice (fallback upload without node) */
export async function proxyMultipartToService(
  targetUrl: string,
  targetPath: string,
  req: express.Request,
  res: express.Response,
) {
  try {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    const sep = targetPath.includes('?') ? '&' : '?';
    const finalUrl = userId ? `${targetUrl}${targetPath}${sep}senderId=${userId}` : `${targetUrl}${targetPath}`;

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;

        const response = await fetch(finalUrl, { method: 'POST', headers, body });
        const data = await response.json() as any;
        res.status(response.status).json(data);
      } catch (err) {
        logger.error({ err: err }, 'Erreur proxy multipart service:');
        res.status(502).json({ error: 'Service indisponible' });
      }
    });
  } catch (err) {
    logger.error({ err: err }, 'Erreur proxy multipart service:');
    res.status(502).json({ error: 'Service indisponible' });
  }
}

/** Proxy raw multipart/JSON to a media service endpoint */
export async function proxyToMedia(
  targetEndpoint: string,
  mediaPath: string,
  req: express.Request,
  res: express.Response,
) {
  try {
    const url = `${targetEndpoint}${mediaPath}`;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);
        const headers: Record<string, string> = {};
        if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'] as string;
        if (req.headers.authorization) headers['authorization'] = req.headers.authorization;
        if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'] as string;

        const response = await fetch(url, {
          method: req.method,
          headers,
          ...(req.method !== 'GET' && req.method !== 'HEAD' && { body }),
        });

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          res.status(response.status).json(data);
        } else if (
          contentType.startsWith('image/') ||
          contentType.startsWith('video/') ||
          contentType.startsWith('audio/') ||
          contentType.startsWith('application/octet-stream')
        ) {
          const buffer = Buffer.from(await response.arrayBuffer());
          res.setHeader('Content-Type', contentType);
          res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || 'http://localhost:4000');
          res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
          const cc = response.headers.get('cache-control');
          if (cc) res.setHeader('Cache-Control', cc);
          res.status(response.status).send(buffer);
        } else {
          res.status(response.status).send(await response.text());
        }
      } catch (err) {
        logger.error({ err: err }, 'Erreur proxy média:');
        res.status(502).json({ error: 'Service média indisponible' });
      }
    });
  } catch (err) {
    logger.error({ err: err }, 'Erreur proxy média:');
    res.status(502).json({ error: 'Service média indisponible' });
  }
}
