"use strict";
// ==========================================
// ALFYCHAT — HTTP Proxy Functions
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.proxyRequest = proxyRequest;
exports.proxyToNode = proxyToNode;
exports.proxyToNodeMultipart = proxyToNodeMultipart;
exports.proxyMultipartToService = proxyMultipartToService;
exports.proxyToMedia = proxyToMedia;
const helpers_1 = require("./helpers");
const env_1 = require("../config/env");
const logger_1 = require("../utils/logger");
const service_registry_1 = require("../utils/service-registry");
/** Proxy JSON HTTP request to a microservice with failover to other healthy instances */
async function proxyRequest(targetUrl, req, res, fallbackUrl, serviceType) {
    const SKIP_USERID_INJECT = ['/friends/request'];
    const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
    const skipInject = SKIP_USERID_INJECT.some(path => req.originalUrl.replace(/^\/api/, '').startsWith(path));
    let bodyToSend = req.body;
    if (userId && req.method !== 'GET' && req.method !== 'HEAD' && !skipInject) {
        bodyToSend = { ...req.body, userId, ownerId: userId };
    }
    const doFetch = async (baseUrl) => {
        const url = `${baseUrl}${req.originalUrl.replace(/^\/api/, '')}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15_000);
        try {
            return await fetch(url, {
                method: req.method,
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    ...(userId && { 'X-User-Id': userId }),
                },
                ...(req.method !== 'GET' && req.method !== 'HEAD' && { body: JSON.stringify(bodyToSend) }),
                signal: controller.signal,
            });
        }
        finally {
            clearTimeout(timer);
        }
    };
    const sendResponse = async (response) => {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await (0, helpers_1.safeJson)(response);
            res.status(response.status).json(data ?? { error: 'Réponse vide' });
        }
        else {
            const text = await response.text();
            if (!text) {
                res.status(response.status).json({ success: response.ok });
            }
            else {
                logger_1.logger.error({ err: text }, `Service ${targetUrl} retourne du non-JSON:`);
                res.status(response.status).json({ error: 'Service non disponible' });
            }
        }
    };
    // Essaye une URL — retourne la Response ou lève une exception pour 5XX
    const tryUrl = async (baseUrl) => {
        const response = await doFetch(baseUrl);
        if (response.status >= 500) {
            throw Object.assign(new Error(`${response.status}`), { statusCode: response.status, response });
        }
        return response;
    };
    // Construire la liste des URLs à essayer : primaire + autres instances du registry
    const urlsToTry = [targetUrl];
    if (serviceType) {
        const others = service_registry_1.serviceRegistry.getInstances(serviceType)
            .filter((i) => i.endpoint !== targetUrl && !i.degraded)
            .sort((a, b) => service_registry_1.serviceRegistry.computeScore(b) - service_registry_1.serviceRegistry.computeScore(a))
            .map((i) => i.endpoint);
        urlsToTry.push(...others);
    }
    if (fallbackUrl && !urlsToTry.includes(fallbackUrl)) {
        urlsToTry.push(fallbackUrl);
    }
    // Dédupliquer
    const seen = new Set();
    const uniqueUrls = urlsToTry.filter((u) => { if (seen.has(u))
        return false; seen.add(u); return true; });
    let lastError;
    for (const baseUrl of uniqueUrls) {
        try {
            const response = await tryUrl(baseUrl);
            return sendResponse(response);
        }
        catch (err) {
            lastError = err;
            if (err?.statusCode >= 500) {
                // 5XX → marquer dégradé si dans le registry et essayer le suivant
                const inst = service_registry_1.serviceRegistry.getAll().find((i) => i.endpoint === baseUrl);
                if (inst && serviceType) {
                    service_registry_1.serviceRegistry.markDegraded(inst.id, `HTTP ${err.statusCode} sur proxyRequest`);
                    logger_1.logger.warn(`[Proxy] Instance ${inst.id} dégradée (${err.statusCode}), bascule vers suivant…`);
                }
                else {
                    logger_1.logger.warn(`[Proxy] ${baseUrl} → ${err.statusCode}, essai suivant…`);
                }
            }
            else {
                // Erreur réseau / timeout → essayer le suivant
                logger_1.logger.warn(`[Proxy] Erreur réseau ${baseUrl}: ${err?.message}, essai suivant…`);
            }
        }
    }
    logger_1.logger.error({ err: lastError }, '[Proxy] Tous les endpoints épuisés');
    res.status(502).json({ error: 'Service indisponible' });
}
/** Proxy JSON toward a self-hosted server-node (binary passthrough for images) */
async function proxyToNode(nodeEndpoint, nodePath, req, res) {
    try {
        const url = `${nodeEndpoint}${nodePath}`;
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
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
        }
        else if (contentType && (contentType.startsWith('image/') || contentType.startsWith('video/') || contentType.startsWith('audio/') || contentType.startsWith('application/octet-stream') || contentType.startsWith('application/pdf'))) {
            const buffer = Buffer.from(await response.arrayBuffer());
            res.setHeader('Content-Type', contentType);
            const cacheControl = response.headers.get('cache-control');
            if (cacheControl)
                res.setHeader('Cache-Control', cacheControl);
            res.setHeader('Access-Control-Allow-Origin', env_1.allowedOrigins[0] || 'http://localhost:4000');
            res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
            res.status(response.status).send(buffer);
        }
        else {
            res.status(response.status).json({ error: 'Node non disponible' });
        }
    }
    catch (error) {
        logger_1.logger.error({ err: error }, 'Erreur proxy node:');
        res.status(502).json({ error: 'Server node indisponible' });
    }
}
/** Proxy multipart/form-data to a server-node (file uploads) */
async function proxyToNodeMultipart(nodeEndpoint, nodePath, req, res) {
    try {
        const url = `${nodeEndpoint}${nodePath}`;
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        const separator = url.includes('?') ? '&' : '?';
        const finalUrl = userId ? `${url}${separator}senderId=${userId}` : url;
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', async () => {
            try {
                const body = Buffer.concat(chunks);
                const headers = {};
                if (req.headers['content-type'])
                    headers['content-type'] = req.headers['content-type'];
                if (req.headers.authorization)
                    headers['authorization'] = req.headers.authorization;
                if (req.headers['content-length'])
                    headers['content-length'] = req.headers['content-length'];
                const response = await fetch(finalUrl, { method: req.method, headers, body });
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const data = await response.json();
                    res.status(response.status).json(data);
                }
                else {
                    const text = await response.text();
                    res.status(response.status).send(text);
                }
            }
            catch (error) {
                logger_1.logger.error({ err: error }, 'Erreur proxy node multipart:');
                res.status(502).json({ error: 'Server node indisponible' });
            }
        });
    }
    catch (error) {
        logger_1.logger.error({ err: error }, 'Erreur proxy node multipart:');
        res.status(502).json({ error: 'Server node indisponible' });
    }
}
/** Proxy raw multipart to a microservice (fallback upload without node) */
async function proxyMultipartToService(targetUrl, targetPath, req, res) {
    try {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        const sep = targetPath.includes('?') ? '&' : '?';
        const finalUrl = userId ? `${targetUrl}${targetPath}${sep}senderId=${userId}` : `${targetUrl}${targetPath}`;
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', async () => {
            try {
                const body = Buffer.concat(chunks);
                const headers = {};
                if (req.headers['content-type'])
                    headers['content-type'] = req.headers['content-type'];
                if (req.headers['content-length'])
                    headers['content-length'] = req.headers['content-length'];
                if (req.headers.authorization)
                    headers['authorization'] = req.headers.authorization;
                const response = await fetch(finalUrl, { method: 'POST', headers, body });
                const data = await response.json();
                res.status(response.status).json(data);
            }
            catch (err) {
                logger_1.logger.error({ err: err }, 'Erreur proxy multipart service:');
                res.status(502).json({ error: 'Service indisponible' });
            }
        });
    }
    catch (err) {
        logger_1.logger.error({ err: err }, 'Erreur proxy multipart service:');
        res.status(502).json({ error: 'Service indisponible' });
    }
}
/** Proxy raw multipart/JSON to a media service endpoint */
async function proxyToMedia(targetEndpoint, mediaPath, req, res) {
    try {
        const url = `${targetEndpoint}${mediaPath}`;
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', async () => {
            try {
                const body = Buffer.concat(chunks);
                const headers = {};
                if (req.headers['content-type'])
                    headers['content-type'] = req.headers['content-type'];
                if (req.headers.authorization)
                    headers['authorization'] = req.headers.authorization;
                if (req.headers['content-length'])
                    headers['content-length'] = req.headers['content-length'];
                const response = await fetch(url, {
                    method: req.method,
                    headers,
                    ...(req.method !== 'GET' && req.method !== 'HEAD' && { body }),
                });
                const contentType = response.headers.get('content-type') || '';
                if (contentType.includes('application/json')) {
                    const data = await response.json();
                    res.status(response.status).json(data);
                }
                else if (contentType.startsWith('image/') ||
                    contentType.startsWith('video/') ||
                    contentType.startsWith('audio/') ||
                    contentType.startsWith('application/octet-stream')) {
                    const buffer = Buffer.from(await response.arrayBuffer());
                    res.setHeader('Content-Type', contentType);
                    res.setHeader('Access-Control-Allow-Origin', env_1.allowedOrigins[0] || 'http://localhost:4000');
                    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
                    const cc = response.headers.get('cache-control');
                    if (cc)
                        res.setHeader('Cache-Control', cc);
                    res.status(response.status).send(buffer);
                }
                else {
                    res.status(response.status).send(await response.text());
                }
            }
            catch (err) {
                logger_1.logger.error({ err: err }, 'Erreur proxy média:');
                res.status(502).json({ error: 'Service média indisponible' });
            }
        });
    }
    catch (err) {
        logger_1.logger.error({ err: err }, 'Erreur proxy média:');
        res.status(502).json({ error: 'Service média indisponible' });
    }
}
//# sourceMappingURL=proxy.js.map