"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerFriendsRoutes = registerFriendsRoutes;
const runtime_1 = require("../state/runtime");
const helpers_1 = require("./helpers");
const proxy_1 = require("./proxy");
const block_cache_1 = require("../state/block-cache");
const logger_1 = require("../utils/logger");
const env_1 = require("../config/env");
function registerFriendsRoutes(app) {
    // Route spécifique : envoi demande d'ami via HTTP → proxy + notification WS au destinataire
    app.post('/api/friends/request', async (req, res) => {
        const fromUserId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        try {
            const url = `${env_1.FRIENDS_URL}/friends/request`;
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    ...(fromUserId && { 'X-User-Id': fromUserId }),
                },
                body: JSON.stringify(req.body),
            });
            const data = await response.json();
            res.status(response.status).json(data);
            // Notifier le destinataire via WS si succès
            if (response.ok && data.toUserId) {
                runtime_1.runtime.io.to(`user:${data.toUserId}`).emit('FRIEND_REQUEST', {
                    type: 'FRIEND_REQUEST',
                    payload: { id: data.id, fromUserId, toUserId: data.toUserId },
                    timestamp: new Date(),
                });
            }
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur envoi demande ami:');
            res.status(502).json({ error: 'Service indisponible' });
        }
    });
    // Route spécifique : acceptation demande d'ami → proxy + notification WS aux deux utilisateurs
    app.post('/api/friends/requests/:requestId/accept', async (req, res) => {
        const acceptorUserId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        const { requestId } = req.params;
        try {
            const url = `${env_1.FRIENDS_URL}/friends/requests/${requestId}/accept`;
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    ...(acceptorUserId && { 'X-User-Id': acceptorUserId }),
                },
                body: JSON.stringify({ ...req.body, userId: acceptorUserId }),
            });
            const data = await response.json();
            res.status(response.status).json(data);
            if (response.ok) {
                const fromUserId = data.user_id || data.userId;
                const toUserId = data.friend_id || data.friendId;
                if (fromUserId)
                    runtime_1.runtime.io.to(`user:${fromUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
                if (toUserId)
                    runtime_1.runtime.io.to(`user:${toUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
            }
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur accept ami:');
            res.status(502).json({ error: 'Service indisponible' });
        }
    });
    // GET /api/friends → GET /friends/
    app.get('/api/friends', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
            });
            const data = await (0, helpers_1.safeJson)(response);
            res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur getFriends:');
            res.status(502).json({ error: 'Service indisponible' });
        }
    });
    // GET /api/friends/requests → GET /friends/requests
    app.get('/api/friends/requests', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/requests`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
            });
            const data = await (0, helpers_1.safeJson)(response);
            // Le frontend attend { received: [], sent: [] }
            const normalized = response.ok
                ? (Array.isArray(data) ? { received: data, sent: [] } : (data ?? { received: [], sent: [] }))
                : (data ?? { error: 'Erreur service' });
            res.status(response.status).json(normalized);
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur getFriendRequests:');
            res.status(502).json({ received: [], sent: [] });
        }
    });
    // GET /api/friends/blocked → GET /friends/blocked
    app.get('/api/friends/blocked', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/blocked`, {
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
            });
            const data = await (0, helpers_1.safeJson)(response);
            res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur getBlockedUsers:');
            res.status(502).json({ error: 'Service indisponible' });
        }
    });
    // DELETE /api/friends/:friendId → DELETE /friends/:friendId
    app.delete('/api/friends/:friendId', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        const { friendId } = req.params;
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/${friendId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
                body: JSON.stringify({ userId }),
            });
            const data = await (0, helpers_1.safeJson)(response);
            if (response.ok) {
                runtime_1.runtime.io.to(`user:${userId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId }, timestamp: new Date() });
                runtime_1.runtime.io.to(`user:${friendId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId: userId }, timestamp: new Date() });
            }
            res.status(response.status).json({ success: response.ok, ...(data ?? {}) });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur removeFriend:');
            res.status(502).json({ success: false, error: 'Service indisponible' });
        }
    });
    // POST /api/friends/:targetId/block → POST /friends/:targetId/block
    app.post('/api/friends/:targetId/block', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        const { targetId } = req.params;
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/${targetId}/block`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
                body: JSON.stringify({ userId, blockedUserId: targetId }),
            });
            const data = await (0, helpers_1.safeJson)(response);
            if (response.ok)
                (0, block_cache_1.invalidateBlockCache)(userId, targetId);
            res.status(response.status).json({ success: response.ok, ...(data ?? {}) });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur blockUser:');
            res.status(502).json({ success: false, error: 'Service indisponible' });
        }
    });
    // POST /api/friends/:targetId/unblock → POST /friends/:targetId/unblock
    app.post('/api/friends/:targetId/unblock', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        const { targetId } = req.params;
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/${targetId}/unblock`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
                body: JSON.stringify({ userId }),
            });
            const data = await (0, helpers_1.safeJson)(response);
            if (response.ok)
                (0, block_cache_1.invalidateBlockCache)(userId, targetId);
            res.status(response.status).json({ success: response.ok, ...(data ?? {}) });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur unblockUser:');
            res.status(502).json({ success: false, error: 'Service indisponible' });
        }
    });
    // Décline d'une demande d'ami
    app.post('/api/friends/requests/:requestId/decline', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId)
            return res.status(401).json({ error: 'Non authentifié' });
        const { requestId } = req.params;
        try {
            const response = await fetch(`${env_1.FRIENDS_URL}/friends/requests/${requestId}/decline`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(req.headers.authorization && { authorization: req.headers.authorization }),
                    'X-User-Id': userId,
                },
                body: JSON.stringify({ userId }),
            });
            const data = await (0, helpers_1.safeJson)(response) ?? {};
            res.status(response.status).json({ success: response.ok, ...data });
        }
        catch (error) {
            logger_1.logger.error({ err: error }, 'Erreur declineFriendRequest:');
            res.status(502).json({ success: false, error: 'Service indisponible' });
        }
    });
    app.all('/api/friends/*', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('friends', env_1.FRIENDS_URL), req, res, env_1.FRIENDS_URL));
    app.all('/api/friends', (req, res) => (0, proxy_1.proxyRequest)((0, helpers_1.getServiceUrl)('friends', env_1.FRIENDS_URL), req, res, env_1.FRIENDS_URL));
}
//# sourceMappingURL=friends.routes.js.map