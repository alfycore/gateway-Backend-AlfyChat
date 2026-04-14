import type { Express } from 'express';
import { runtime } from '../state/runtime';
import { extractUserIdFromJWT, safeJson, getServiceUrl } from './helpers';
import { proxyRequest } from './proxy';
import { invalidateBlockCache } from '../state/block-cache';
import { logger } from '../utils/logger';
import { FRIENDS_URL } from '../config/env';

export function registerFriendsRoutes(app: Express): void {
  // Route spécifique : envoi demande d'ami via HTTP → proxy + notification WS au destinataire
  app.post('/api/friends/request', async (req, res) => {
    const fromUserId = extractUserIdFromJWT(req.headers.authorization);
    try {
      const url = `${FRIENDS_URL}/friends/request`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          ...(fromUserId && { 'X-User-Id': fromUserId }),
        },
        body: JSON.stringify(req.body),
      });
      const data = await response.json() as any;
      res.status(response.status).json(data);
      // Notifier le destinataire via WS si succès
      if (response.ok && data.toUserId) {
        runtime.io.to(`user:${data.toUserId}`).emit('FRIEND_REQUEST', {
          type: 'FRIEND_REQUEST',
          payload: { id: data.id, fromUserId, toUserId: data.toUserId },
          timestamp: new Date(),
        });
      }
    } catch (error) {
      logger.error({ err: error }, 'Erreur envoi demande ami:');
      res.status(502).json({ error: 'Service indisponible' });
    }
  });

  // Route spécifique : acceptation demande d'ami → proxy + notification WS aux deux utilisateurs
  app.post('/api/friends/requests/:requestId/accept', async (req, res) => {
    const acceptorUserId = extractUserIdFromJWT(req.headers.authorization);
    const { requestId } = req.params;
    try {
      const url = `${FRIENDS_URL}/friends/requests/${requestId}/accept`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          ...(acceptorUserId && { 'X-User-Id': acceptorUserId }),
        },
        body: JSON.stringify({ ...req.body, userId: acceptorUserId }),
      });
      const data = await response.json() as any;
      res.status(response.status).json(data);
      if (response.ok) {
        const fromUserId = data.user_id || data.userId;
        const toUserId = data.friend_id || data.friendId;
        if (fromUserId) runtime.io.to(`user:${fromUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
        if (toUserId) runtime.io.to(`user:${toUserId}`).emit('FRIEND_ACCEPT', { type: 'FRIEND_ACCEPT', payload: data, timestamp: new Date() });
      }
    } catch (error) {
      logger.error({ err: error }, 'Erreur accept ami:');
      res.status(502).json({ error: 'Service indisponible' });
    }
  });

  // GET /api/friends → GET /friends/
  app.get('/api/friends', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/`, {
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
      });
      const data = await safeJson(response);
      res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
    } catch (error) {
      logger.error({ err: error }, 'Erreur getFriends:');
      res.status(502).json({ error: 'Service indisponible' });
    }
  });

  // GET /api/friends/requests → GET /friends/requests
  app.get('/api/friends/requests', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/requests`, {
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
      });
      const data = await safeJson(response);
      // Le frontend attend { received: [], sent: [] }
      const normalized = response.ok
        ? (Array.isArray(data) ? { received: data, sent: [] } : (data ?? { received: [], sent: [] }))
        : (data ?? { error: 'Erreur service' });
      res.status(response.status).json(normalized);
    } catch (error) {
      logger.error({ err: error }, 'Erreur getFriendRequests:');
      res.status(502).json({ received: [], sent: [] });
    }
  });

  // GET /api/friends/blocked → GET /friends/blocked
  app.get('/api/friends/blocked', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/blocked`, {
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
      });
      const data = await safeJson(response);
      res.status(response.status).json(response.ok ? (data ?? []) : (data ?? { error: 'Erreur service' }));
    } catch (error) {
      logger.error({ err: error }, 'Erreur getBlockedUsers:');
      res.status(502).json({ error: 'Service indisponible' });
    }
  });

  // DELETE /api/friends/:friendId → DELETE /friends/:friendId
  app.delete('/api/friends/:friendId', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    const { friendId } = req.params;
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/${friendId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
        body: JSON.stringify({ userId }),
      });
      const data = await safeJson(response);
      if (response.ok) {
        runtime.io.to(`user:${userId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId }, timestamp: new Date() });
        runtime.io.to(`user:${friendId}`).emit('FRIEND_REMOVE', { type: 'FRIEND_REMOVE', payload: { friendId: userId }, timestamp: new Date() });
      }
      res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
    } catch (error) {
      logger.error({ err: error }, 'Erreur removeFriend:');
      res.status(502).json({ success: false, error: 'Service indisponible' });
    }
  });

  // POST /api/friends/:targetId/block → POST /friends/:targetId/block
  app.post('/api/friends/:targetId/block', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    const { targetId } = req.params;
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/${targetId}/block`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
        body: JSON.stringify({ userId, blockedUserId: targetId }),
      });
      const data = await safeJson(response);
      if (response.ok) invalidateBlockCache(userId, targetId);
      res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
    } catch (error) {
      logger.error({ err: error }, 'Erreur blockUser:');
      res.status(502).json({ success: false, error: 'Service indisponible' });
    }
  });

  // POST /api/friends/:targetId/unblock → POST /friends/:targetId/unblock
  app.post('/api/friends/:targetId/unblock', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    const { targetId } = req.params;
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/${targetId}/unblock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
        body: JSON.stringify({ userId }),
      });
      const data = await safeJson(response);
      if (response.ok) invalidateBlockCache(userId, targetId);
      res.status(response.status).json({ success: response.ok, ...((data ?? {}) as object) });
    } catch (error) {
      logger.error({ err: error }, 'Erreur unblockUser:');
      res.status(502).json({ success: false, error: 'Service indisponible' });
    }
  });

  // Décline d'une demande d'ami
  app.post('/api/friends/requests/:requestId/decline', async (req, res) => {
    const userId = extractUserIdFromJWT(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Non authentifié' });
    const { requestId } = req.params;
    try {
      const response = await fetch(`${FRIENDS_URL}/friends/requests/${requestId}/decline`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(req.headers.authorization && { authorization: req.headers.authorization }),
          'X-User-Id': userId,
        },
        body: JSON.stringify({ userId }),
      });
      const data = await safeJson(response) ?? {};
      res.status(response.status).json({ success: response.ok, ...(data as object) });
    } catch (error) {
      logger.error({ err: error }, 'Erreur declineFriendRequest:');
      res.status(502).json({ success: false, error: 'Service indisponible' });
    }
  });

  app.all('/api/friends/*', (req, res) => proxyRequest(getServiceUrl('friends', FRIENDS_URL), req, res, FRIENDS_URL));
  app.all('/api/friends', (req, res) => proxyRequest(getServiceUrl('friends', FRIENDS_URL), req, res, FRIENDS_URL));
}
