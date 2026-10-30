"use strict";
// ==========================================
// ALFYCHAT — Endpoints d'amorçage (bootstrap)
// ==========================================
// Le navigateur ouvrait ~40 requêtes pour afficher /channels/me et ~5 de plus
// pour ouvrir une conversation. L'essentiel de ce trafic était de la
// composition : récupérer une liste, puis un profil par élément.
//
// Ces deux endpoints font cette composition CÔTÉ SERVEUR, sur le réseau interne
// (latence ~1 ms au lieu de ~50 ms par aller-retour depuis le client), et
// renvoient une seule réponse complète.
//
// Deux règles non négociables ici :
//   1. On transmet l'Authorization de l'appelant à chaque service — jamais le
//      bypass interne. Chaque service applique donc ses propres contrôles, et
//      l'agrégation n'ouvre aucune nouvelle surface d'autorisation.
//   2. Une brique en échec ne fait pas échouer la page : le champ vaut null et
//      le client retombe sur son chemin habituel pour cette donnée-là.
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerBootstrapRoutes = registerBootstrapRoutes;
const helpers_1 = require("./helpers");
const env_1 = require("../config/env");
const logger_1 = require("../utils/logger");
/** Délai au-delà duquel une brique est abandonnée : la page passe sans elle. */
const PART_TIMEOUT_MS = 8_000;
/**
 * Appelle un service avec l'identité de l'appelant.
 * Retourne `null` sur échec (réseau, 4xx, 5xx, timeout) — jamais d'exception :
 * une brique manquante ne doit pas faire tomber tout l'amorçage.
 */
async function part(req, baseUrl, path) {
    if (!baseUrl)
        return null;
    try {
        const response = await fetch(`${baseUrl}${path}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}),
            },
            signal: AbortSignal.timeout(PART_TIMEOUT_MS),
        });
        if (!response.ok)
            return null;
        return (await response.json());
    }
    catch {
        return null;
    }
}
/** Déballe les réponses encore enveloppées dans `{ success, data }`. */
function unwrap(value) {
    if (value && typeof value === 'object' && 'data' in value) {
        return (value.data ?? null);
    }
    return (value ?? null);
}
/**
 * Recopie le profil du destinataire à la racine de chaque conversation privée.
 *
 * Le service messages renvoie DÉJÀ ces informations dans `participants[]` (il
 * les joint à la table `users` en une requête). Le client les ignorait et
 * réémettait un `GET /api/users/:id` par conversation — 30 requêtes pour des
 * données qu'il avait déjà en main.
 */
function withRecipientProfiles(conversations) {
    if (!Array.isArray(conversations))
        return [];
    return conversations.map((conv) => {
        if (conv.type !== 'dm' || !conv.recipientId)
            return conv;
        const profile = (conv.participants ?? []).find((p) => p?.userId === conv.recipientId);
        if (!profile)
            return conv;
        return {
            ...conv,
            recipientName: profile.displayName || profile.username || conv.name || conv.recipientId,
            recipientAvatar: profile.avatarUrl,
            recipientUsername: profile.username,
            recipientOnline: profile.isOnline === true,
        };
    });
}
function registerBootstrapRoutes(app) {
    /**
     * GET /api/bootstrap/me
     * Tout ce qu'il faut pour peindre le shell, la barre latérale et la page Amis.
     */
    app.get('/api/bootstrap/me', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId) {
            return res.status(401).json({ error: 'Authentification requise' });
        }
        const usersUrl = (0, helpers_1.getServiceUrl)('users', env_1.USERS_URL);
        const messagesUrl = (0, helpers_1.getServiceUrl)('messages', env_1.MESSAGES_URL);
        const friendsUrl = (0, helpers_1.getServiceUrl)('friends', env_1.FRIENDS_URL);
        const serversUrl = (0, helpers_1.getServiceUrl)('servers', env_1.SERVERS_URL);
        const started = Date.now();
        // Toutes les briques en parallèle : la réponse coûte le temps de la plus
        // lente, pas la somme.
        const [user, servers, conversationsRaw, friends, friendRequests, blocked, notifications, notificationSettings, preferences,] = await Promise.all([
            part(req, usersUrl, `/users/${userId}`),
            part(req, serversUrl, `/servers?userId=${encodeURIComponent(userId)}`),
            part(req, messagesUrl, '/conversations'),
            part(req, friendsUrl, '/friends'),
            part(req, friendsUrl, '/friends/requests'),
            part(req, friendsUrl, '/friends/blocked'),
            part(req, messagesUrl, '/notifications'),
            part(req, messagesUrl, '/messages/notifications/settings'),
            part(req, usersUrl, `/users/${userId}/preferences`),
        ]);
        const conversations = withRecipientProfiles(unwrap(conversationsRaw));
        logger_1.logger.info(`bootstrap/me ${userId} — ${conversations.length} conversations en ${Date.now() - started} ms`);
        res.json({
            user: unwrap(user),
            servers: unwrap(servers) ?? [],
            conversations,
            friends: unwrap(friends) ?? [],
            friendRequests: unwrap(friendRequests) ?? { received: [], sent: [] },
            blocked: unwrap(blocked) ?? [],
            notifications: unwrap(notifications) ?? {},
            notificationSettings: unwrap(notificationSettings) ?? {},
            preferences: unwrap(preferences) ?? {},
            fetchedAt: Date.now(),
        });
    });
    /**
     * GET /api/bootstrap/dm/:recipientId
     * Tout ce qu'il faut pour ouvrir une conversation privée.
     *
     * `?limit=` borne la première page de messages (50 par défaut, 100 max).
     */
    app.get('/api/bootstrap/dm/:recipientId', async (req, res) => {
        const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
        if (!userId) {
            return res.status(401).json({ error: 'Authentification requise' });
        }
        const { recipientId } = req.params;
        const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!UUID_RE.test(recipientId)) {
            return res.status(400).json({ error: 'recipientId invalide' });
        }
        const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? '50'), 10) || 50, 1), 100);
        const usersUrl = (0, helpers_1.getServiceUrl)('users', env_1.USERS_URL);
        const messagesUrl = (0, helpers_1.getServiceUrl)('messages', env_1.MESSAGES_URL);
        const friendsUrl = (0, helpers_1.getServiceUrl)('friends', env_1.FRIENDS_URL);
        const started = Date.now();
        const [recipient, blockStatus, keyBundle, messages] = await Promise.all([
            part(req, usersUrl, `/users/${recipientId}`),
            part(req, friendsUrl, `/friends/block-status/${recipientId}`),
            // Consomme une one-time prekey côté serveur : à ne demander que pour une
            // conversation réellement ouverte, pas dans un préchargement de liste.
            part(req, usersUrl, `/users/keys/${recipientId}`),
            part(req, messagesUrl, `/messages?recipientId=${encodeURIComponent(recipientId)}&limit=${limit}`),
        ]);
        logger_1.logger.info(`bootstrap/dm ${userId} → ${recipientId} en ${Date.now() - started} ms`);
        res.json({
            recipient: unwrap(recipient),
            blockStatus: unwrap(blockStatus) ?? { iBlockedThem: false, theyBlockedMe: false },
            keyBundle: unwrap(keyBundle),
            messages: unwrap(messages) ?? [],
            fetchedAt: Date.now(),
        });
    });
}
//# sourceMappingURL=bootstrap.routes.js.map