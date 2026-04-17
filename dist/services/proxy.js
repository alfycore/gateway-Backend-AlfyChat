"use strict";
// ==========================================
// ALFYCHAT - PROXY VERS LES MICROSERVICES
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceProxy = void 0;
const opossum_1 = __importDefault(require("opossum"));
const logger_1 = require("../utils/logger");
const service_registry_1 = require("../utils/service-registry");
const mailer_1 = require("../utils/mailer");
const env_1 = require("../config/env");
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || '';
// Throttle des alertes email : 1 email max par instance toutes les 10 minutes
const _alertThrottle = new Map();
const ALERT_THROTTLE_MS = 10 * 60 * 1000;
// ── Circuit breakers — un par hostname ──────────────────────────────────────
const _breakers = new Map();
function getBreaker(url) {
    let host;
    try {
        host = new URL(url).host;
    }
    catch {
        host = url;
    }
    if (!_breakers.has(host)) {
        const action = (fn) => fn();
        const breaker = new opossum_1.default(action, {
            timeout: 15_000, // 15 s max par appel
            errorThresholdPercentage: 75, // ouvre après 75 % d'erreurs (plus tolérant)
            resetTimeout: 10_000, // demi-ouverture après 10 s (récupère plus vite)
            volumeThreshold: 10, // évalue après 10 requêtes minimum
        });
        breaker.on('open', () => logger_1.logger.warn(`Circuit OUVERT: ${host}`));
        breaker.on('halfOpen', () => logger_1.logger.info(`Circuit HALF-OPEN: ${host}`));
        breaker.on('close', () => logger_1.logger.info(`Circuit FERMÉ: ${host}`));
        _breakers.set(host, breaker);
    }
    return _breakers.get(host);
}
// ── Retry exponentiel (2 tentatives, backoff x2) ────────────────────────────
async function withRetry(fn, retries = 2, delayMs = 300) {
    try {
        return await fn();
    }
    catch (error) {
        if (retries <= 0)
            throw error;
        await new Promise(r => setTimeout(r, delayMs));
        return withRetry(fn, retries - 1, delayMs * 2);
    }
}
// ── Alerte email admin (throttled) ──────────────────────────────────────────
function notifyAdminDegraded(instance, reason) {
    const now = Date.now();
    const last = _alertThrottle.get(instance.id) ?? 0;
    if (now - last < ALERT_THROTTLE_MS)
        return;
    _alertThrottle.set(instance.id, now);
    const subject = `[AlfyChat] ⚠️ Service dégradé : ${instance.id}`;
    const text = [
        `L'instance "${instance.id}" (${instance.serviceType}) a retourné une erreur 5XX.`,
        ``,
        `  Endpoint : ${instance.endpoint}`,
        `  Domaine  : ${instance.domain}`,
        `  Raison   : ${reason}`,
        `  Heure    : ${new Date().toISOString()}`,
        ``,
        `L'instance a été SUSPENDUE automatiquement et ne recevra plus de trafic.`,
        ``,
        `Pour la réactiver, un administrateur ou technicien doit confirmer via :`,
        `  PATCH /api/admin/services/${encodeURIComponent(instance.id)}/restore`,
        ``,
        `— AlfyChat Gateway`,
    ].join('\n');
    (0, mailer_1.sendMail)({ to: env_1.ADMIN_ALERT_EMAILS, subject, text }).catch(() => { });
}
// ── Fetch avec failover multi-instance ──────────────────────────────────────
/**
 * Exécute un fetch HTTP en utilisant l'URL fournie en priorité.
 * Si l'URL retourne une erreur 5XX (ou le circuit est ouvert), tente de basculer
 * sur une autre instance saine du même serviceType dans le registre.
 * L'instance défaillante est marquée dégradée et les admins sont alertés par email.
 */
async function fetchWithFailover(primaryUrl, serviceType, options) {
    const { token, ...fetchOptions } = options || {};
    const doRequest = async (url) => {
        const response = await fetch(url, {
            ...fetchOptions,
            headers: {
                'Content-Type': 'application/json',
                ...(INTERNAL_SECRET ? { 'X-Internal-Secret': INTERNAL_SECRET } : {}),
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...fetchOptions?.headers,
            },
        });
        if (!response.ok) {
            let detail = response.statusText;
            try {
                const b = await response.json();
                detail = JSON.stringify(b);
            }
            catch { }
            const err = new Error(`Service error: ${response.status} ${detail}`);
            err.statusCode = response.status;
            throw err;
        }
        return response.json();
    };
    const tryFetch = async (url) => {
        const breaker = getBreaker(url);
        return await breaker.fire(() => withRetry(doRequest.bind(null, url)));
    };
    // Tentative primaire
    try {
        return await tryFetch(primaryUrl);
    }
    catch (primaryErr) {
        const isPrimary5xx = (primaryErr?.statusCode >= 500) || /Breaker is open|503|502|500/.test(String(primaryErr?.message));
        // Pas un 5XX (ex: 400, 401, 404) → ne pas basculer, propager l'erreur
        if (!isPrimary5xx || !serviceType) {
            logger_1.logger.error({ err: primaryErr }, `Fetch error for ${primaryUrl}`);
            throw primaryErr;
        }
        // Trouver l'instance correspondant à l'URL primaire
        const allInstances = service_registry_1.serviceRegistry.getAll().filter((i) => i.serviceType === serviceType);
        const primaryInstance = allInstances.find((i) => primaryUrl.startsWith(i.endpoint));
        if (primaryInstance) {
            service_registry_1.serviceRegistry.markDegraded(primaryInstance.id, primaryErr.message);
            notifyAdminDegraded(primaryInstance, primaryErr.message);
            logger_1.logger.warn(`[Failover] Instance primaire dégradée: ${primaryInstance.id} — recherche d'un fallback…`);
        }
        // Chercher une autre instance saine du même type (exclut la primaire)
        const fallbacks = service_registry_1.serviceRegistry.getInstances(serviceType).filter((i) => i.id !== primaryInstance?.id && !i.degraded);
        if (fallbacks.length === 0) {
            logger_1.logger.error(`[Failover] Aucun fallback disponible pour ${serviceType}`);
            throw primaryErr;
        }
        // Trier par score et essayer dans l'ordre
        const sorted = fallbacks.sort((a, b) => service_registry_1.serviceRegistry.computeScore(b) - service_registry_1.serviceRegistry.computeScore(a));
        for (const fallback of sorted) {
            // Remplacer la base de l'URL primaire par le endpoint du fallback
            const fallbackUrl = primaryUrl.replace(primaryInstance?.endpoint || primaryUrl.split('/').slice(0, 3).join('/'), fallback.endpoint);
            try {
                logger_1.logger.info(`[Failover] Bascule vers ${fallback.id} (${fallback.endpoint})`);
                const result = await tryFetch(fallbackUrl);
                return result;
            }
            catch (fallbackErr) {
                const isFallback5xx = (fallbackErr?.statusCode >= 500) || /Breaker is open|503|502|500/.test(String(fallbackErr?.message));
                if (isFallback5xx) {
                    service_registry_1.serviceRegistry.markDegraded(fallback.id, fallbackErr.message);
                    notifyAdminDegraded(fallback, fallbackErr.message);
                    logger_1.logger.warn(`[Failover] Fallback ${fallback.id} aussi dégradé, essai suivant…`);
                }
                else {
                    throw fallbackErr;
                }
            }
        }
        logger_1.logger.error(`[Failover] Tous les fallbacks épuisés pour ${serviceType}`);
        throw primaryErr;
    }
}
// Wrapper rétrocompatible pour les appels sans failover (services sans registry)
async function fetchService(url, options) {
    return fetchWithFailover(url, null, options);
}
class ServiceProxy {
    users;
    messages;
    friends;
    calls;
    servers;
    bots;
    constructor(urls) {
        this.users = new UsersProxy(urls.users);
        this.messages = new MessagesProxy(urls.messages);
        this.friends = new FriendsProxy(urls.friends);
        this.calls = new CallsProxy(urls.calls);
        this.servers = new ServersProxy(urls.servers);
        this.bots = new BotsProxy(urls.bots);
    }
}
exports.ServiceProxy = ServiceProxy;
// ============ USERS PROXY ============
class UsersProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getUser(userId) {
        return fetchService(`${this.baseUrl}/users/${userId}`);
    }
    async updateStatus(userId, status, customStatus) {
        return fetchService(`${this.baseUrl}/users/${userId}/status`, {
            method: 'PATCH',
            body: JSON.stringify({ status, ...(customStatus !== undefined && { customStatus }) }),
            headers: { 'x-user-id': userId, 'x-internal-secret': INTERNAL_SECRET },
        });
    }
    async updateLastSeen(userId) {
        try {
            return fetchService(`${this.baseUrl}/users/${userId}/last-seen`, {
                method: 'PATCH',
                headers: { 'x-user-id': userId, 'x-internal-secret': INTERNAL_SECRET },
            });
        }
        catch (error) {
            logger_1.logger.warn(`Impossible de mettre à jour last_seen pour ${userId}`);
            return null;
        }
    }
    async getPreferences(userId, token) {
        return fetchService(`${this.baseUrl}/users/${userId}/preferences`, { token });
    }
    async updateProfile(userId, data, token) {
        return fetchService(`${this.baseUrl}/users/${userId}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
            token,
        });
    }
}
// ============ MESSAGES PROXY ============
class MessagesProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getConversations(userId, token) {
        return fetchWithFailover(`${this.baseUrl}/conversations`, 'messages', {
            headers: { 'x-user-id': userId },
            ...(token ? { token } : {}),
            signal: AbortSignal.timeout(5_000), // 5s max au connect — non bloquant
        });
    }
    async isParticipant(conversationId, userId) {
        try {
            const result = await fetchService(`${this.baseUrl}/conversations/${conversationId}/participants/${userId}/check`, { method: 'GET' });
            return result?.isParticipant === true;
        }
        catch {
            return false;
        }
    }
    async createMessage(data) {
        return fetchWithFailover(`${this.baseUrl}/messages`, 'messages', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async updateMessage(messageId, content, userId) {
        return fetchService(`${this.baseUrl}/messages/${messageId}`, {
            method: 'PATCH',
            body: JSON.stringify({ content }),
            headers: { 'x-user-id': userId },
        });
    }
    async deleteMessage(messageId, userId) {
        return fetchService(`${this.baseUrl}/messages/${messageId}`, {
            method: 'DELETE',
            headers: { 'x-user-id': userId },
        });
    }
    async addReaction(messageId, userId, emoji) {
        return fetchService(`${this.baseUrl}/messages/${messageId}/reactions`, {
            method: 'POST',
            body: JSON.stringify({ emoji }),
            headers: { 'x-user-id': userId },
        });
    }
    async removeReaction(messageId, userId, emoji) {
        return fetchService(`${this.baseUrl}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
            method: 'DELETE',
            headers: { 'x-user-id': userId },
        });
    }
    async createConversation(data) {
        // Le service messages attend 'participantIds', pas 'participants'
        const { participants, createdBy, ...rest } = data;
        return fetchService(`${this.baseUrl}/conversations`, {
            method: 'POST',
            body: JSON.stringify({ ...rest, participantIds: participants }),
        });
    }
    async updateConversation(conversationId, data, token) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
            token,
        });
    }
    async addParticipant(conversationId, userId, token) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
            token,
        });
    }
    async removeParticipant(conversationId, userId, token) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants/${userId}`, {
            method: 'DELETE',
            token,
        });
    }
    async leaveConversation(conversationId, userId, token) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}/leave`, {
            method: 'POST',
            token,
            headers: { 'x-user-id': userId },
        });
    }
    async deleteConversation(conversationId, token) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}`, {
            method: 'DELETE',
            token,
        });
    }
    // ===== SYSTÈME HYBRIDE DM =====
    async getArchiveStatus(conversationId, token) {
        return fetchService(`${this.baseUrl}/archive/status/${conversationId}`, { token });
    }
    async getArchiveStats(conversationId, token) {
        return fetchService(`${this.baseUrl}/archive/stats/${conversationId}`, { token });
    }
    async checkArchiveQuota(conversationId, token) {
        return fetchService(`${this.baseUrl}/archive/quota/${conversationId}`, { token });
    }
    async confirmArchive(conversationId, archiveLogId, token) {
        return fetchService(`${this.baseUrl}/archive/confirm`, {
            method: 'POST',
            body: JSON.stringify({ conversationId, archiveLogId }),
            token,
        });
    }
    async getCachedArchivedMessage(messageId, token) {
        return fetchService(`${this.baseUrl}/archive/message/${messageId}`, { token });
    }
    async cacheArchivedMessages(messages) {
        return fetchService(`${this.baseUrl}/archive/cache`, {
            method: 'POST',
            body: JSON.stringify({ messages }),
        });
    }
    async saveNotification(userId, conversationId, senderName) {
        return fetchService(`${this.baseUrl}/notifications`, {
            method: 'POST',
            body: JSON.stringify({ userId, conversationId, senderName }),
        });
    }
    async getNotifications(userId, token) {
        return fetchService(`${this.baseUrl}/notifications`, { token });
    }
}
// ============ FRIENDS PROXY ============
class FriendsProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getFriends(userId) {
        try {
            // Pour l'instant, retourner un tableau vide car le service Friends
            // nécessite un token JWT et nous n'avons pas accès au token ici
            return [];
        }
        catch (error) {
            logger_1.logger.warn(`Impossible de récupérer les amis pour ${userId}`);
            return [];
        }
    }
    async sendFriendRequest(fromUserId, toUserId, message) {
        return fetchService(`${this.baseUrl}/friends/requests`, {
            method: 'POST',
            body: JSON.stringify({ fromUserId, toUserId, message }),
        });
    }
    async acceptFriendRequest(requestId, userId) {
        return fetchService(`${this.baseUrl}/friends/requests/${requestId}/accept`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async declineFriendRequest(requestId, userId) {
        return fetchService(`${this.baseUrl}/friends/requests/${requestId}/decline`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async rejectFriendRequest(requestId, userId) {
        return this.declineFriendRequest(requestId, userId);
    }
    async removeFriend(userId, friendId) {
        return fetchService(`${this.baseUrl}/friends/${friendId}`, {
            method: 'DELETE',
            body: JSON.stringify({ userId }),
        });
    }
    async blockUser(userId, blockedUserId) {
        return fetchService(`${this.baseUrl}/friends/block`, {
            method: 'POST',
            body: JSON.stringify({ userId, blockedUserId }),
        });
    }
    async unblockUser(userId, blockedUserId) {
        return fetchService(`${this.baseUrl}/friends/unblock`, {
            method: 'POST',
            body: JSON.stringify({ userId, blockedUserId }),
        });
    }
}
// ============ CALLS PROXY ============
class CallsProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async initiateCall(data) {
        // Le calls service requiert participantIds — construire à partir de initiatorId + recipientId
        const participantIds = [data.initiatorId];
        if (data.recipientId && data.recipientId !== data.initiatorId) {
            participantIds.push(data.recipientId);
        }
        return fetchService(`${this.baseUrl}/calls`, {
            method: 'POST',
            body: JSON.stringify({
                type: data.type,
                initiatorId: data.initiatorId,
                conversationId: data.conversationId || null,
                channelId: data.channelId || null,
                participantIds,
            }),
        });
    }
    async joinCall(callId, userId) {
        return fetchService(`${this.baseUrl}/calls/${callId}/join`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async getCall(callId) {
        try {
            return await fetchService(`${this.baseUrl}/calls/${callId}`, {
                method: 'GET',
            });
        }
        catch {
            return null;
        }
    }
    async rejectCall(callId, userId) {
        return fetchService(`${this.baseUrl}/calls/${callId}/reject`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async endCall(callId, userId) {
        return fetchService(`${this.baseUrl}/calls/${callId}/end`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async leaveCall(callId, userId) {
        return fetchService(`${this.baseUrl}/calls/${callId}/leave`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    // ── Appels groupe via LiveKit SFU ──
    async createGroupRoom(data) {
        return fetchService(`${this.baseUrl}/calls/group/room`, { method: 'POST', body: JSON.stringify(data) });
    }
    async getGroupCallToken(data) {
        return fetchService(`${this.baseUrl}/calls/group/token`, { method: 'POST', body: JSON.stringify(data) });
    }
    async endGroupCall(callId) {
        return fetchService(`${this.baseUrl}/calls/group/${callId}/end`, { method: 'POST' });
    }
}
// ============ SERVERS PROXY ============
class ServersProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getUserServers(userId, token) {
        return fetchService(`${this.baseUrl}/servers?userId=${userId}`, token ? { token } : undefined);
    }
    async getServer(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}`);
    }
    async getServerChannels(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels`, {
            headers: {
                ...(userId ? { 'x-user-id': userId } : {}),
                'x-internal-secret': INTERNAL_SECRET,
            },
        });
    }
    async joinServer(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/join`, {
            method: 'POST',
            headers: { 'x-user-id': userId, 'x-internal-secret': INTERNAL_SECRET },
            body: JSON.stringify({ userId }),
        });
    }
    async leaveServer(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/leave`, {
            method: 'POST',
            headers: { 'x-user-id': userId, 'x-internal-secret': INTERNAL_SECRET },
            body: JSON.stringify({ userId }),
        });
    }
    async registerServerHost(data) {
        return fetchService(`${this.baseUrl}/servers/register`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async createServer(data) {
        return fetchService(`${this.baseUrl}/servers`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async updateServer(serverId, updates, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}`, {
            method: 'PATCH',
            body: JSON.stringify({ ...updates, userId }),
        });
    }
    async deleteServer(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}`, {
            method: 'DELETE',
            body: JSON.stringify({ userId }),
        });
    }
    async createChannel(serverId, data, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels`, {
            method: 'POST',
            body: JSON.stringify({ ...data, userId }),
        });
    }
    async updateChannel(serverId, channelId, updates, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels/${channelId}`, {
            method: 'PATCH',
            body: JSON.stringify({ ...updates, userId }),
        });
    }
    async deleteChannel(serverId, channelId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels/${channelId}`, {
            method: 'DELETE',
            body: JSON.stringify({ userId }),
        });
    }
    async kickMember(serverId, memberUserId, requesterId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}/kick`, {
            method: 'POST',
            body: JSON.stringify({ requesterId }),
        });
    }
    async banMember(serverId, memberUserId, requesterId, reason) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}/ban`, {
            method: 'POST',
            body: JSON.stringify({ requesterId, reason }),
        });
    }
    // ============ MESSAGES SERVEUR ============
    async getChannelMessages(serverId, channelId, limit = 50, before) {
        let url = `${this.baseUrl}/servers/${serverId}/channels/${channelId}/messages?limit=${limit}`;
        if (before)
            url += `&before=${before}`;
        return fetchService(url);
    }
    async createServerMessage(serverId, channelId, data) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels/${channelId}/messages`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async editServerMessage(serverId, messageId, content, senderId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}`, {
            method: 'PATCH',
            body: JSON.stringify({ content, senderId }),
        });
    }
    async deleteServerMessage(serverId, messageId, senderId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}`, {
            method: 'DELETE',
            body: JSON.stringify({ senderId }),
        });
    }
    async addServerReaction(serverId, messageId, userId, emoji) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}/reactions`, {
            method: 'POST',
            body: JSON.stringify({ userId, emoji }),
        });
    }
    async removeServerReaction(serverId, messageId, userId, emoji) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
            method: 'DELETE',
            body: JSON.stringify({ userId }),
        });
    }
    // ============ MEMBRES ============
    async getMembers(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/members`);
    }
    async updateMember(serverId, memberUserId, data) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }
    async isMember(serverId, userId) {
        const result = await fetchService(`${this.baseUrl}/servers/${serverId}/members/${userId}/check`);
        return result.isMember === true;
    }
    async getRoles(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/roles`);
    }
    async createRole(serverId, data) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/roles`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async updateRole(serverId, roleId, data) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/roles/${roleId}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }
    async deleteRole(serverId, roleId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/roles/${roleId}`, {
            method: 'DELETE',
        });
    }
    // ============ INVITATIONS ============
    async createInvite(serverId, data) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/invites`, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async getInvites(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/invites`);
    }
    async resolveInvite(code) {
        return fetchService(`${this.baseUrl}/servers/invite/${code}`);
    }
    async joinByInvite(inviteCode, userId) {
        return fetchService(`${this.baseUrl}/servers/join`, {
            method: 'POST',
            body: JSON.stringify({ inviteCode, userId }),
        });
    }
    async validateNodeToken(nodeToken) {
        return fetchService(`${this.baseUrl}/servers/nodes/validate`, {
            method: 'POST',
            body: JSON.stringify({ nodeToken }),
        });
    }
    async registerNode(name) {
        return fetchService(`${this.baseUrl}/servers/nodes/register`, {
            method: 'POST',
            body: JSON.stringify({ name }),
        });
    }
}
// ============ BOTS PROXY ============
class BotsProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getBot(botId) {
        return fetchService(`${this.baseUrl}/bots/${botId}`);
    }
    async validateBotToken(token) {
        return fetchService(`${this.baseUrl}/bots/validate`, {
            method: 'POST',
            body: JSON.stringify({ token }),
        });
    }
}
//# sourceMappingURL=proxy.js.map