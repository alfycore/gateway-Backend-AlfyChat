"use strict";
// ==========================================
// ALFYCHAT - PROXY VERS LES MICROSERVICES
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServiceProxy = void 0;
const logger_1 = require("../utils/logger");
async function fetchService(url, options) {
    try {
        const { token, ...fetchOptions } = options || {};
        const response = await fetch(url, {
            ...fetchOptions,
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...fetchOptions?.headers,
            },
        });
        if (!response.ok) {
            throw new Error(`Service error: ${response.status} ${response.statusText}`);
        }
        return response.json();
    }
    catch (error) {
        logger_1.logger.error(`Fetch error for ${url}:`, error);
        throw error;
    }
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
    async updateStatus(userId, status) {
        return fetchService(`${this.baseUrl}/users/${userId}/status`, {
            method: 'PATCH',
            body: JSON.stringify({ status }),
        });
    }
    async updateLastSeen(userId) {
        try {
            return fetchService(`${this.baseUrl}/users/${userId}/last-seen`, {
                method: 'PATCH',
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
        return fetchService(`${this.baseUrl}/conversations?userId=${userId}`, { token });
    }
    async createMessage(data) {
        return fetchService(`${this.baseUrl}/messages`, {
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
    async addParticipant(conversationId, userId) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async removeParticipant(conversationId, userId) {
        return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants/${userId}`, {
            method: 'DELETE',
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
}
// ============ SERVERS PROXY ============
class ServersProxy {
    baseUrl;
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }
    async getUserServers(userId) {
        return fetchService(`${this.baseUrl}/servers?userId=${userId}`);
    }
    async getServer(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}`);
    }
    async getServerChannels(serverId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/channels`);
    }
    async joinServer(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/join`, {
            method: 'POST',
            body: JSON.stringify({ userId }),
        });
    }
    async leaveServer(serverId, userId) {
        return fetchService(`${this.baseUrl}/servers/${serverId}/leave`, {
            method: 'POST',
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
    async updateChannel(channelId, updates, userId) {
        return fetchService(`${this.baseUrl}/channels/${channelId}`, {
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