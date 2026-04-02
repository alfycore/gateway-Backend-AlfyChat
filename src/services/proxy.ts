// ==========================================
// ALFYCHAT - PROXY VERS LES MICROSERVICES
// ==========================================

import CircuitBreaker from 'opossum';
import { logger } from '../utils/logger';

// ── Circuit breakers — un par hostname ──────────────────────────────────────
const _breakers = new Map<string, CircuitBreaker>();

function getBreaker(url: string): CircuitBreaker {
  let host: string;
  try { host = new URL(url).host; } catch { host = url; }
  if (!_breakers.has(host)) {
    const action = (fn: () => Promise<unknown>) => fn();
    const breaker = new CircuitBreaker(action, {
      timeout: 10_000,               // 10 s max par appel
      errorThresholdPercentage: 50,  // ouvre après 50 % d'erreurs
      resetTimeout: 30_000,          // demi-ouverture après 30 s
      volumeThreshold: 5,            // évalue après 5 requêtes minimum
    });
    breaker.on('open',     () => logger.warn(`Circuit OUVERT: ${host}`));
    breaker.on('halfOpen', () => logger.info(`Circuit HALF-OPEN: ${host}`));
    breaker.on('close',    () => logger.info(`Circuit FERMÉ: ${host}`));
    _breakers.set(host, breaker);
  }
  return _breakers.get(host)!;
}

// ── Retry exponentiel (2 tentatives, backoff x2) ────────────────────────────
async function withRetry<T>(fn: () => Promise<T>, retries = 2, delayMs = 300): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (retries <= 0) throw error;
    await new Promise(r => setTimeout(r, delayMs));
    return withRetry(fn, retries - 1, delayMs * 2);
  }
}

interface ServiceUrls {
  users: string;
  messages: string;
  friends: string;
  calls: string;
  servers: string;
  bots: string;
}

async function fetchService<T = unknown>(url: string, options?: RequestInit & { token?: string }): Promise<T> {
  const { token, ...fetchOptions } = options || {};

  const doRequest = async (): Promise<T> => {
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
    return response.json() as Promise<T>;
  };

  try {
    const breaker = getBreaker(url);
    return await breaker.fire(() => withRetry(doRequest)) as T;
  } catch (error) {
    logger.error({ err: error }, `Fetch error for ${url}`);
    throw error;
  }
}

export class ServiceProxy {
  public users: UsersProxy;
  public messages: MessagesProxy;
  public friends: FriendsProxy;
  public calls: CallsProxy;
  public servers: ServersProxy;
  public bots: BotsProxy;

  constructor(urls: ServiceUrls) {
    this.users = new UsersProxy(urls.users);
    this.messages = new MessagesProxy(urls.messages);
    this.friends = new FriendsProxy(urls.friends);
    this.calls = new CallsProxy(urls.calls);
    this.servers = new ServersProxy(urls.servers);
    this.bots = new BotsProxy(urls.bots);
  }
}

// ============ USERS PROXY ============

class UsersProxy {
  constructor(private baseUrl: string) {}

  async getUser(userId: string) {
    return fetchService(`${this.baseUrl}/users/${userId}`);
  }

  async updateStatus(userId: string, status: string, customStatus?: string) {
    return fetchService(`${this.baseUrl}/users/${userId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, ...(customStatus !== undefined && { customStatus }) }),
    });
  }

  async updateLastSeen(userId: string) {
    try {
      return fetchService(`${this.baseUrl}/users/${userId}/last-seen`, {
        method: 'PATCH',
      });
    } catch (error) {
      logger.warn(`Impossible de mettre à jour last_seen pour ${userId}`);
      return null;
    }
  }

  async getPreferences(userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/users/${userId}/preferences`, { token });
  }

  async updateProfile(userId: string, data: Record<string, unknown>, token?: string) {
    return fetchService(`${this.baseUrl}/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
      token,
    });
  }
}

// ============ MESSAGES PROXY ============

class MessagesProxy {
  constructor(private baseUrl: string) {}

  async getConversations(userId: string, token?: string) {
    return fetchService<any[]>(`${this.baseUrl}/conversations`, {
      headers: { 'x-user-id': userId },
      ...(token ? { token } : {}),
    });
  }

  async isParticipant(conversationId: string, userId: string): Promise<boolean> {
    try {
      const result = await fetchService<{ isParticipant: boolean }>(
        `${this.baseUrl}/conversations/${conversationId}/participants/${userId}/check`,
        { method: 'GET' },
      );
      return (result as any)?.isParticipant === true;
    } catch {
      return false;
    }
  }

  async createMessage(data: { id?: string; conversationId: string; senderId: string; content: string; senderContent?: string; e2eeType?: number; replyToId?: string }) {
    return fetchService(`${this.baseUrl}/messages`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateMessage(messageId: string, content: string, userId: string) {
    return fetchService(`${this.baseUrl}/messages/${messageId}`, {
      method: 'PATCH',
      body: JSON.stringify({ content }),
      headers: { 'x-user-id': userId },
    });
  }

  async deleteMessage(messageId: string, userId: string) {
    return fetchService(`${this.baseUrl}/messages/${messageId}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async addReaction(messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/messages/${messageId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
      headers: { 'x-user-id': userId },
    });
  }

  async removeReaction(messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async createConversation(data: { type: string; name?: string; avatarUrl?: string; participants: string[]; createdBy: string }) {
    // Le service messages attend 'participantIds', pas 'participants'
    const { participants, createdBy, ...rest } = data;
    return fetchService(`${this.baseUrl}/conversations`, {
      method: 'POST',
      body: JSON.stringify({ ...rest, participantIds: participants }),
    });
  }

  async updateConversation(conversationId: string, data: { name?: string; avatarUrl?: string }, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${conversationId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
      token,
    });
  }

  async addParticipant(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
      token,
    });
  }

  async removeParticipant(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${conversationId}/participants/${userId}`, {
      method: 'DELETE',
      token,
    });
  }

  async leaveConversation(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${conversationId}/leave`, {
      method: 'POST',
      token,
      headers: { 'x-user-id': userId } as any,
    });
  }

  async deleteConversation(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${conversationId}`, {
      method: 'DELETE',
      token,
    });
  }

  // ===== SYSTÈME HYBRIDE DM =====

  async getArchiveStatus(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/status/${conversationId}`, { token });
  }

  async getArchiveStats(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/stats/${conversationId}`, { token });
  }

  async checkArchiveQuota(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/quota/${conversationId}`, { token });
  }

  async confirmArchive(conversationId: string, archiveLogId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/confirm`, {
      method: 'POST',
      body: JSON.stringify({ conversationId, archiveLogId }),
      token,
    });
  }

  async getCachedArchivedMessage(messageId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/message/${messageId}`, { token });
  }

  async cacheArchivedMessages(messages: any[]) {
    return fetchService(`${this.baseUrl}/archive/cache`, {
      method: 'POST',
      body: JSON.stringify({ messages }),
    });
  }

  async saveNotification(userId: string, conversationId: string, senderName: string) {
    return fetchService(`${this.baseUrl}/notifications`, {
      method: 'POST',
      body: JSON.stringify({ userId, conversationId, senderName }),
    });
  }

  async getNotifications(userId: string, token: string) {
    return fetchService(`${this.baseUrl}/notifications`, { token });
  }
}

// ============ FRIENDS PROXY ============

class FriendsProxy {
  constructor(private baseUrl: string) {}

  async getFriends(userId: string): Promise<any[]> {
    try {
      // Pour l'instant, retourner un tableau vide car le service Friends
      // nécessite un token JWT et nous n'avons pas accès au token ici
      return [];
    } catch (error) {
      logger.warn(`Impossible de récupérer les amis pour ${userId}`);
      return [];
    }
  }

  async sendFriendRequest(fromUserId: string, toUserId: string, message?: string) {
    return fetchService(`${this.baseUrl}/friends/requests`, {
      method: 'POST',
      body: JSON.stringify({ fromUserId, toUserId, message }),
    });
  }

  async acceptFriendRequest(requestId: string, userId: string) {
    return fetchService(`${this.baseUrl}/friends/requests/${requestId}/accept`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async declineFriendRequest(requestId: string, userId: string) {
    return fetchService(`${this.baseUrl}/friends/requests/${requestId}/decline`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async rejectFriendRequest(requestId: string, userId: string) {
    return this.declineFriendRequest(requestId, userId);
  }

  async removeFriend(userId: string, friendId: string) {
    return fetchService(`${this.baseUrl}/friends/${friendId}`, {
      method: 'DELETE',
      body: JSON.stringify({ userId }),
    });
  }

  async blockUser(userId: string, blockedUserId: string) {
    return fetchService(`${this.baseUrl}/friends/block`, {
      method: 'POST',
      body: JSON.stringify({ userId, blockedUserId }),
    });
  }

  async unblockUser(userId: string, blockedUserId: string) {
    return fetchService(`${this.baseUrl}/friends/unblock`, {
      method: 'POST',
      body: JSON.stringify({ userId, blockedUserId }),
    });
  }
}

// ============ CALLS PROXY ============

class CallsProxy {
  constructor(private baseUrl: string) {}

  async initiateCall(data: { type: string; initiatorId: string; conversationId?: string; channelId?: string; recipientId?: string }) {
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

  async joinCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${callId}/join`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async rejectCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${callId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async endCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${callId}/end`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async leaveCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${callId}/leave`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  // ── Appels groupe via LiveKit SFU ──

  async createGroupRoom(data: { channelId: string; participantId: string; participantName: string; type: string }) {
    return fetchService<{ callId: string; roomName: string; token: string; wsUrl: string }>(
      `${this.baseUrl}/calls/group/room`,
      { method: 'POST', body: JSON.stringify(data) },
    );
  }

  async getGroupCallToken(data: { callId: string; participantId: string; participantName: string }) {
    return fetchService<{ token: string; roomName: string; wsUrl: string }>(
      `${this.baseUrl}/calls/group/token`,
      { method: 'POST', body: JSON.stringify(data) },
    );
  }

  async endGroupCall(callId: string) {
    return fetchService(`${this.baseUrl}/calls/group/${callId}/end`, { method: 'POST' });
  }
}

// ============ SERVERS PROXY ============

class ServersProxy {
  constructor(private baseUrl: string) {}

  async getUserServers(userId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers?userId=${userId}`);
  }

  async getServer(serverId: string) {
    return fetchService<any>(`${this.baseUrl}/servers/${serverId}`);
  }

  async getServerChannels(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${serverId}/channels`);
  }

  async joinServer(serverId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/join`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async leaveServer(serverId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/leave`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async registerServerHost(data: { serverId: string; endpoint: string; port: number; publicKey: string }) {
    return fetchService(`${this.baseUrl}/servers/register`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async createServer(data: { name: string; description?: string; ownerId: string }) {
    return fetchService(`${this.baseUrl}/servers`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateServer(serverId: string, updates: any, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}`, {
      method: 'PATCH',
      body: JSON.stringify({ ...updates, userId }),
    });
  }

  async deleteServer(serverId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}`, {
      method: 'DELETE',
      body: JSON.stringify({ userId }),
    });
  }

  async createChannel(serverId: string, data: { name: string; type: string; parentId?: string }, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/channels`, {
      method: 'POST',
      body: JSON.stringify({ ...data, userId }),
    });
  }

  async updateChannel(channelId: string, updates: any, userId: string) {
    return fetchService(`${this.baseUrl}/channels/${channelId}`, {
      method: 'PATCH',
      body: JSON.stringify({ ...updates, userId }),
    });
  }

  async deleteChannel(serverId: string, channelId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/channels/${channelId}`, {
      method: 'DELETE',
      body: JSON.stringify({ userId }),
    });
  }

  async kickMember(serverId: string, memberUserId: string, requesterId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}/kick`, {
      method: 'POST',
      body: JSON.stringify({ requesterId }),
    });
  }

  async banMember(serverId: string, memberUserId: string, requesterId: string, reason?: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}/ban`, {
      method: 'POST',
      body: JSON.stringify({ requesterId, reason }),
    });
  }

  // ============ MESSAGES SERVEUR ============

  async getChannelMessages(serverId: string, channelId: string, limit = 50, before?: string) {
    let url = `${this.baseUrl}/servers/${serverId}/channels/${channelId}/messages?limit=${limit}`;
    if (before) url += `&before=${before}`;
    return fetchService<any[]>(url);
  }

  async createServerMessage(serverId: string, channelId: string, data: { senderId: string; content: string; attachments?: string[]; replyToId?: string; tags?: string[] }) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/channels/${channelId}/messages`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async editServerMessage(serverId: string, messageId: string, content: string, senderId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}`, {
      method: 'PATCH',
      body: JSON.stringify({ content, senderId }),
    });
  }

  async deleteServerMessage(serverId: string, messageId: string, senderId: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}`, {
      method: 'DELETE',
      body: JSON.stringify({ senderId }),
    });
  }

  async addServerReaction(serverId: string, messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ userId, emoji }),
    });
  }

  async removeServerReaction(serverId: string, messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/messages/${messageId}/reactions/${encodeURIComponent(emoji)}`, {
      method: 'DELETE',
      body: JSON.stringify({ userId }),
    });
  }

  // ============ MEMBRES ============

  async getMembers(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${serverId}/members`);
  }

  async updateMember(serverId: string, memberUserId: string, data: { roleIds?: string[]; nickname?: string }) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/members/${memberUserId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async isMember(serverId: string, userId: string): Promise<boolean> {
    const result = await fetchService<{ isMember: boolean }>(`${this.baseUrl}/servers/${serverId}/members/${userId}/check`);
    return result.isMember === true;
  }

  async getRoles(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${serverId}/roles`);
  }

  // ============ INVITATIONS ============

  async createInvite(serverId: string, data: { creatorId: string; maxUses?: number; expiresIn?: number; customSlug?: string; isPermanent?: boolean; code?: string; id?: string }) {
    return fetchService(`${this.baseUrl}/servers/${serverId}/invites`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getInvites(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${serverId}/invites`);
  }

  async resolveInvite(code: string) {
    return fetchService(`${this.baseUrl}/servers/invite/${code}`);
  }

  async joinByInvite(inviteCode: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/join`, {
      method: 'POST',
      body: JSON.stringify({ inviteCode, userId }),
    });
  }

  async validateNodeToken(nodeToken: string) {
    return fetchService(`${this.baseUrl}/servers/nodes/validate`, {
      method: 'POST',
      body: JSON.stringify({ nodeToken }),
    });
  }

  async registerNode(name?: string) {
    return fetchService(`${this.baseUrl}/servers/nodes/register`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }
}

// ============ BOTS PROXY ============

class BotsProxy {
  constructor(private baseUrl: string) {}

  async getBot(botId: string) {
    return fetchService(`${this.baseUrl}/bots/${botId}`);
  }

  async validateBotToken(token: string) {
    return fetchService(`${this.baseUrl}/bots/validate`, {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }
}
