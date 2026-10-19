// ==========================================
// ALFYCHAT - PROXY VERS LES MICROSERVICES
// ==========================================

import CircuitBreaker from 'opossum';
import { logger } from '../utils/logger';
import { serviceRegistry, type ServiceType } from '../utils/service-registry';
import { sendMail } from '../utils/mailer';
import { ADMIN_ALERT_EMAILS } from '../config/env';

const INTERNAL_SECRET = process.env.INTERNAL_SECRET || '';

// Throttle des alertes email : 1 email max par instance toutes les 10 minutes
const _alertThrottle = new Map<string, number>();
const ALERT_THROTTLE_MS = 10 * 60 * 1000;

// ── Circuit breakers — un par hostname ──────────────────────────────────────
const _breakers = new Map<string, InstanceType<typeof CircuitBreaker>>();

function getBreaker(url: string): InstanceType<typeof CircuitBreaker> {
  let host: string;
  try { host = new URL(url).host; } catch { host = url; }
  if (!_breakers.has(host)) {
    const action = (fn: () => Promise<unknown>) => fn();
    const breaker = new CircuitBreaker(action, {
      timeout: 15_000,               // 15 s max par appel
      errorThresholdPercentage: 75,  // ouvre après 75 % d'erreurs (plus tolérant)
      resetTimeout: 10_000,          // demi-ouverture après 10 s (récupère plus vite)
      volumeThreshold: 10,           // évalue après 10 requêtes minimum
      // Un 4xx est une réponse normale du service (refus, conflit, introuvable),
      // pas une panne : les compter ouvrait le circuit après quelques refus et
      // coupait TOUT le service (ex. 409 « appel déjà actif » → plus d'appels).
      errorFilter: (err: any) => typeof err?.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 500,
    });
    breaker.on('open',     () => logger.warn(`Circuit OUVERT: ${host}`));
    breaker.on('halfOpen', () => logger.info(`Circuit HALF-OPEN: ${host}`));
    breaker.on('close',    () => logger.info(`Circuit FERMÉ: ${host}`));
    _breakers.set(host, breaker);
  }
  return _breakers.get(host)!;
}

// ── Segments d'URL ──────────────────────────────────────────────────────────
// Les identifiants interpolés dans les URL internes viennent très souvent du
// client (payload WebSocket). Non validés, un `../` suffisait à viser une autre
// route du microservice — avec le secret interne attaché. Tout identifiant
// passe donc par `seg()` : alphabet restreint, puis encodage.
const SEGMENT_RE = /^[A-Za-z0-9_-]{1,128}$/;

export function seg(value: unknown): string {
  if (typeof value !== 'string' || !SEGMENT_RE.test(value)) {
    const err = new Error('INVALID_ID');
    (err as any).statusCode = 400;
    throw err;
  }
  return encodeURIComponent(value);
}

// ── Retry exponentiel (2 tentatives, backoff x2) ────────────────────────────
// Uniquement pour les méthodes idempotentes, et jamais sur une réponse 4xx :
// rejouer un POST après un timeout créait des doublons (le service avait pu
// committer avant que la réponse ne se perde).
async function withRetry<T>(fn: () => Promise<T>, retries = 2, delayMs = 300): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    const status = Number(error?.statusCode);
    if (retries <= 0 || (status >= 400 && status < 500)) throw error;
    await new Promise(r => setTimeout(r, delayMs));
    return withRetry(fn, retries - 1, delayMs * 2);
  }
}

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']);

interface ServiceUrls {
  users: string;
  messages: string;
  friends: string;
  calls: string;
  servers: string;
  bots: string;
  mediaServer?: string;
}

// ── Alerte email admin (throttled) ──────────────────────────────────────────
function notifyAdminDegraded(instance: { id: string; serviceType: string; endpoint: string; domain: string }, reason: string): void {
  const now = Date.now();
  const last = _alertThrottle.get(instance.id) ?? 0;
  if (now - last < ALERT_THROTTLE_MS) return;
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

  sendMail({ to: ADMIN_ALERT_EMAILS, subject, text }).catch(() => {});
}

// ── Fetch avec failover multi-instance ──────────────────────────────────────
/**
 * Exécute un fetch HTTP en utilisant l'URL fournie en priorité.
 * Si l'URL retourne une erreur 5XX (ou le circuit est ouvert), tente de basculer
 * sur une autre instance saine du même serviceType dans le registre.
 * L'instance défaillante est marquée dégradée et les admins sont alertés par email.
 */
async function fetchWithFailover<T = unknown>(
  primaryUrl: string,
  serviceType: ServiceType | null,
  options?: RequestInit & { token?: string },
): Promise<T> {
  const { token, ...fetchOptions } = options || {};

  const doRequest = async (url: string): Promise<T> => {
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
      try { const b = await response.json(); detail = JSON.stringify(b); } catch {}
      const err = new Error(`Service error: ${response.status} ${detail}`);
      (err as any).statusCode = response.status;
      throw err;
    }
    return response.json() as Promise<T>;
  };

  const method = String(fetchOptions?.method || 'GET').toUpperCase();
  const retryable = IDEMPOTENT_METHODS.has(method);

  const tryFetch = async (url: string): Promise<T> => {
    const breaker = getBreaker(url);
    return await breaker.fire(() => (retryable ? withRetry(doRequest.bind(null, url)) : doRequest(url))) as T;
  };

  // Tentative primaire
  try {
    return await tryFetch(primaryUrl);
  } catch (primaryErr: any) {
    const isPrimary5xx = (primaryErr?.statusCode >= 500) || /Breaker is open|503|502|500/.test(String(primaryErr?.message));

    // Pas un 5XX (ex: 400, 401, 404) → ne pas basculer, propager l'erreur
    if (!isPrimary5xx || !serviceType || !retryable) {
      logger.error({ err: primaryErr }, `Fetch error for ${primaryUrl}`);
      throw primaryErr;
    }

    // Trouver l'instance correspondant à l'URL primaire
    const allInstances = serviceRegistry.getAll().filter((i) => i.serviceType === serviceType);
    const primaryInstance = allInstances.find((i) => primaryUrl.startsWith(i.endpoint));

    if (primaryInstance) {
      serviceRegistry.markDegraded(primaryInstance.id, primaryErr.message);
      notifyAdminDegraded(primaryInstance, primaryErr.message);
      logger.warn(`[Failover] Instance primaire dégradée: ${primaryInstance.id} — recherche d'un fallback…`);
    }

    // Chercher une autre instance saine du même type (exclut la primaire)
    const fallbacks = serviceRegistry.getInstances(serviceType).filter(
      (i) => i.id !== primaryInstance?.id && !i.degraded,
    );

    if (fallbacks.length === 0) {
      logger.error(`[Failover] Aucun fallback disponible pour ${serviceType}`);
      throw primaryErr;
    }

    // Trier par score et essayer dans l'ordre
    const sorted = fallbacks.sort(
      (a, b) => serviceRegistry.computeScore(b) - serviceRegistry.computeScore(a),
    );

    for (const fallback of sorted) {
      // Remplacer la base de l'URL primaire par le endpoint du fallback
      const fallbackUrl = primaryUrl.replace(
        primaryInstance?.endpoint || primaryUrl.split('/').slice(0, 3).join('/'),
        fallback.endpoint,
      );
      try {
        logger.info(`[Failover] Bascule vers ${fallback.id} (${fallback.endpoint})`);
        const result = await tryFetch(fallbackUrl);
        return result;
      } catch (fallbackErr: any) {
        const isFallback5xx = (fallbackErr?.statusCode >= 500) || /Breaker is open|503|502|500/.test(String(fallbackErr?.message));
        if (isFallback5xx) {
          serviceRegistry.markDegraded(fallback.id, fallbackErr.message);
          notifyAdminDegraded(fallback, fallbackErr.message);
          logger.warn(`[Failover] Fallback ${fallback.id} aussi dégradé, essai suivant…`);
        } else {
          throw fallbackErr;
        }
      }
    }

    logger.error(`[Failover] Tous les fallbacks épuisés pour ${serviceType}`);
    throw primaryErr;
  }
}

// Wrapper rétrocompatible pour les appels sans failover (services sans registry)
async function fetchService<T = unknown>(url: string, options?: RequestInit & { token?: string }): Promise<T> {
  return fetchWithFailover<T>(url, null, options);
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// En production, le LB est la seule source de vérité — pas de fallback .env.
// En dev / test, fallback sur l'URL fournie si le LB n'a pas d'instance saine.
function resolveServiceUrl(serviceType: ServiceType, fallbackUrl: string): string {
  const best = serviceRegistry.selectBest(serviceType);
  if (best) return best.endpoint;
  return IS_PRODUCTION ? '' : fallbackUrl;
}

export class ServiceProxy {
  public users: UsersProxy;
  public messages: MessagesProxy;
  public friends: FriendsProxy;
  public calls: CallsProxy;
  public servers: ServersProxy;
  public bots: BotsProxy;
  public media: MediaServerProxy;

  constructor(urls: ServiceUrls) {
    this.users = new UsersProxy(urls.users);
    this.messages = new MessagesProxy(urls.messages);
    this.friends = new FriendsProxy(urls.friends);
    this.calls = new CallsProxy(urls.calls);
    this.servers = new ServersProxy(urls.servers);
    this.bots = new BotsProxy(urls.bots);
    this.media = new MediaServerProxy(urls.mediaServer || 'http://localhost:3010');
  }
}

// ============ USERS PROXY ============

class UsersProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('users', this._fallbackUrl); }

  async getUser(userId: string) {
    return fetchService(`${this.baseUrl}/users/${seg(userId)}`);
  }

  /**
   * Statut de modération global (ban / mute). Endpoint interne : les motifs
   * de sanction ne transitent jamais par le profil public.
   */
  async getModerationStatus(userId: string) {
    return fetchService<{
      banned: boolean;
      bannedUntil: string | null;
      banReason: string | null;
      muted: boolean;
      mutedUntil: string | null;
      muteReason: string | null;
      warnings: number;
    }>(`${this.baseUrl}/internal/moderation/${seg(userId)}`);
  }

  async updateStatus(userId: string, status: string, customStatus?: string | null, emoji?: string | null) {
    return fetchService(`${this.baseUrl}/users/${seg(userId)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({
        status,
        ...(customStatus !== undefined && { customStatus, text: customStatus }),
        ...(emoji !== undefined && { emoji }),
      }),
      headers: { 'x-user-id': userId },
    });
  }

  async updateLastSeen(userId: string) {
    try {
      return fetchService(`${this.baseUrl}/users/${seg(userId)}/last-seen`, {
        method: 'PATCH',
        headers: { 'x-user-id': userId },
      });
    } catch (error) {
      logger.warn(`Impossible de mettre à jour last_seen pour ${userId}`);
      return null;
    }
  }

  async getPreferences(userId: string, _token?: string) {
    return fetchService(`${this.baseUrl}/users/${seg(userId)}/preferences`, {
      headers: { 'x-user-id': userId },
    });
  }

  async updateProfile(userId: string, data: Record<string, unknown>, _token?: string) {
    return fetchService(`${this.baseUrl}/users/${seg(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
      headers: { 'x-user-id': userId },
    });
  }

  async changeUsername(userId: string, newUsername: string, password: string, token?: string) {
    return fetchService(`${this.baseUrl}/users/${seg(userId)}/change-username`, {
      method: 'POST',
      body: JSON.stringify({ newUsername, password }),
      token,
    });
  }

  async sendPushNotification(payload: {
    userId: string;
    title: string;
    body: string;
    url?: string;
    type?: string;
    conversationKey?: string;
  }): Promise<void> {
    try {
      await fetchService(`${this.baseUrl}/push/send`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    } catch {
      // Fire-and-forget — ne pas bloquer l'envoi du message
    }
  }
}

// ============ MESSAGES PROXY ============

class MessagesProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('messages', this._fallbackUrl); }

  async getConversations(userId: string, token?: string) {
    return fetchWithFailover<any[]>(`${this.baseUrl}/conversations`, 'messages', {
      headers: { 'x-user-id': userId },
      ...(token ? { token } : {}),
      signal: AbortSignal.timeout(5_000), // 5s max au connect — non bloquant
    });
  }

  async isParticipant(conversationId: string, userId: string): Promise<boolean> {
    try {
      const result = await fetchService<{ isParticipant: boolean }>(
        `${this.baseUrl}/conversations/${seg(conversationId)}/participants/${seg(userId)}/check`,
        { method: 'GET' },
      );
      return (result as any)?.isParticipant === true;
    } catch {
      return false;
    }
  }

  async createMessage(data: { id?: string; conversationId: string; senderId: string; content: string; senderContent?: string; e2eeType?: number; replyToId?: string }) {
    return fetchWithFailover(`${this.baseUrl}/messages`, 'messages', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateMessage(messageId: string, content: string, userId: string, senderContent?: string, e2eeType?: number) {
    return fetchWithFailover(`${this.baseUrl}/messages/${seg(messageId)}`, 'messages', {
      method: 'PATCH',
      body: JSON.stringify({ content, ...(senderContent !== undefined && { senderContent }), ...(e2eeType !== undefined && { e2eeType }) }),
      headers: { 'x-user-id': userId },
    });
  }

  async deleteMessage(messageId: string, userId: string) {
    return fetchWithFailover(`${this.baseUrl}/messages/${seg(messageId)}`, 'messages', {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async addReaction(messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/messages/${seg(messageId)}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
      headers: { 'x-user-id': userId },
    });
  }

  async removeReaction(messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/messages/${seg(messageId)}/reactions/${encodeURIComponent(String(emoji))}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async createConversation(data: { type: string; name?: string; avatarUrl?: string; participants: string[]; createdBy: string; isOpen?: boolean }) {
    // Le service messages attend 'participantIds', pas 'participants'
    const { participants, createdBy, ...rest } = data;
    return fetchService(`${this.baseUrl}/conversations`, {
      method: 'POST',
      headers: { 'x-user-id': createdBy },
      body: JSON.stringify({ ...rest, participantIds: participants }),
    });
  }

  async updateConversation(conversationId: string, data: { name?: string; avatarUrl?: string; isOpen?: boolean }, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
      token,
    });
  }

  async getConversationParticipants(conversationId: string): Promise<{ participants?: Array<{ userId: string }> } | Array<{ userId: string }>> {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}/participants`);
  }

  async addParticipant(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}/participants`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
      token,
    });
  }

  async removeParticipant(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}/participants/${seg(userId)}`, {
      method: 'DELETE',
      token,
    });
  }

  async leaveConversation(conversationId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}/leave`, {
      method: 'POST',
      token,
      headers: { 'x-user-id': userId } as any,
    });
  }

  async deleteConversation(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/conversations/${seg(conversationId)}`, {
      method: 'DELETE',
      token,
    });
  }

  // ===== SYSTÈME HYBRIDE DM =====

  async getArchiveStatus(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/status/${seg(conversationId)}`, { token });
  }

  async getArchiveStats(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/stats/${seg(conversationId)}`, { token });
  }

  async checkArchiveQuota(conversationId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/quota/${seg(conversationId)}`, { token });
  }

  async confirmArchive(conversationId: string, archiveLogId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/confirm`, {
      method: 'POST',
      body: JSON.stringify({ conversationId, archiveLogId }),
      token,
    });
  }

  async getCachedArchivedMessage(messageId: string, token?: string) {
    return fetchService(`${this.baseUrl}/archive/message/${seg(messageId)}`, { token });
  }

  async cacheArchivedMessages(messages: any[]) {
    return fetchService(`${this.baseUrl}/archive/cache`, {
      method: 'POST',
      body: JSON.stringify({ messages }),
    });
  }

  async saveNotification(
    userId: string,
    conversationId: string,
    senderName: string,
    senderId?: string,
    notificationType?: 'message' | 'mention',
    channelName?: string,
  ) {
    return fetchService(`${this.baseUrl}/notifications`, {
      method: 'POST',
      body: JSON.stringify({ userId, conversationId, senderName, senderId, notificationType, channelName }),
    });
  }

  async getNotifications(userId: string, token: string) {
    return fetchService(`${this.baseUrl}/notifications`, { token });
  }
}

// ============ FRIENDS PROXY ============

class FriendsProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('friends', this._fallbackUrl); }

  async getFriends(userId: string): Promise<any[]> {
    try {
      // Le middleware du service Friends accepte le bypass interne
      // (X-Internal-Secret, injecté automatiquement par fetchWithFailover)
      // + x-user-id pour s'authentifier sans le JWT de l'utilisateur.
      return await fetchService<any[]>(`${this.baseUrl}/friends`, {
        headers: { 'x-user-id': userId },
      });
    } catch (error) {
      logger.warn(`Impossible de récupérer les amis pour ${userId}`);
      return [];
    }
  }

  async sendFriendRequest(fromUserId: string, toUserId: string, message?: string) {
    return fetchService(`${this.baseUrl}/friends/requests`, {
      method: 'POST',
      headers: { 'x-user-id': fromUserId },
      body: JSON.stringify({ toUserId, message }),
    });
  }

  async acceptFriendRequest(requestId: string, userId: string) {
    return fetchService(`${this.baseUrl}/friends/requests/${seg(requestId)}/accept`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId }),
    });
  }

  async declineFriendRequest(requestId: string, userId: string) {
    return fetchService(`${this.baseUrl}/friends/requests/${seg(requestId)}/decline`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId }),
    });
  }

  async rejectFriendRequest(requestId: string, userId: string) {
    return this.declineFriendRequest(requestId, userId);
  }

  async removeFriend(userId: string, friendId: string) {
    return fetchService(`${this.baseUrl}/friends/${seg(friendId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async blockUser(userId: string, blockedUserId: string) {
    return fetchService(`${this.baseUrl}/friends/${seg(blockedUserId)}/block`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
    });
  }

  async unblockUser(userId: string, blockedUserId: string) {
    return fetchService(`${this.baseUrl}/friends/${seg(blockedUserId)}/unblock`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
    });
  }
}

// ============ CALLS PROXY ============

class CallsProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('calls', this._fallbackUrl); }

  private internalHeaders(userId?: string): Record<string, string> {
    return {
      // fetchWithFailover already injects X-Internal-Secret from the module scope.
      // Adding it here again would cause Express to receive both X-Internal-Secret
      // and x-internal-secret and concatenate them ("secret, secret"), breaking
      // safeCompare in the auth middleware. Only inject the per-request user id.
      ...(userId ? { 'x-user-id': userId } : {}),
    };
  }

  async initiateCall(data: { type: string; initiatorId: string; conversationId?: string; channelId?: string; recipientId?: string }) {
    // Le calls service requiert participantIds — construire à partir de initiatorId + recipientId
    const participantIds = [data.initiatorId];
    if (data.recipientId && data.recipientId !== data.initiatorId) {
      participantIds.push(data.recipientId);
    }
    return fetchService(`${this.baseUrl}/calls`, {
      method: 'POST',
      headers: this.internalHeaders(data.initiatorId),
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
    return fetchService(`${this.baseUrl}/calls/${seg(callId)}/join`, {
      method: 'POST',
      headers: this.internalHeaders(userId),
      body: JSON.stringify({ userId }),
    });
  }

  async getCall(callId: string): Promise<{ id: string; participants: string[]; status: string } | null> {
    try {
      return await fetchService<{ id: string; participants: string[]; status: string }>(`${this.baseUrl}/calls/${seg(callId)}`, {
        method: 'GET',
        headers: this.internalHeaders(),
      });
    } catch {
      return null;
    }
  }

  async rejectCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${seg(callId)}/reject`, {
      method: 'POST',
      headers: this.internalHeaders(userId),
      body: JSON.stringify({ userId }),
    });
  }

  async endCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${seg(callId)}/end`, {
      method: 'POST',
      headers: this.internalHeaders(userId),
      body: JSON.stringify({ userId }),
    });
  }

  async leaveCall(callId: string, userId: string) {
    return fetchService(`${this.baseUrl}/calls/${seg(callId)}/leave`, {
      method: 'POST',
      headers: this.internalHeaders(userId),
      body: JSON.stringify({ userId }),
    });
  }

  async createDmCall(data: { type: string; initiatorId: string; conversationId?: string }) {
    return fetchService<{ id: string; callCategory: string; participants: string[] }>(
      `${this.baseUrl}/calls/dm`,
      { method: 'POST', headers: this.internalHeaders(data.initiatorId), body: JSON.stringify(data) },
    );
  }

  async createGroupCall(data: { channelId: string; initiatorId: string; type: string }) {
    return fetchService<{ id: string; callId?: string; callCategory: string; channelId: string; type: string; status: string; participants: string[] }>(
      `${this.baseUrl}/calls/group`,
      { method: 'POST', headers: this.internalHeaders(data.initiatorId), body: JSON.stringify(data) },
    );
  }

  async createServerCall(data: { channelId: string; serverId: string; initiatorId: string; type: string }) {
    return fetchService<{ id: string; callCategory: string; channelId: string; serverId: string; status: string; participants: string[] }>(
      `${this.baseUrl}/calls/server`,
      { method: 'POST', headers: this.internalHeaders(data.initiatorId), body: JSON.stringify(data) },
    );
  }

  async getCallQuality(callId: string) {
    return fetchService<{ callId: string; tier: number; participantCount: number; callCategory: string }>(
      `${this.baseUrl}/calls/${seg(callId)}/quality`,
      { method: 'GET', headers: this.internalHeaders() },
    );
  }

  async getServerLimit(serverId: string) {
    try {
      const res = await fetchService<{ maxParticipants: number }>(
        `${this.baseUrl}/calls/limits/${seg(serverId)}`,
        { method: 'GET', headers: this.internalHeaders() },
      );
      return res.maxParticipants;
    } catch {
      return 1500;
    }
  }
}

// ============ MEDIA SERVER PROXY ============

class MediaServerProxy {
  constructor(private baseUrl: string) {}

  private headers() {
    return {
      'Content-Type': 'application/json',
      'x-internal-secret': INTERNAL_SECRET,
    };
  }

  private async post<T = unknown>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`media-server ${path}: ${res.status} ${detail}`);
    }
    return res.json() as Promise<T>;
  }

  private async del(path: string): Promise<void> {
    await fetch(`${this.baseUrl}${path}`, { method: 'DELETE', headers: this.headers() });
  }

  private async get<T = unknown>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, { method: 'GET', headers: this.headers() });
    if (!res.ok) throw new Error(`media-server GET ${path}: ${res.status}`);
    return res.json() as Promise<T>;
  }

  async createRoom(callId: string, callCategory: 'group' | 'server') {
    return this.post('/internal/rooms', { callId, callCategory });
  }

  async destroyRoom(callId: string) {
    return this.del(`/internal/rooms/${seg(callId)}`);
  }

  async getRtpCapabilities(callId: string) {
    return this.get<{ rtpCapabilities: unknown }>(`/internal/rooms/${seg(callId)}/capabilities`);
  }

  async createTransport(callId: string, userId: string, direction: 'send' | 'recv') {
    return this.post<{
      transportId: string;
      iceParameters: unknown;
      iceCandidates: unknown;
      dtlsParameters: unknown;
    }>(`/internal/rooms/${seg(callId)}/transports`, { userId, direction });
  }

  async connectTransport(callId: string, transportId: string, dtlsParameters: unknown, userId: string) {
    return this.post(`/internal/rooms/${seg(callId)}/connect`, { transportId, dtlsParameters, userId });
  }

  async produce(callId: string, transportId: string, kind: string, rtpParameters: unknown, userId: string, appData?: unknown) {
    return this.post<{ producerId: string }>(`/internal/rooms/${seg(callId)}/produce`, {
      transportId, kind, rtpParameters, userId, appData,
    });
  }

  async consume(callId: string, recvTransportId: string, producerId: string, rtpCapabilities: unknown, userId: string) {
    return this.post<{
      consumerId: string; producerId: string; kind: string; rtpParameters: unknown; paused: boolean;
    }>(`/internal/rooms/${seg(callId)}/consume`, { recvTransportId, producerId, rtpCapabilities, userId });
  }

  async resumeConsumer(callId: string, consumerId: string, userId: string) {
    return this.post(`/internal/rooms/${seg(callId)}/resume`, { consumerId, userId });
  }

  async closeProducer(callId: string, producerId: string, userId: string) {
    return this.post(`/internal/rooms/${seg(callId)}/close-producer`, { producerId, userId });
  }

  async getRoomStats(callId: string) {
    return this.get<{ participantCount: number; tier: number }>(`/internal/rooms/${seg(callId)}/stats`);
  }

  async getProducers(callId: string) {
    return this.get<{ producers: { producerId: string; userId: string; kind: string }[] }>(
      `/internal/rooms/${seg(callId)}/producers`,
    );
  }
}

// ============ SERVERS PROXY ============

class ServersProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('servers', this._fallbackUrl); }

  async getUserServers(userId: string, token?: string) {
    // Le service servers ne lit QUE `x-user-id` sur un appel interne (le
    // paramètre d'URL est ignoré) : sans cet en-tête il cherchait les serveurs
    // de « internal », la liste revenait vide et aucune socket ne rejoignait
    // les rooms serveur / salon — plus aucune diffusion en direct.
    return fetchService<any[]>(`${this.baseUrl}/servers?userId=${seg(userId)}`, {
      ...(token ? { token } : {}),
      headers: { 'x-user-id': userId },
    });
  }

  async getServer(serverId: string) {
    return fetchService<any>(`${this.baseUrl}/servers/${seg(serverId)}`);
  }

  async getServerChannels(serverId: string, userId?: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${seg(serverId)}/channels`, {
      headers: {
        ...(userId ? { 'x-user-id': userId } : {}),
      },
    });
  }

  async joinServer(serverId: string, userId: string, inviteCode?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/join`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId, ...(inviteCode ? { inviteCode } : {}) }),
    });
  }

  async leaveServer(serverId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/leave`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
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

  async updateServer(serverId: string, updates: any, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}`, {
      method: 'PATCH',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ ...updates, userId }),
      token,
    });
  }

  async deleteServer(serverId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId }),
      token,
    });
  }

  async createChannel(
    serverId: string,
    data: { name: string; type: string; parentId?: string | null; topic?: string; isNsfw?: boolean; slowMode?: number; userLimit?: number; isPrivate?: boolean },
    userId: string,
    token?: string,
  ) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ ...data, userId }),
      token,
    });
  }

  async updateChannel(serverId: string, channelId: string, updates: any, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}`, {
      method: 'PATCH',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ ...updates, userId }),
      token,
    });
  }

  /** Réorganisation par lot (glisser-déposer). */
  async reorderChannels(serverId: string, positions: { id: string; position: number; parentId?: string | null }[], userId: string) {
    return fetchService<{ serverId: string; channels: any[] }>(`${this.baseUrl}/servers/${seg(serverId)}/channels`, {
      method: 'PATCH',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ positions }),
    });
  }

  /** Règles AutoMod actives du serveur — `blocked` si le message doit être refusé. */
  async automodCheck(serverId: string, content: string, userId: string) {
    return fetchService<{ blocked: boolean; reason: string | null; action?: string }>(
      `${this.baseUrl}/servers/${seg(serverId)}/automod/check`,
      { method: 'POST', body: JSON.stringify({ content, userId }) },
    );
  }

  async getChannelOverrides(serverId: string, channelId: string) {
    return fetchService<{ channelId: string; parentId: string | null; synced: boolean; overrides: any[] }>(
      `${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/overrides`,
    );
  }

  async setChannelOverride(serverId: string, channelId: string, data: { targetType: 'role' | 'member'; targetId: string; allow: number; deny: number }, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/overrides`, {
      method: 'PUT',
      headers: { 'x-user-id': userId },
      body: JSON.stringify(data),
    });
  }

  async deleteChannelOverride(serverId: string, channelId: string, targetType: 'role' | 'member', targetId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/overrides/${seg(targetType)}/${seg(targetId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async syncChannelOverrides(serverId: string, channelId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/overrides/sync`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({}),
    });
  }

  async reorderRoles(serverId: string, positions: { id: string; position: number }[], userId: string) {
    return fetchService<{ serverId: string; roles: any[] }>(`${this.baseUrl}/servers/${seg(serverId)}/roles`, {
      method: 'PATCH',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ positions }),
    });
  }

  async deleteChannel(serverId: string, channelId: string, userId: string, token?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId }),
      token,
    });
  }

  async kickMember(serverId: string, memberUserId: string, requesterId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/members/${seg(memberUserId)}/kick`, {
      method: 'POST',
      headers: { 'x-user-id': requesterId },
      body: JSON.stringify({ requesterId }),
    });
  }

  async banMember(serverId: string, memberUserId: string, requesterId: string, reason?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/members/${seg(memberUserId)}/ban`, {
      method: 'POST',
      headers: { 'x-user-id': requesterId },
      body: JSON.stringify({ requesterId, reason }),
    });
  }

  // ============ MESSAGES SERVEUR ============

  async getChannelMessages(serverId: string, channelId: string, limit = 50, before?: string, userId?: string) {
    let url = `${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/messages?limit=${Math.min(Math.max(Number(limit) || 50, 1), 100)}`;
    if (before) url += `&before=${encodeURIComponent(String(before))}`;
    return fetchService<any[]>(url, userId ? { headers: { 'x-user-id': userId } } : undefined);
  }

  async createServerMessage(serverId: string, channelId: string, data: { senderId: string; content: string; attachments?: string[]; replyToId?: string; tags?: string[] }) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/channels/${seg(channelId)}/messages`, {
      method: 'POST',
      headers: { 'x-user-id': data.senderId },
      body: JSON.stringify(data),
    });
  }

  async editServerMessage(serverId: string, messageId: string, content: string, senderId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/messages/${seg(messageId)}`, {
      method: 'PATCH',
      headers: { 'x-user-id': senderId },
      body: JSON.stringify({ content, senderId }),
    });
  }

  async deleteServerMessage(serverId: string, messageId: string, senderId: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/messages/${seg(messageId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': senderId },
      body: JSON.stringify({ senderId }),
    });
  }

  async addServerReaction(serverId: string, messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/messages/${seg(messageId)}/reactions`, {
      method: 'POST',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId, emoji }),
    });
  }

  async removeServerReaction(serverId: string, messageId: string, userId: string, emoji: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/messages/${seg(messageId)}/reactions/${encodeURIComponent(String(emoji))}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
      body: JSON.stringify({ userId }),
    });
  }

  // ============ MEMBRES ============

  async getMembers(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${seg(serverId)}/members`);
  }

  async updateMember(serverId: string, memberUserId: string, data: { roleIds?: string[]; nickname?: string }, actorId?: string, token?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/members/${seg(memberUserId)}`, {
      method: 'PATCH',
      headers: actorId ? { 'x-user-id': actorId } : undefined,
      body: JSON.stringify(data),
      token,
    });
  }

  async isMember(serverId: string, userId: string): Promise<boolean> {
    const result = await fetchService<{ isMember: boolean }>(`${this.baseUrl}/servers/${seg(serverId)}/members/${seg(userId)}/check`);
    return result.isMember === true;
  }

  /** Fiche minimale d'un membre (rôles, pseudo, date d'arrivée) — même route que `isMember`. */
  async getMemberRecord(serverId: string, userId: string) {
    return fetchService<{ isMember: boolean; nickname?: string | null; roleIds?: string[]; joinedAt?: string | null }>(
      `${this.baseUrl}/servers/${seg(serverId)}/members/${seg(userId)}/check`,
    );
  }

  /**
   * Permissions cumulées d'un membre — un entier, calculé côté SQL.
   * Remplace le trio getServer + getMembers + getRoles qui rapatriait toute la
   * liste des membres à chaque vérification de permission.
   */
  async getMemberPermissions(serverId: string, userId: string, channelId?: string) {
    const query = channelId ? `?channelId=${encodeURIComponent(channelId)}` : '';
    return fetchService<{ isMember: boolean; isOwner: boolean; permissions: number }>(
      `${this.baseUrl}/servers/${seg(serverId)}/members/${seg(userId)}/permissions${query}`,
    );
  }

  async getRoles(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${seg(serverId)}/roles`);
  }

  async createRole(serverId: string, data: { name: string; color?: string; permissions?: any }, userId?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/roles`, {
      method: 'POST',
      headers: userId ? { 'x-user-id': userId } : undefined,
      body: JSON.stringify(data),
    });
  }

  async updateRole(serverId: string, roleId: string, data: any, userId?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/roles/${seg(roleId)}`, {
      method: 'PATCH',
      headers: userId ? { 'x-user-id': userId } : undefined,
      body: JSON.stringify(data),
    });
  }

  async deleteRole(serverId: string, roleId: string, userId?: string) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/roles/${seg(roleId)}`, {
      method: 'DELETE',
      headers: userId ? { 'x-user-id': userId } : undefined,
    });
  }

  // ============ INVITATIONS ============

  async createInvite(serverId: string, data: { creatorId: string; maxUses?: number; expiresIn?: number; customSlug?: string; isPermanent?: boolean; code?: string; id?: string }) {
    return fetchService(`${this.baseUrl}/servers/${seg(serverId)}/invites`, {
      method: 'POST',
      headers: { 'x-user-id': data.creatorId },
      body: JSON.stringify(data),
    });
  }

  async deleteInvite(inviteId: string, userId: string) {
    return fetchService(`${this.baseUrl}/servers/invites/${seg(inviteId)}`, {
      method: 'DELETE',
      headers: { 'x-user-id': userId },
    });
  }

  async getInvites(serverId: string) {
    return fetchService<any[]>(`${this.baseUrl}/servers/${seg(serverId)}/invites`);
  }

  async resolveInvite(code: string) {
    return fetchService(`${this.baseUrl}/servers/invite/${seg(code)}`);
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

  async registerNode(name?: string, ownerId?: string) {
    return fetchService(`${this.baseUrl}/servers/nodes/register`, {
      method: 'POST',
      headers: ownerId ? { 'x-user-id': ownerId } : undefined,
      body: JSON.stringify({ name, ownerId }),
    });
  }
}

// ============ BOTS PROXY ============

class BotsProxy {
  constructor(private _fallbackUrl: string) {}
  private get baseUrl(): string { return resolveServiceUrl('bots', this._fallbackUrl); }

  async getBot(botId: string) {
    return fetchService(`${this.baseUrl}/bots/${seg(botId)}`);
  }

  async validateBotToken(token: string) {
    return fetchService(`${this.baseUrl}/bots/validate`, {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }
}
