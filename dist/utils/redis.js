"use strict";
// ==========================================
// ALFYCHAT - REDIS CLIENT POUR GATEWAY
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisClient = void 0;
const ioredis_1 = __importDefault(require("ioredis"));
const logger_1 = require("./logger");
class RedisClient {
    client;
    subscriber;
    publisher;
    constructor(config) {
        const options = {
            host: config.host,
            port: config.port,
            password: config.password,
            retryStrategy: (times) => Math.min(times * 50, 2000),
        };
        this.client = new ioredis_1.default(options);
        this.subscriber = new ioredis_1.default(options);
        this.publisher = new ioredis_1.default(options);
        this.client.on('connect', () => logger_1.logger.info('Redis client connecté'));
        this.client.on('error', (err) => logger_1.logger.error({ err: err }, 'Redis error:'));
    }
    async setUserOnline(userId, socketId) {
        await this.client.sadd(`user:sockets:${userId}`, socketId);
        await this.client.sadd('online:list', userId);
        await this.client.hset('online:users', userId, socketId);
    }
    async setUserOffline(userId, socketId) {
        await this.client.srem(`user:sockets:${userId}`, socketId);
        const remaining = await this.client.scard(`user:sockets:${userId}`);
        if (remaining === 0) {
            await this.client.hdel('online:users', userId);
            await this.client.srem('online:list', userId);
        }
    }
    async isUserOnline(userId) {
        return (await this.client.sismember('online:list', userId)) === 1;
    }
    async getUserSocketId(userId) {
        return this.client.hget('online:users', userId);
    }
    // ============ PRÉSENCE (nouveau système unifié) ============
    /** Set full presence data for a user. TTL = 24h so it survives short disconnects. */
    async setPresence(userId, data) {
        const key = `presence:${userId}`;
        let current = null;
        const raw = await this.client.get(key);
        if (raw) {
            try {
                current = JSON.parse(raw);
            }
            catch { /* ignore */ }
        }
        const merged = {
            status: current?.status ?? 'online',
            chosenStatus: current?.chosenStatus ?? 'online',
            emoji: current?.emoji ?? null,
            text: current?.text ?? null,
            lastActivity: current?.lastActivity ?? Date.now(),
            ...data,
        };
        await this.client.setex(key, 86400, JSON.stringify(merged));
    }
    /** Get full presence data for a user. Returns null if absent. */
    async getPresence(userId) {
        const raw = await this.client.get(`presence:${userId}`);
        if (!raw)
            return null;
        try {
            return JSON.parse(raw);
        }
        catch {
            return null;
        }
    }
    /** Update only lastActivity timestamp (called from HEARTBEAT). */
    async touchActivity(userId) {
        const key = `presence:${userId}`;
        const raw = await this.client.get(key);
        if (!raw)
            return;
        try {
            const p = JSON.parse(raw);
            p.lastActivity = Date.now();
            await this.client.setex(key, 86400, JSON.stringify(p));
        }
        catch { /* ignore */ }
    }
    /** @deprecated Utiliser setPresence() à la place. Conservé pour compatibilité transitoire. */
    async setUserStatus(userId, status, customStatus) {
        await this.setPresence(userId, {
            status,
            chosenStatus: status,
            text: customStatus ?? null,
            lastActivity: Date.now(),
        });
    }
    /** @deprecated Utiliser getPresence() à la place. */
    async getUserStatus(userId) {
        const isOnline = await this.isUserOnline(userId);
        if (!isOnline)
            return { status: 'offline', customStatus: null };
        const p = await this.getPresence(userId);
        return { status: p?.status ?? 'online', customStatus: p?.text ?? null };
    }
    /** Returns presence info for multiple users — uses Redis pipeline (2 cmds per user). */
    async getBulkPresence(userIds) {
        if (userIds.length === 0)
            return [];
        const pipeline = this.client.multi();
        for (const uid of userIds) {
            pipeline.get(`presence:${uid}`);
            pipeline.scard(`user:sockets:${uid}`);
        }
        const results = await pipeline.exec();
        return userIds.map((userId, i) => {
            const raw = results?.[i * 2]?.[1];
            const scount = results?.[i * 2 + 1]?.[1] || 0;
            if (!raw || scount === 0)
                return { userId, status: 'offline', customStatus: null, emoji: null };
            try {
                const p = JSON.parse(raw);
                const visibleStatus = p.status === 'invisible' ? 'offline' : p.status;
                return { userId, status: visibleStatus, customStatus: p.text, emoji: p.emoji };
            }
            catch {
                return { userId, status: 'offline', customStatus: null, emoji: null };
            }
        });
    }
    async setSession(userId, sessionId, data, ttl = 86400) {
        const key = `session:${userId}:${sessionId}`;
        await this.client.setex(key, ttl, JSON.stringify(data));
        await this.client.sadd(`user:sessions:${userId}`, sessionId);
    }
    async getSession(userId, sessionId) {
        const key = `session:${userId}:${sessionId}`;
        const data = await this.client.get(key);
        return data ? JSON.parse(data) : null;
    }
    async deleteSession(userId, sessionId) {
        const key = `session:${userId}:${sessionId}`;
        await this.client.del(key);
        await this.client.srem(`user:sessions:${userId}`, sessionId);
    }
    async setTyping(conversationId, userId) {
        const key = `typing:${conversationId}`;
        await this.client.hset(key, userId, Date.now().toString());
        await this.client.expire(key, 5);
    }
    async removeTyping(conversationId, userId) {
        await this.client.hdel(`typing:${conversationId}`, userId);
    }
    async publish(channel, message) {
        await this.publisher.publish(channel, JSON.stringify(message));
    }
    async subscribe(channel, callback) {
        await this.subscriber.subscribe(channel);
        this.subscriber.on('message', (ch, msg) => {
            if (ch === channel)
                callback(msg);
        });
    }
    // Accès générique clé/valeur (pour codes éphémères, etc.)
    async set(key, value, ttl) {
        if (ttl) {
            await this.client.setex(key, ttl, value);
        }
        else {
            await this.client.set(key, value);
        }
    }
    async get(key) {
        return this.client.get(key);
    }
    async del(key) {
        await this.client.del(key);
    }
    // ============ USER ROOMS (persistance reconnexion) ============
    async saveUserRooms(userId, serverIds, channelIds) {
        await this.client.setex(`rooms:${userId}`, 7 * 24 * 3600, JSON.stringify({ serverIds, channelIds }));
    }
    async getUserRooms(userId) {
        const data = await this.client.get(`rooms:${userId}`);
        if (!data)
            return null;
        try {
            return JSON.parse(data);
        }
        catch {
            return null;
        }
    }
    // ============ IP BAN ============
    async banIP(ip, reason, bannedBy) {
        const data = JSON.stringify({ reason, bannedBy, bannedAt: new Date().toISOString() });
        await this.client.hset('banned:ips', ip, data);
    }
    async unbanIP(ip) {
        await this.client.hdel('banned:ips', ip);
    }
    async isIPBanned(ip) {
        return (await this.client.hexists('banned:ips', ip)) === 1;
    }
    async getBannedIPs() {
        const all = await this.client.hgetall('banned:ips');
        return Object.entries(all).map(([ip, data]) => {
            const parsed = JSON.parse(data);
            return { ip, ...parsed };
        });
    }
    // ============ RATE LIMIT STATS ============
    async incrementRateLimit(ip, window) {
        const key = `ratelimit:${ip}`;
        const count = await this.client.incr(key);
        if (count === 1)
            await this.client.expire(key, window);
        return count;
    }
    async incrementRateLimitWithKey(key, windowSeconds) {
        const count = await this.client.incr(key);
        if (count === 1)
            await this.client.expire(key, windowSeconds);
        return count;
    }
    async getRateLimitCount(ip) {
        const val = await this.client.get(`ratelimit:${ip}`);
        return val ? parseInt(val) : 0;
    }
    async getRateLimitStats() {
        const blocked = await this.client.get('ratelimit:total_blocked') || '0';
        const keys = await this.client.keys('ratelimit:*');
        const activeWindows = keys.filter(k => k !== 'ratelimit:total_blocked').length;
        return { totalBlocked: parseInt(blocked), activeWindows };
    }
    async incrementRateLimitBlocked() {
        await this.client.incr('ratelimit:total_blocked');
    }
    // ============ PENDING DM PINGS ============
    /**
     * Incrémente le compteur de pings non-lus pour un utilisateur hors ligne.
     * Stocké sous la clé hash `pending_pings:{userId}` avec champ = conversationId.
     */
    async addPendingPing(userId, conversationId, senderName) {
        const key = `pending_pings:${userId}`;
        await this.client.hincrby(key, conversationId, 1);
        // Stocker aussi le nom du dernier expéditeur
        await this.client.hset(`pending_pings_meta:${userId}`, conversationId, senderName);
        // TTL de 30 jours
        await this.client.expire(key, 30 * 24 * 60 * 60);
        await this.client.expire(`pending_pings_meta:${userId}`, 30 * 24 * 60 * 60);
    }
    /**
     * Récupère les pings en attente pour un utilisateur.
     * Retourne { [conversationId]: { count, senderName } }
     */
    async getPendingPings(userId) {
        const counts = await this.client.hgetall(`pending_pings:${userId}`);
        const meta = await this.client.hgetall(`pending_pings_meta:${userId}`);
        if (!counts)
            return {};
        const result = {};
        for (const [convId, count] of Object.entries(counts)) {
            result[convId] = { count: parseInt(count), senderName: meta?.[convId] || '' };
        }
        return result;
    }
    /**
     * Supprime tous les pings en attente d'un utilisateur (après qu'il s'est reconnecté).
     */
    async clearPendingPings(userId) {
        await this.client.del(`pending_pings:${userId}`);
        await this.client.del(`pending_pings_meta:${userId}`);
    }
    async disconnect() {
        await this.client.quit();
        await this.subscriber.quit();
        await this.publisher.quit();
    }
    // ============ ANOMALY DETECTION ============
    /**
     * Incrémente un compteur avec sliding window (INCR + EXPIRE one-time).
     * Retourne le nouveau total dans la fenêtre.
     */
    async anomalyIncrReq(key, windowSecs) {
        const count = await this.client.incr(key);
        if (count === 1)
            await this.client.expire(key, windowSecs);
        return count;
    }
    /**
     * Enregistre un endpoint unique dans un SET Redis et retourne le nombre d'endpoints distincts.
     * Le SET expire après windowSecs (positionné à la première insertion).
     */
    async anomalyAddEndpoint(key, endpoint, windowSecs) {
        const added = await this.client.sadd(key, endpoint);
        if (added === 1) {
            // Refresh TTL only on first insertion of each member (cheap: 1 EXPIRE instead of every call)
            const ttl = await this.client.ttl(key);
            if (ttl === -1)
                await this.client.expire(key, windowSecs);
        }
        return this.client.scard(key);
    }
    /** Expose le client ioredis brut (nécessaire pour rate-limiter-flexible et redis-adapter). */
    getRawClient() {
        return this.client;
    }
}
exports.RedisClient = RedisClient;
//# sourceMappingURL=redis.js.map