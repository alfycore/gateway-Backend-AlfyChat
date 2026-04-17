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
    /** Stores the full presence status (online/idle/dnd/invisible) for a user. */
    async setUserStatus(userId, status, customStatus) {
        await this.client.hset('user:status', userId, status);
        if (customStatus !== undefined) {
            if (customStatus === null) {
                await this.client.hdel('user:customstatus', userId);
            }
            else {
                await this.client.hset('user:customstatus', userId, customStatus);
            }
        }
    }
    /** Returns the stored presence status for a user, falling back to online/offline from Redis. */
    async getUserStatus(userId) {
        const isOnline = await this.isUserOnline(userId);
        if (!isOnline)
            return { status: 'offline', customStatus: null };
        const status = (await this.client.hget('user:status', userId)) || 'online';
        const customStatus = (await this.client.hget('user:customstatus', userId)) ?? null;
        return { status, customStatus };
    }
    /** Returns presence info for multiple users at once. */
    async getBulkPresence(userIds) {
        if (userIds.length === 0)
            return [];
        return Promise.all(userIds.map(async (userId) => {
            const { status, customStatus } = await this.getUserStatus(userId);
            return { userId, status, customStatus };
        }));
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
    /** Expose le client ioredis brut (nécessaire pour rate-limiter-flexible et redis-adapter). */
    getRawClient() {
        return this.client;
    }
}
exports.RedisClient = RedisClient;
//# sourceMappingURL=redis.js.map