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
        this.client.on('error', (err) => logger_1.logger.error('Redis error:', err));
    }
    async setUserOnline(userId, socketId) {
        await this.client.hset('online:users', userId, socketId);
        await this.client.sadd('online:list', userId);
    }
    async setUserOffline(userId) {
        await this.client.hdel('online:users', userId);
        await this.client.srem('online:list', userId);
    }
    async isUserOnline(userId) {
        return (await this.client.sismember('online:list', userId)) === 1;
    }
    async getUserSocketId(userId) {
        return this.client.hget('online:users', userId);
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
    async disconnect() {
        await this.client.quit();
        await this.subscriber.quit();
        await this.publisher.quit();
    }
}
exports.RedisClient = RedisClient;
//# sourceMappingURL=redis.js.map