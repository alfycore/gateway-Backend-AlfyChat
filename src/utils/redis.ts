// ==========================================
// ALFYCHAT - REDIS CLIENT POUR GATEWAY
// ==========================================

import Redis from 'ioredis';
import { logger } from './logger';

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
}

export class RedisClient {
  private client: Redis;
  private subscriber: Redis;
  private publisher: Redis;

  constructor(config: RedisConfig) {
    const options = {
      host: config.host,
      port: config.port,
      password: config.password,
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
    };

    this.client = new Redis(options);
    this.subscriber = new Redis(options);
    this.publisher = new Redis(options);

    this.client.on('connect', () => logger.info('Redis client connecté'));
    this.client.on('error', (err) => logger.error('Redis error:', err));
  }

  async setUserOnline(userId: string, socketId: string): Promise<void> {
    await this.client.hset('online:users', userId, socketId);
    await this.client.sadd('online:list', userId);
  }

  async setUserOffline(userId: string): Promise<void> {
    await this.client.hdel('online:users', userId);
    await this.client.srem('online:list', userId);
  }

  async isUserOnline(userId: string): Promise<boolean> {
    return (await this.client.sismember('online:list', userId)) === 1;
  }

  async getUserSocketId(userId: string): Promise<string | null> {
    return this.client.hget('online:users', userId);
  }

  async setSession(userId: string, sessionId: string, data: object, ttl = 86400): Promise<void> {
    const key = `session:${userId}:${sessionId}`;
    await this.client.setex(key, ttl, JSON.stringify(data));
    await this.client.sadd(`user:sessions:${userId}`, sessionId);
  }

  async getSession(userId: string, sessionId: string): Promise<object | null> {
    const key = `session:${userId}:${sessionId}`;
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  async deleteSession(userId: string, sessionId: string): Promise<void> {
    const key = `session:${userId}:${sessionId}`;
    await this.client.del(key);
    await this.client.srem(`user:sessions:${userId}`, sessionId);
  }

  async setTyping(conversationId: string, userId: string): Promise<void> {
    const key = `typing:${conversationId}`;
    await this.client.hset(key, userId, Date.now().toString());
    await this.client.expire(key, 5);
  }

  async removeTyping(conversationId: string, userId: string): Promise<void> {
    await this.client.hdel(`typing:${conversationId}`, userId);
  }

  async publish(channel: string, message: object): Promise<void> {
    await this.publisher.publish(channel, JSON.stringify(message));
  }

  async subscribe(channel: string, callback: (message: string) => void): Promise<void> {
    await this.subscriber.subscribe(channel);
    this.subscriber.on('message', (ch, msg) => {
      if (ch === channel) callback(msg);
    });
  }

  // Accès générique clé/valeur (pour codes éphémères, etc.)
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.setex(key, ttl, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async disconnect(): Promise<void> {
    await this.client.quit();
    await this.subscriber.quit();
    await this.publisher.quit();
  }
}
