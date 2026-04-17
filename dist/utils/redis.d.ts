import Redis from 'ioredis';
export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
}
export declare class RedisClient {
    private client;
    private subscriber;
    private publisher;
    constructor(config: RedisConfig);
    setUserOnline(userId: string, socketId: string): Promise<void>;
    setUserOffline(userId: string, socketId: string): Promise<void>;
    isUserOnline(userId: string): Promise<boolean>;
    getUserSocketId(userId: string): Promise<string | null>;
    /** Stores the full presence status (online/idle/dnd/invisible) for a user. */
    setUserStatus(userId: string, status: string, customStatus?: string | null): Promise<void>;
    /** Returns the stored presence status for a user, falling back to online/offline from Redis. */
    getUserStatus(userId: string): Promise<{
        status: string;
        customStatus: string | null;
    }>;
    /** Returns presence info for multiple users at once. */
    getBulkPresence(userIds: string[]): Promise<Array<{
        userId: string;
        status: string;
        customStatus: string | null;
    }>>;
    setSession(userId: string, sessionId: string, data: object, ttl?: number): Promise<void>;
    getSession(userId: string, sessionId: string): Promise<object | null>;
    deleteSession(userId: string, sessionId: string): Promise<void>;
    setTyping(conversationId: string, userId: string): Promise<void>;
    removeTyping(conversationId: string, userId: string): Promise<void>;
    publish(channel: string, message: object): Promise<void>;
    subscribe(channel: string, callback: (message: string) => void): Promise<void>;
    set(key: string, value: string, ttl?: number): Promise<void>;
    get(key: string): Promise<string | null>;
    del(key: string): Promise<void>;
    banIP(ip: string, reason: string, bannedBy: string): Promise<void>;
    unbanIP(ip: string): Promise<void>;
    isIPBanned(ip: string): Promise<boolean>;
    getBannedIPs(): Promise<Array<{
        ip: string;
        reason: string;
        bannedBy: string;
        bannedAt: string;
    }>>;
    incrementRateLimit(ip: string, window: number): Promise<number>;
    incrementRateLimitWithKey(key: string, windowSeconds: number): Promise<number>;
    getRateLimitCount(ip: string): Promise<number>;
    getRateLimitStats(): Promise<{
        totalBlocked: number;
        activeWindows: number;
    }>;
    incrementRateLimitBlocked(): Promise<void>;
    /**
     * Incrémente le compteur de pings non-lus pour un utilisateur hors ligne.
     * Stocké sous la clé hash `pending_pings:{userId}` avec champ = conversationId.
     */
    addPendingPing(userId: string, conversationId: string, senderName: string): Promise<void>;
    /**
     * Récupère les pings en attente pour un utilisateur.
     * Retourne { [conversationId]: { count, senderName } }
     */
    getPendingPings(userId: string): Promise<Record<string, {
        count: number;
        senderName: string;
    }>>;
    /**
     * Supprime tous les pings en attente d'un utilisateur (après qu'il s'est reconnecté).
     */
    clearPendingPings(userId: string): Promise<void>;
    disconnect(): Promise<void>;
    /** Expose le client ioredis brut (nécessaire pour rate-limiter-flexible et redis-adapter). */
    getRawClient(): Redis;
}
//# sourceMappingURL=redis.d.ts.map