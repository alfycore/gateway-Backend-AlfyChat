import Redis from 'ioredis';
export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
}
export interface PresenceData {
    status: string;
    chosenStatus: string;
    emoji: string | null;
    text: string | null;
    lastActivity: number;
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
    /** Set full presence data for a user. TTL = 24h so it survives short disconnects. */
    setPresence(userId: string, data: Partial<PresenceData>): Promise<void>;
    /** Get full presence data for a user. Returns null if absent. */
    getPresence(userId: string): Promise<PresenceData | null>;
    /** Update only lastActivity timestamp (called from HEARTBEAT). */
    touchActivity(userId: string): Promise<void>;
    /** @deprecated Utiliser setPresence() à la place. Conservé pour compatibilité transitoire. */
    setUserStatus(userId: string, status: string, customStatus?: string | null): Promise<void>;
    /** @deprecated Utiliser getPresence() à la place. */
    getUserStatus(userId: string): Promise<{
        status: string;
        customStatus: string | null;
    }>;
    /** Returns presence info for multiple users — uses Redis pipeline (2 cmds per user). */
    getBulkPresence(userIds: string[]): Promise<Array<{
        userId: string;
        status: string;
        customStatus: string | null;
        emoji: string | null;
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
    saveUserRooms(userId: string, serverIds: string[], channelIds: string[]): Promise<void>;
    getUserRooms(userId: string): Promise<{
        serverIds: string[];
        channelIds: string[];
    } | null>;
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
    /**
     * Incrémente un compteur avec sliding window (INCR + EXPIRE one-time).
     * Retourne le nouveau total dans la fenêtre.
     */
    anomalyIncrReq(key: string, windowSecs: number): Promise<number>;
    /**
     * Enregistre un endpoint unique dans un SET Redis et retourne le nombre d'endpoints distincts.
     * Le SET expire après windowSecs (positionné à la première insertion).
     */
    anomalyAddEndpoint(key: string, endpoint: string, windowSecs: number): Promise<number>;
    /** Expose le client ioredis brut (nécessaire pour rate-limiter-flexible et redis-adapter). */
    getRawClient(): Redis;
}
//# sourceMappingURL=redis.d.ts.map