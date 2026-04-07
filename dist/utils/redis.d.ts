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
    setUserOffline(userId: string): Promise<void>;
    isUserOnline(userId: string): Promise<boolean>;
    getUserSocketId(userId: string): Promise<string | null>;
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
    disconnect(): Promise<void>;
}
//# sourceMappingURL=redis.d.ts.map