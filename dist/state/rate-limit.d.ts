/** userId → array of timestamps (last N messages) */
export declare const messageRateLimit: Map<string, number[]>;
export declare const MSG_RATE_WINDOW = 10000;
export declare const MSG_RATE_MAX = 10;
/** SERVER_JOIN / SERVER_LEAVE rate limit */
export declare const serverJoinRateLimit: Map<string, number[]>;
export declare const JOIN_RATE_WINDOW = 60000;
export declare const JOIN_RATE_MAX = 5;
export declare function checkServerJoinRate(userId: string): boolean;
//# sourceMappingURL=rate-limit.d.ts.map