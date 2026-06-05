/** Check if DM is blocked between two users (cached) */
export declare function isDmBlocked(senderId: string, recipientId: string): Promise<boolean>;
/** Invalidate block cache when a block/unblock event occurs */
export declare function invalidateBlockCache(u1: string, u2: string): void;
//# sourceMappingURL=block-cache.d.ts.map