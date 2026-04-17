/** Map<serviceId, sha256(rawKey)> — loaded from DB at startup */
export declare const serviceKeyHashes: Map<string, string>;
/** Blacklist of instances disabled/deleted by an admin */
export declare const bannedServiceIds: Set<string>;
/** Whitelist of IDs authorised to register (pre-registered by an admin) */
export declare const allowedServiceIds: Set<string>;
/** Generate a unique service key and its SHA-256 hash */
export declare function generateServiceKey(): {
    rawKey: string;
    hash: string;
};
/** Validate a service secret against stored hash or INTERNAL_SECRET fallback */
export declare function validateServiceSecret(id: string, secret: string): boolean;
//# sourceMappingURL=service-keys.d.ts.map