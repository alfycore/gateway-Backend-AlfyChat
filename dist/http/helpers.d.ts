import express from 'express';
import { ServiceType } from '../utils/service-registry';
/** Extract client IP, trusting X-Forwarded-For only from known proxies */
export declare function getClientIP(req: express.Request): string;
/** Decode userId from Authorization header (no throw) */
export declare function extractUserIdFromJWT(authHeader: string | undefined): string | null;
/** Parse JSON safely — returns null if body is empty or not valid JSON */
export declare function safeJson(response: Response): Promise<any>;
/**
 * Best-effort service URL via registry. Falls back to env-var URL.
 * In dev, always returns the fallback (.env / localhost).
 */
export declare function getServiceUrl(serviceType: ServiceType, fallback: string): string;
/** Rewrite Express URL for a server-node: /api/servers/:id/X → /X */
export declare function rewriteNodePath(req: express.Request, serverId: string): string;
//# sourceMappingURL=helpers.d.ts.map