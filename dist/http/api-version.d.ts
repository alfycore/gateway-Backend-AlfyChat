import type { Request, Response, NextFunction } from 'express';
export declare const LATEST_API_VERSION = 1;
export declare const SUPPORTED_API_VERSIONS: ReadonlyArray<number>;
declare global {
    namespace Express {
        interface Request {
            apiVersion?: number;
        }
    }
}
/**
 * Normalise les URLs versionnées en URLs sans version avant le routing.
 *
 * Exemples :
 *   GET /api/v1/users/me  → req.url = /api/users/me, req.apiVersion = 1
 *   GET /api/v2/servers   → req.url = /api/servers,  req.apiVersion = 2
 *   GET /api/users/me     → req.url inchangé,        req.apiVersion = LATEST_API_VERSION
 *
 * La version résolue est renvoyée dans l'entête `X-API-Version`.
 */
export declare function apiVersionMiddleware(req: Request, res: Response, next: NextFunction): Response<any, Record<string, any>> | undefined;
//# sourceMappingURL=api-version.d.ts.map