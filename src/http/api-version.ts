import type { Request, Response, NextFunction } from 'express';

// Dernière version de l'API exposée. À incrémenter en même temps que SUPPORTED_API_VERSIONS
// quand une nouvelle version est introduite.
export const LATEST_API_VERSION = 1;

// Versions actuellement supportées par le gateway.
// /api/<path>       → version latest (par défaut)
// /api/v1/<path>    → version 1 (explicite)
// /api/v<N>/<path>  → version N si présente dans cette liste, sinon 400.
export const SUPPORTED_API_VERSIONS: ReadonlyArray<number> = [1];

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiVersion?: number;
    }
  }
}

const VERSION_PREFIX_RE = /^\/api\/v(\d+)(?=\/|$)/i;

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
export function apiVersionMiddleware(req: Request, res: Response, next: NextFunction) {
  const match = req.url.match(VERSION_PREFIX_RE);
  if (match) {
    const version = parseInt(match[1], 10);
    if (!SUPPORTED_API_VERSIONS.includes(version)) {
      res.setHeader('X-API-Supported-Versions', SUPPORTED_API_VERSIONS.join(','));
      return res.status(400).json({
        error: `Version d'API non supportée: v${version}`,
        supported: SUPPORTED_API_VERSIONS.map((v) => `v${v}`),
      });
    }
    req.apiVersion = version;
    // Strip le préfixe de version de l'URL : /api/v1/users → /api/users
    req.url = req.url.replace(VERSION_PREFIX_RE, '/api');
  } else {
    req.apiVersion = LATEST_API_VERSION;
  }
  res.setHeader('X-API-Version', `v${req.apiVersion}`);
  next();
}
