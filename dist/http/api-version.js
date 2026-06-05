"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_API_VERSIONS = exports.LATEST_API_VERSION = void 0;
exports.apiVersionMiddleware = apiVersionMiddleware;
// Dernière version de l'API exposée. À incrémenter en même temps que SUPPORTED_API_VERSIONS
// quand une nouvelle version est introduite.
exports.LATEST_API_VERSION = 1;
// Versions actuellement supportées par le gateway.
// /api/<path>       → version latest (par défaut)
// /api/v1/<path>    → version 1 (explicite)
// /api/v<N>/<path>  → version N si présente dans cette liste, sinon 400.
exports.SUPPORTED_API_VERSIONS = [1];
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
function apiVersionMiddleware(req, res, next) {
    const match = req.url.match(VERSION_PREFIX_RE);
    if (match) {
        const version = parseInt(match[1], 10);
        if (!exports.SUPPORTED_API_VERSIONS.includes(version)) {
            res.setHeader('X-API-Supported-Versions', exports.SUPPORTED_API_VERSIONS.join(','));
            return res.status(400).json({
                error: `Version d'API non supportée: v${version}`,
                supported: exports.SUPPORTED_API_VERSIONS.map((v) => `v${v}`),
            });
        }
        req.apiVersion = version;
        // Strip le préfixe de version de l'URL : /api/v1/users → /api/users
        req.url = req.url.replace(VERSION_PREFIX_RE, '/api');
    }
    else {
        req.apiVersion = exports.LATEST_API_VERSION;
    }
    res.setHeader('X-API-Version', `v${req.apiVersion}`);
    next();
}
//# sourceMappingURL=api-version.js.map