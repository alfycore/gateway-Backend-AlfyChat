"use strict";
// ==========================================
// ALFYCHAT — Admin Guard Middleware
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAdmin = requireAdmin;
const helpers_1 = require("../http/helpers");
const env_1 = require("../config/env");
/**
 * Verifies the request comes from an admin user.
 * Returns the admin userId on success, null (and sends HTTP error) on failure.
 */
async function requireAdmin(req, res) {
    const userId = (0, helpers_1.extractUserIdFromJWT)(req.headers.authorization);
    if (!userId) {
        res.status(401).json({ error: 'Non authentifié' });
        return null;
    }
    try {
        const userRes = await fetch(`${(0, helpers_1.getServiceUrl)('users', env_1.USERS_URL)}/users/${userId}`, {
            headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
        });
        const userData = await (0, helpers_1.safeJson)(userRes);
        if (!userData || userData.role !== 'admin') {
            res.status(403).json({ error: 'Accès refusé' });
            return null;
        }
    }
    catch {
        res.status(502).json({ error: 'Service indisponible' });
        return null;
    }
    return userId;
}
//# sourceMappingURL=admin-guard.js.map