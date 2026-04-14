// ==========================================
// ALFYCHAT — Admin Guard Middleware
// ==========================================

import express from 'express';
import { extractUserIdFromJWT, safeJson, getServiceUrl } from '../http/helpers';
import { USERS_URL } from '../config/env';

/**
 * Verifies the request comes from an admin user.
 * Returns the admin userId on success, null (and sends HTTP error) on failure.
 */
export async function requireAdmin(
  req: express.Request,
  res: express.Response,
): Promise<string | null> {
  const userId = extractUserIdFromJWT(req.headers.authorization);
  if (!userId) { res.status(401).json({ error: 'Non authentifié' }); return null; }
  try {
    const userRes = await fetch(`${getServiceUrl('users', USERS_URL)}/users/${userId}`, {
      headers: { ...(req.headers.authorization && { authorization: req.headers.authorization }) },
    });
    const userData = await safeJson(userRes) as any;
    if (!userData || userData.role !== 'admin') { res.status(403).json({ error: 'Accès refusé' }); return null; }
  } catch {
    res.status(502).json({ error: 'Service indisponible' });
    return null;
  }
  return userId;
}
