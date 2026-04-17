// ==========================================
// ALFYCHAT - GATEWAY CONFIG / ENV
// Constantes d'environnement centralisées.
// ==========================================

import dotenv from 'dotenv';
dotenv.config();

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET manquant — définissez-le dans .env (openssl rand -hex 64). Refus de démarrer avec un secret par défaut.');
}

export const JWT_SECRET = process.env.JWT_SECRET;
export const IS_PRODUCTION = process.env.NODE_ENV === 'production';
export const IS_DEV = process.env.NODE_ENV === 'development';

export const PORT = process.env.PORT || 3000;

// ── URLs microservices ──────────────────────────────────────────────
export const USERS_URL = process.env.USERS_SERVICE_URL || 'https://users.alfychat.eu';
export const MESSAGES_URL = process.env.MESSAGES_SERVICE_URL || 'https://messages.alfychat.eu';
export const FRIENDS_URL = process.env.FRIENDS_SERVICE_URL || 'https://friends.s.backend.alfychat.app';
export const CALLS_URL = process.env.CALLS_SERVICE_URL || 'https://calls.s.backend.alfychat.app';
export const SERVERS_URL = process.env.SERVERS_SERVICE_URL || 'https://servers.s.backend.alfychat.app';
export const BOTS_URL = process.env.BOTS_SERVICE_URL || 'https://bots.s.backend.alfychat.app';
export const MEDIA_URL = process.env.MEDIA_SERVICE_URL || 'https://media.s.backend.alfychat.app';
export const SERVERHOSTING_URL = process.env.SERVERHOSTING_SERVICE_URL || 'http://localhost:3008';
export const SUBSCRIPTIONS_URL = process.env.SUBSCRIPTIONS_SERVICE_URL || 'http://localhost:3009';

export const INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'alfychat-internal-secret-dev';

// ── Rate limiting ───────────────────────────────────────────────────
export const RATE_LIMIT_ANON  = parseInt(process.env.RATE_LIMIT_ANON  || '20');
export const RATE_LIMIT_USER  = parseInt(process.env.RATE_LIMIT_USER  || '150');
export const RATE_LIMIT_ADMIN = parseInt(process.env.RATE_LIMIT_ADMIN || '500');
export const RATE_LIMIT_WINDOW = 1;

export const RATE_LIMIT_AUTH_POINTS = parseInt(process.env.RATE_LIMIT_AUTH_POINTS || '30');
export const RATE_LIMIT_AUTH_WINDOW = parseInt(process.env.RATE_LIMIT_AUTH_WINDOW || '300');
export const AUTH_BRUTEFORCE_PATHS = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/verify-2fa',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
];

// ── Trusted reverse-proxy IPs ───────────────────────────────────────
export const TRUSTED_PROXIES = new Set(
  (process.env.TRUSTED_PROXIES || '127.0.0.1,::1').split(',').map((s) => s.trim()).filter(Boolean)
);

// ── Regex utilitaires ───────────────────────────────────────────────
export const IP_ENDPOINT_RE = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

// ── CORS ────────────────────────────────────────────────────────────
export const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:4000')
  .split(',')
  .map((o) => o.trim());

// ── Email SMTP ──────────────────────────────────────────────────────
// ADMIN_ALERT_EMAILS : liste d'emails séparés par des virgules qui reçoivent les alertes de dégradation
export const ADMIN_ALERT_EMAILS: string[] = (process.env.ADMIN_ALERT_EMAILS || '')
  .split(',')
  .map((e) => e.trim())
  .filter(Boolean);
