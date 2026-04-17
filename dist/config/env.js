"use strict";
// ==========================================
// ALFYCHAT - GATEWAY CONFIG / ENV
// Constantes d'environnement centralisées.
// ==========================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ADMIN_ALERT_EMAILS = exports.allowedOrigins = exports.IP_ENDPOINT_RE = exports.TRUSTED_PROXIES = exports.AUTH_BRUTEFORCE_PATHS = exports.RATE_LIMIT_AUTH_WINDOW = exports.RATE_LIMIT_AUTH_POINTS = exports.RATE_LIMIT_WINDOW = exports.RATE_LIMIT_ADMIN = exports.RATE_LIMIT_USER = exports.RATE_LIMIT_ANON = exports.INTERNAL_SECRET = exports.SUBSCRIPTIONS_URL = exports.SERVERHOSTING_URL = exports.MEDIA_URL = exports.BOTS_URL = exports.SERVERS_URL = exports.CALLS_URL = exports.FRIENDS_URL = exports.MESSAGES_URL = exports.USERS_URL = exports.PORT = exports.IS_DEV = exports.IS_PRODUCTION = exports.JWT_SECRET = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET manquant — définissez-le dans .env (openssl rand -hex 64). Refus de démarrer avec un secret par défaut.');
}
exports.JWT_SECRET = process.env.JWT_SECRET;
exports.IS_PRODUCTION = process.env.NODE_ENV === 'production';
exports.IS_DEV = process.env.NODE_ENV === 'development';
exports.PORT = process.env.PORT || 3000;
// ── URLs microservices ──────────────────────────────────────────────
exports.USERS_URL = process.env.USERS_SERVICE_URL || 'https://users.alfychat.eu';
exports.MESSAGES_URL = process.env.MESSAGES_SERVICE_URL || 'https://messages.alfychat.eu';
exports.FRIENDS_URL = process.env.FRIENDS_SERVICE_URL || 'https://friends.s.backend.alfychat.app';
exports.CALLS_URL = process.env.CALLS_SERVICE_URL || 'https://calls.s.backend.alfychat.app';
exports.SERVERS_URL = process.env.SERVERS_SERVICE_URL || 'https://servers.s.backend.alfychat.app';
exports.BOTS_URL = process.env.BOTS_SERVICE_URL || 'https://bots.s.backend.alfychat.app';
exports.MEDIA_URL = process.env.MEDIA_SERVICE_URL || 'https://media.s.backend.alfychat.app';
exports.SERVERHOSTING_URL = process.env.SERVERHOSTING_SERVICE_URL || 'http://localhost:3008';
exports.SUBSCRIPTIONS_URL = process.env.SUBSCRIPTIONS_SERVICE_URL || 'http://localhost:3009';
exports.INTERNAL_SECRET = process.env.INTERNAL_SECRET || 'alfychat-internal-secret-dev';
// ── Rate limiting ───────────────────────────────────────────────────
exports.RATE_LIMIT_ANON = parseInt(process.env.RATE_LIMIT_ANON || '20');
exports.RATE_LIMIT_USER = parseInt(process.env.RATE_LIMIT_USER || '150');
exports.RATE_LIMIT_ADMIN = parseInt(process.env.RATE_LIMIT_ADMIN || '500');
exports.RATE_LIMIT_WINDOW = 1;
exports.RATE_LIMIT_AUTH_POINTS = parseInt(process.env.RATE_LIMIT_AUTH_POINTS || '10');
exports.RATE_LIMIT_AUTH_WINDOW = parseInt(process.env.RATE_LIMIT_AUTH_WINDOW || '900');
exports.AUTH_BRUTEFORCE_PATHS = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/verify-2fa',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
];
// ── Trusted reverse-proxy IPs ───────────────────────────────────────
exports.TRUSTED_PROXIES = new Set((process.env.TRUSTED_PROXIES || '127.0.0.1,::1').split(',').map((s) => s.trim()).filter(Boolean));
// ── Regex utilitaires ───────────────────────────────────────────────
exports.IP_ENDPOINT_RE = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
// ── CORS ────────────────────────────────────────────────────────────
exports.allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:4000')
    .split(',')
    .map((o) => o.trim());
// ── Email SMTP ──────────────────────────────────────────────────────
// ADMIN_ALERT_EMAILS : liste d'emails séparés par des virgules qui reçoivent les alertes de dégradation
exports.ADMIN_ALERT_EMAILS = (process.env.ADMIN_ALERT_EMAILS || '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
//# sourceMappingURL=env.js.map