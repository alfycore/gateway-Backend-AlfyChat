"use strict";
// ==========================================
// ALFYCHAT — Anomaly detection middleware
//
// Tracks per-subject (userId or IP) across a sliding window:
//   • Request rate (req/60s)
//   • Endpoint diversity (unique paths/60s)
//   • 4xx error ratio (errors / total requests)
//
// When the combined suspicion score crosses SCORE_ALERT_THRESHOLD a
// SECURITY_ANOMALY log entry is emitted (no ban, no kick — observable first).
//
// Hook in HTTP:  app.use(anomalyMiddleware) — after rate-limit
// Hook in WS:    attachAnomalyWsHooks(socket, userId) — after auth
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.anomalyMiddleware = anomalyMiddleware;
exports.attachAnomalyWsHooks = attachAnomalyWsHooks;
const runtime_1 = require("../state/runtime");
const logger_1 = require("../utils/logger");
// ── Tunable constants ─────────────────────────────────────────────────────
const WINDOW_SECS = 60; // sliding window in seconds
const REQ_THRESHOLD = 150; // requests per window before suspicion
const ENDPOINT_THRESHOLD = 25; // unique endpoints per window before suspicion
const ERR4XX_THRESHOLD = 0.50; // fraction of 4xx over total (if ≥ ERR4XX_MIN_REQS)
const ERR4XX_MIN_REQS = 20; // minimum requests before applying error-ratio check
const SCORE_ALERT = 2.0; // suspicion score ≥ this → SECURITY_ANOMALY log
const COOLDOWN_SECS = 300; // seconds between repeated alerts for the same subject
// WS events that are pure infrastructure — never counted toward anomaly score
const WS_IGNORED_EVENTS = new Set([
    'ping', 'pong', 'heartbeat', 'connect', 'disconnect', 'error',
    'presence:update', 'typing:start', 'typing:stop',
]);
// ── Redis key helpers ─────────────────────────────────────────────────────
const KEYS = {
    reqs: (id) => `anm:req:${id}`,
    eps: (id) => `anm:ep:${id}`,
    errs: (id) => `anm:err:${id}`,
    alerted: (id) => `anm:alt:${id}`,
};
// ── Core scoring logic ────────────────────────────────────────────────────
async function recordAndScore(subject, endpoint, isError) {
    const r = runtime_1.runtime.redis;
    if (!r)
        return;
    try {
        const [reqCount, epCount] = await Promise.all([
            r.anomalyIncrReq(KEYS.reqs(subject), WINDOW_SECS),
            r.anomalyAddEndpoint(KEYS.eps(subject), endpoint, WINDOW_SECS),
        ]);
        const errCount = isError ? await r.anomalyIncrReq(KEYS.errs(subject), WINDOW_SECS) : 0;
        // Suspicion score — each factor can contribute up to 1 (or more for extreme values)
        let score = 0;
        if (reqCount > REQ_THRESHOLD) {
            score += reqCount / REQ_THRESHOLD;
        }
        if (epCount > ENDPOINT_THRESHOLD) {
            score += epCount / ENDPOINT_THRESHOLD;
        }
        if (reqCount >= ERR4XX_MIN_REQS) {
            const errRate = errCount / reqCount;
            if (errRate > ERR4XX_THRESHOLD) {
                score += errRate / ERR4XX_THRESHOLD;
            }
        }
        if (score >= SCORE_ALERT) {
            const alreadyAlerted = await r.get(KEYS.alerted(subject));
            if (!alreadyAlerted) {
                await r.set(KEYS.alerted(subject), '1', COOLDOWN_SECS);
                logger_1.logger.warn({
                    SECURITY_ANOMALY: true,
                    subject,
                    score: +score.toFixed(2),
                    reqCount,
                    epCount,
                    errCount,
                    windowSecs: WINDOW_SECS,
                }, `SECURITY_ANOMALY: comportement suspect détecté (${subject}, score=${score.toFixed(2)})`);
            }
        }
    }
    catch {
        // Never let anomaly tracking crash the request path
    }
}
// ── Subject extraction helpers ────────────────────────────────────────────
/** Fast JWT payload decode (no signature verification — already done by auth middleware). */
function jwtSubject(authHeader) {
    if (!authHeader?.startsWith('Bearer '))
        return null;
    try {
        const part = authHeader.split('.')[1];
        const payload = JSON.parse(Buffer.from(part, 'base64url').toString());
        return payload.userId || payload.id || null;
    }
    catch {
        return null;
    }
}
function ipSubject(req) {
    const xfwd = req.headers['x-forwarded-for'];
    const raw = Array.isArray(xfwd) ? xfwd[0] : xfwd?.split(',')[0]?.trim();
    return raw || req.socket.remoteAddress || 'unknown';
}
// ── HTTP middleware ───────────────────────────────────────────────────────
/**
 * Attach after rate-limit middleware. Records request stats asynchronously
 * once the response has been flushed — zero impact on response latency.
 */
function anomalyMiddleware(req, res, next) {
    next();
    res.on('finish', () => {
        // Skip health-check / monitoring noise
        if (req.path === '/health' || req.path === '/api/health')
            return;
        const subject = jwtSubject(req.headers.authorization) ?? ipSubject(req);
        const endpoint = `${req.method} ${req.route?.path || req.path}`;
        const is4xx = res.statusCode >= 400 && res.statusCode < 500;
        recordAndScore(subject, endpoint, is4xx).catch(() => { });
    });
}
// ── WebSocket hooks ───────────────────────────────────────────────────────
/**
 * Attach to a socket after successful authentication.
 * Counts non-trivial WS events toward the anomaly score of the userId.
 */
function attachAnomalyWsHooks(socket, userId) {
    socket.onAny((event) => {
        if (WS_IGNORED_EVENTS.has(event))
            return;
        recordAndScore(userId, `WS:${event}`, false).catch(() => { });
    });
}
//# sourceMappingURL=anomaly.js.map