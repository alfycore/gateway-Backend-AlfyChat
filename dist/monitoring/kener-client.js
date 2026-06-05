"use strict";
// ==========================================
// ALFYCHAT — Kener v4 API client
// Publishes incidents when services transition to degraded/down and
// resolves them when they recover.
// ==========================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.SERVICE_TO_KENER_TAG = exports.KENER_ENABLED = void 0;
exports.createIncident = createIncident;
exports.addIncidentComment = addIncidentComment;
exports.setIncidentEnd = setIncidentEnd;
exports.handleStatusTransition = handleStatusTransition;
const logger_1 = require("../utils/logger");
const KENER_URL = (process.env.KENER_URL || 'https://status.alfychat.app').replace(/\/$/, '');
const KENER_TOKEN = process.env.KENER_API_TOKEN || '';
exports.KENER_ENABLED = Boolean(KENER_TOKEN);
// Gateway service name → Kener monitor tag. Keep in sync with monitors
// configured in Kener (see /api/v4/monitors).
exports.SERVICE_TO_KENER_TAG = {
    gateway: 'eu',
    website: 'ws',
    users: 'su1',
    messages: 'sm1',
    friends: 'sf1',
    calls: 'sc1',
    servers: 'ss1',
    bots: 'sb1',
    media: 'media3to',
};
async function kenerFetch(path, init = {}) {
    return fetch(`${KENER_URL}${path}`, {
        ...init,
        headers: {
            Authorization: `Bearer ${KENER_TOKEN}`,
            'Content-Type': 'application/json',
            ...(init.headers || {}),
        },
        signal: AbortSignal.timeout(8000),
    });
}
async function parseOrThrow(res, ctx) {
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Kener ${ctx} HTTP ${res.status}: ${body.slice(0, 200)}`);
    }
    return res.json();
}
async function createIncident(args) {
    const body = {
        title: args.title,
        start_date_time: args.startTs,
        incident_type: 'INCIDENT',
        monitors: [{ monitor_tag: args.monitorTag, impact: args.impact }],
    };
    const res = await kenerFetch('/api/v4/incidents', { method: 'POST', body: JSON.stringify(body) });
    const data = await parseOrThrow(res, 'createIncident');
    return data.incident;
}
/** State transitions are done via comments (INVESTIGATING → IDENTIFIED → MONITORING → RESOLVED). */
async function addIncidentComment(incidentId, state, comment) {
    const res = await kenerFetch(`/api/v4/incidents/${incidentId}/comments`, {
        method: 'POST',
        body: JSON.stringify({ comment, state, timestamp: Math.floor(Date.now() / 1000) }),
    });
    await parseOrThrow(res, 'addIncidentComment');
}
async function setIncidentEnd(incidentId, endTs) {
    const res = await kenerFetch(`/api/v4/incidents/${incidentId}`, {
        method: 'PATCH',
        body: JSON.stringify({ end_date_time: endTs }),
    });
    await parseOrThrow(res, 'setIncidentEnd');
}
// ── Active incidents tracker (in-memory, resets on process restart) ─────────
// serviceName → incidentId. Survives hot-reloads via globalThis.
const g = globalThis;
if (!g.__gw_kenerActiveIncidents)
    g.__gw_kenerActiveIncidents = {};
const activeIncidents = g.__gw_kenerActiveIncidents;
/**
 * Called by the monitoring cycle on each observed status transition.
 * Opens an incident on up→degraded/down and resolves it on any→up.
 */
async function handleStatusTransition(service, prev, next, reason) {
    if (!exports.KENER_ENABLED)
        return;
    const tag = exports.SERVICE_TO_KENER_TAG[service];
    if (!tag)
        return; // service not mapped to a Kener monitor — skip silently
    try {
        // Opening: transition into degraded or down, no active incident yet
        if ((next === 'down' || next === 'degraded') && prev !== next && !activeIncidents[service]) {
            const impact = next === 'down' ? 'DOWN' : 'DEGRADED';
            const label = next === 'down' ? 'hors ligne' : 'dégradé';
            const now = Math.floor(Date.now() / 1000);
            const incident = await createIncident({
                title: `${service} ${label}`,
                monitorTag: tag,
                impact,
                startTs: now,
            });
            activeIncidents[service] = incident.id;
            await addIncidentComment(incident.id, 'INVESTIGATING', reason
                ? `Détection automatique — ${reason}`
                : `Détection automatique du gateway : ${service} est ${label}.`);
            logger_1.logger.warn(`[Kener] Incident #${incident.id} ouvert pour ${service} (${impact})`);
            return;
        }
        // Escalation: degraded → down while incident already open
        if (next === 'down' && prev === 'degraded' && activeIncidents[service]) {
            await addIncidentComment(activeIncidents[service], 'IDENTIFIED', `Aggravation : ${service} est passé de dégradé à hors ligne.`);
            return;
        }
        // Recovery: back to up while incident is open
        if (next === 'up' && activeIncidents[service]) {
            const id = activeIncidents[service];
            const now = Math.floor(Date.now() / 1000);
            await addIncidentComment(id, 'RESOLVED', `Service rétabli : ${service} répond à nouveau normalement.`);
            await setIncidentEnd(id, now);
            delete activeIncidents[service];
            logger_1.logger.info(`[Kener] Incident #${id} résolu pour ${service}`);
            return;
        }
    }
    catch (err) {
        // Never let Kener hiccups crash the monitoring cycle.
        logger_1.logger.error({ err }, `[Kener] Échec traitement transition ${service} ${prev}→${next}`);
    }
}
//# sourceMappingURL=kener-client.js.map