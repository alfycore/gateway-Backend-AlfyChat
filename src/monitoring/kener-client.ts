// ==========================================
// ALFYCHAT — Kener v4 API client
// Publishes incidents when services transition to degraded/down and
// resolves them when they recover.
// ==========================================

import { logger } from '../utils/logger';

type ServiceStatus = 'up' | 'degraded' | 'down';

export interface KenerMonitorImpact {
  monitor_tag: string;
  impact: 'UP' | 'DOWN' | 'DEGRADED';
}

export interface KenerIncident {
  id: number;
  title: string;
  start_date_time: number;
  end_date_time: number | null;
  state: string;
  status: string;
  incident_type: string;
  incident_source: string;
  monitors: KenerMonitorImpact[];
}

const KENER_URL   = (process.env.KENER_URL || 'https://status.alfychat.app').replace(/\/$/, '');
const KENER_TOKEN = process.env.KENER_API_TOKEN || '';
export const KENER_ENABLED = Boolean(KENER_TOKEN);

// Gateway service name → Kener monitor tag. Keep in sync with monitors
// configured in Kener (see /api/v4/monitors).
export const SERVICE_TO_KENER_TAG: Record<string, string> = {
  gateway:  'eu',
  website:  'ws',
  users:    'su1',
  messages: 'sm1',
  friends:  'sf1',
  calls:    'sc1',
  servers:  'ss1',
  bots:     'sb1',
  media:    'media3to',
};

async function kenerFetch(path: string, init: RequestInit = {}): Promise<Response> {
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

async function parseOrThrow(res: Response, ctx: string): Promise<any> {
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Kener ${ctx} HTTP ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

export async function createIncident(args: {
  title: string;
  monitorTag: string;
  impact: 'DOWN' | 'DEGRADED';
  startTs: number;
}): Promise<KenerIncident> {
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
export async function addIncidentComment(
  incidentId: number,
  state: 'INVESTIGATING' | 'IDENTIFIED' | 'MONITORING' | 'RESOLVED',
  comment: string,
): Promise<void> {
  const res = await kenerFetch(`/api/v4/incidents/${incidentId}/comments`, {
    method: 'POST',
    body: JSON.stringify({ comment, state, timestamp: Math.floor(Date.now() / 1000) }),
  });
  await parseOrThrow(res, 'addIncidentComment');
}

export async function setIncidentEnd(incidentId: number, endTs: number): Promise<void> {
  const res = await kenerFetch(`/api/v4/incidents/${incidentId}`, {
    method: 'PATCH',
    body: JSON.stringify({ end_date_time: endTs }),
  });
  await parseOrThrow(res, 'setIncidentEnd');
}

// ── Active incidents tracker (in-memory, resets on process restart) ─────────
// serviceName → incidentId. Survives hot-reloads via globalThis.
const g = globalThis as any;
if (!g.__gw_kenerActiveIncidents) g.__gw_kenerActiveIncidents = {} as Record<string, number>;
const activeIncidents: Record<string, number> = g.__gw_kenerActiveIncidents;

/**
 * Called by the monitoring cycle on each observed status transition.
 * Opens an incident on up→degraded/down and resolves it on any→up.
 */
export async function handleStatusTransition(
  service: string,
  prev: ServiceStatus | undefined,
  next: ServiceStatus,
  reason?: string,
): Promise<void> {
  if (!KENER_ENABLED) return;
  const tag = SERVICE_TO_KENER_TAG[service];
  if (!tag) return; // service not mapped to a Kener monitor — skip silently

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
      await addIncidentComment(
        incident.id,
        'INVESTIGATING',
        reason
          ? `Détection automatique — ${reason}`
          : `Détection automatique du gateway : ${service} est ${label}.`,
      );
      logger.warn(`[Kener] Incident #${incident.id} ouvert pour ${service} (${impact})`);
      return;
    }

    // Escalation: degraded → down while incident already open
    if (next === 'down' && prev === 'degraded' && activeIncidents[service]) {
      await addIncidentComment(
        activeIncidents[service],
        'IDENTIFIED',
        `Aggravation : ${service} est passé de dégradé à hors ligne.`,
      );
      return;
    }

    // Recovery: back to up while incident is open
    if (next === 'up' && activeIncidents[service]) {
      const id = activeIncidents[service];
      const now = Math.floor(Date.now() / 1000);
      await addIncidentComment(id, 'RESOLVED', `Service rétabli : ${service} répond à nouveau normalement.`);
      await setIncidentEnd(id, now);
      delete activeIncidents[service];
      logger.info(`[Kener] Incident #${id} résolu pour ${service}`);
      return;
    }
  } catch (err: any) {
    // Never let Kener hiccups crash the monitoring cycle.
    logger.error({ err }, `[Kener] Échec traitement transition ${service} ${prev}→${next}`);
  }
}
