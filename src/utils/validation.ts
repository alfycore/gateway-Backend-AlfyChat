// ==========================================
// ALFYCHAT - VALIDATION (GATEWAY-ENFORCED)
// ==========================================
// Source de vérité pour les entrées utilisateur.
// Le frontend peut mentir — jamais le gateway.

export class ValidationError extends Error {
  constructor(public field: string, message: string) {
    super(`${field}: ${message}`);
    this.name = 'ValidationError';
  }
}

// ── Limites par champ ───────────────────────────────────────────────
export const LIMITS = {
  displayName:      { min: 1, max: 32 },
  username:         { min: 1, max: 32 },
  bio:              { min: 0, max: 500 },
  customStatus:     { min: 0, max: 100 },
  interests:        { maxItems: 10, itemMin: 1, itemMax: 24 },
  messageContent:   { min: 1, max: 4000 },
  groupName:        { min: 1, max: 64 },
  serverName:       { min: 1, max: 64 },
  serverDescription:{ min: 0, max: 500 },
  channelName:      { min: 1, max: 64 },
  channelTopic:     { min: 0, max: 200 },
  roleName:         { min: 1, max: 32 },
  nickname:         { min: 0, max: 32 },
  customSlug:       { min: 3, max: 32 },
  inviteMaxUses:    { min: 1, max: 1000 },
  inviteExpiresIn:  { min: 60, max: 60 * 60 * 24 * 365 },
  attachmentsCount: { max: 10 },
  tags:             { maxItems: 5, itemMin: 1, itemMax: 30 },
  participants:     { max: 100 },
  roleIds:          { max: 50 },
} as const;

// ── Liste de mots filtrés (FR/EN/IT/ES/DE) ──────────────────────────
const BAD_WORDS = [
  'fuck','shit','bitch','asshole','cunt','dick','pussy','nigger','nigga','faggot','retard',
  'putain','merde','salope','connard','encule','enculé','pute','bite','chatte','nique','niquer','tapette','batard','bâtard','fdp',
  'cazzo','stronzo','puta','mierda','scheisse','scheiße',
];

const LEET: Record<string, string> = { '0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s','!':'i' };

function normalize(s: string): string {
  return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[0134579@$!]/g, (c) => LEET[c] || c)
    .replace(/[^a-z]/g, '');
}

export function containsProfanity(text: string): boolean {
  const n = normalize(text);
  if (!n) return false;
  return BAD_WORDS.some((w) => n.includes(w));
}

export function sanitizeText(text: string): string {
  let out = text;
  for (const w of BAD_WORDS) {
    out = out.replace(new RegExp(w, 'gi'), (m) => '*'.repeat(m.length));
  }
  return out;
}

// ── Primitives ──────────────────────────────────────────────────────
interface TextOpts {
  field: string;
  min?: number;
  max: number;
  required?: boolean;
  allowProfanity?: boolean;
  sanitize?: boolean;
}

export function validateText(value: unknown, opts: TextOpts): string | undefined {
  if (value === undefined || value === null || value === '') {
    if (opts.required) throw new ValidationError(opts.field, 'required');
    return undefined;
  }
  if (typeof value !== 'string') throw new ValidationError(opts.field, 'must be a string');
  const trimmed = value.trim();
  if ((opts.min ?? 0) > 0 && trimmed.length < (opts.min ?? 0)) {
    throw new ValidationError(opts.field, `too short (min ${opts.min})`);
  }
  if (trimmed.length > opts.max) {
    throw new ValidationError(opts.field, `too long (max ${opts.max})`);
  }
  if (!opts.allowProfanity && containsProfanity(trimmed)) {
    if (opts.sanitize) return sanitizeText(trimmed);
    throw new ValidationError(opts.field, 'inappropriate content');
  }
  return trimmed;
}

interface ArrayOpts {
  field: string;
  max: number;
  itemMin?: number;
  itemMax?: number;
  dedupe?: boolean;
  allowProfanity?: boolean;
}

export function validateStringArray(value: unknown, opts: ArrayOpts): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) throw new ValidationError(opts.field, 'must be an array');
  if (value.length > opts.max) throw new ValidationError(opts.field, `too many items (max ${opts.max})`);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== 'string') throw new ValidationError(opts.field, 'items must be strings');
    const t = raw.trim();
    if (!t) continue;
    if (opts.itemMin && t.length < opts.itemMin) throw new ValidationError(opts.field, `item too short (min ${opts.itemMin})`);
    if (opts.itemMax && t.length > opts.itemMax) throw new ValidationError(opts.field, `item too long (max ${opts.itemMax})`);
    if (!opts.allowProfanity && containsProfanity(t)) throw new ValidationError(opts.field, 'inappropriate content');
    const key = opts.dedupe ? t.toLowerCase() : t + Math.random();
    if (opts.dedupe && seen.has(key)) continue;
    seen.add(key);
    out.push(t);
  }
  return out;
}

export function validateInt(value: unknown, field: string, min: number, max: number, required = false): number | undefined {
  if (value === undefined || value === null) {
    if (required) throw new ValidationError(field, 'required');
    return undefined;
  }
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n)) throw new ValidationError(field, 'must be an integer');
  if (n < min || n > max) throw new ValidationError(field, `out of range [${min}-${max}]`);
  return n;
}

export function validateBool(value: unknown, field: string): boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'boolean') throw new ValidationError(field, 'must be a boolean');
  return value;
}

const URL_RE = /^https?:\/\/[^\s<>"']+$/i;
export function validateUrl(value: unknown, field: string, maxLen = 500): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new ValidationError(field, 'must be a string');
  const t = value.trim();
  if (t.length > maxLen) throw new ValidationError(field, `url too long (max ${maxLen})`);
  if (!URL_RE.test(t)) throw new ValidationError(field, 'invalid url');
  return t;
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/i;
export function validateSlug(value: unknown, field: string, min: number, max: number): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new ValidationError(field, 'must be a string');
  const t = value.trim();
  if (t.length < min || t.length > max) throw new ValidationError(field, `length must be ${min}-${max}`);
  if (!SLUG_RE.test(t)) throw new ValidationError(field, 'only letters, digits, hyphens');
  if (containsProfanity(t)) throw new ValidationError(field, 'inappropriate content');
  return t;
}

// ── Schémas haut-niveau ─────────────────────────────────────────────

export function validateProfile(data: any): Record<string, unknown> {
  if (!data || typeof data !== 'object') throw new ValidationError('profile', 'invalid payload');
  const out: Record<string, unknown> = {};
  const dn = validateText(data.displayName, { field: 'displayName', ...LIMITS.displayName });
  if (dn !== undefined) out.displayName = dn;
  const un = validateText(data.username, { field: 'username', ...LIMITS.username });
  if (un !== undefined) out.username = un;
  const bio = validateText(data.bio, { field: 'bio', ...LIMITS.bio });
  if (bio !== undefined) out.bio = bio;
  const cs = validateText(data.customStatus, { field: 'customStatus', ...LIMITS.customStatus });
  if (cs !== undefined) out.customStatus = cs;
  const interests = validateStringArray(data.interests, {
    field: 'interests',
    max: LIMITS.interests.maxItems,
    itemMin: LIMITS.interests.itemMin,
    itemMax: LIMITS.interests.itemMax,
    dedupe: true,
  });
  if (interests !== undefined) out.interests = interests;
  const av = validateUrl(data.avatarUrl, 'avatarUrl');
  if (av !== undefined) out.avatarUrl = av;
  const bn = validateUrl(data.bannerUrl, 'bannerUrl');
  if (bn !== undefined) out.bannerUrl = bn;
  // Champs pass-through sûrs (booléens, couleurs, etc.)
  if (data.cardColor !== undefined) out.cardColor = String(data.cardColor).slice(0, 16);
  if (data.showBadges !== undefined) out.showBadges = validateBool(data.showBadges, 'showBadges');
  return out;
}

export function validateGroupInput(data: any): { name?: string; avatarUrl?: string; participantIds?: string[]; addParticipants?: string[]; removeParticipants?: string[] } {
  const out: any = {};
  out.name = validateText(data.name, { field: 'name', ...LIMITS.groupName, required: !data.groupId });
  const av = validateUrl(data.avatarUrl, 'avatarUrl');
  if (av !== undefined) out.avatarUrl = av;
  for (const key of ['participantIds', 'addParticipants', 'removeParticipants'] as const) {
    if (data[key] !== undefined) {
      if (!Array.isArray(data[key])) throw new ValidationError(key, 'must be an array');
      if (data[key].length > LIMITS.participants.max) throw new ValidationError(key, `too many (max ${LIMITS.participants.max})`);
      out[key] = data[key].filter((x: unknown) => typeof x === 'string');
    }
  }
  return out;
}

export function validateServerInput(data: any): { name?: string; description?: string; iconUrl?: string; bannerUrl?: string; isPublic?: boolean } {
  const out: any = {};
  if (data.name !== undefined) out.name = validateText(data.name, { field: 'name', ...LIMITS.serverName, required: true });
  if (data.description !== undefined) out.description = validateText(data.description, { field: 'description', ...LIMITS.serverDescription });
  const icon = validateUrl(data.iconUrl, 'iconUrl');
  if (icon !== undefined) out.iconUrl = icon;
  const banner = validateUrl(data.bannerUrl, 'bannerUrl');
  if (banner !== undefined) out.bannerUrl = banner;
  const pub = validateBool(data.isPublic, 'isPublic');
  if (pub !== undefined) out.isPublic = pub;
  return out;
}

export function validateChannelInput(data: any): { name?: string; topic?: string; type?: string; parentId?: string } {
  const out: any = {};
  if (data.name !== undefined) out.name = validateText(data.name, { field: 'name', ...LIMITS.channelName, required: true });
  if (data.topic !== undefined) out.topic = validateText(data.topic, { field: 'topic', ...LIMITS.channelTopic });
  if (data.type !== undefined) {
    if (!['text', 'voice', 'forum', 'announcement'].includes(data.type)) throw new ValidationError('type', 'invalid channel type');
    out.type = data.type;
  }
  if (data.parentId !== undefined && typeof data.parentId === 'string') out.parentId = data.parentId;
  return out;
}

export function validateRoleInput(data: any): { name?: string; color?: string } {
  const out: any = {};
  if (data.name !== undefined) out.name = validateText(data.name, { field: 'name', ...LIMITS.roleName, required: true });
  if (data.color !== undefined) {
    if (typeof data.color !== 'string' || !/^#[0-9a-f]{6}$/i.test(data.color)) throw new ValidationError('color', 'invalid hex color');
    out.color = data.color;
  }
  return out;
}

export function validateMemberUpdate(data: any): { nickname?: string; roleIds?: string[] } {
  const out: any = {};
  if (data.nickname !== undefined) out.nickname = validateText(data.nickname, { field: 'nickname', ...LIMITS.nickname });
  if (data.roleIds !== undefined) {
    if (!Array.isArray(data.roleIds)) throw new ValidationError('roleIds', 'must be an array');
    if (data.roleIds.length > LIMITS.roleIds.max) throw new ValidationError('roleIds', `too many (max ${LIMITS.roleIds.max})`);
    out.roleIds = data.roleIds.filter((x: unknown) => typeof x === 'string');
  }
  return out;
}

export function validateMessageContent(content: unknown, attachments?: unknown): { content: string; attachments?: string[] } {
  const hasAttachments = Array.isArray(attachments) && attachments.length > 0;
  const c = validateText(content, {
    field: 'content',
    min: hasAttachments ? 0 : LIMITS.messageContent.min,
    max: LIMITS.messageContent.max,
    required: !hasAttachments,
    allowProfanity: true, // messages privés/chat: pas de filtre contenu (libre expression)
  });
  const out: any = { content: c ?? '' };
  if (hasAttachments) {
    if ((attachments as unknown[]).length > LIMITS.attachmentsCount.max) {
      throw new ValidationError('attachments', `too many (max ${LIMITS.attachmentsCount.max})`);
    }
    out.attachments = (attachments as unknown[]).filter((x): x is string => typeof x === 'string');
  }
  return out;
}

export function validateInviteInput(data: any): { maxUses?: number; expiresIn?: number; customSlug?: string; isPermanent?: boolean } {
  const out: any = {};
  if (data.maxUses !== undefined) out.maxUses = validateInt(data.maxUses, 'maxUses', LIMITS.inviteMaxUses.min, LIMITS.inviteMaxUses.max);
  if (data.expiresIn !== undefined && data.expiresIn !== null) out.expiresIn = validateInt(data.expiresIn, 'expiresIn', LIMITS.inviteExpiresIn.min, LIMITS.inviteExpiresIn.max);
  if (data.customSlug !== undefined && data.customSlug !== '') out.customSlug = validateSlug(data.customSlug, 'customSlug', LIMITS.customSlug.min, LIMITS.customSlug.max);
  const perm = validateBool(data.isPermanent, 'isPermanent');
  if (perm !== undefined) out.isPermanent = perm;
  return out;
}

export function validateTags(value: unknown): string[] | undefined {
  return validateStringArray(value, {
    field: 'tags',
    max: LIMITS.tags.maxItems,
    itemMin: LIMITS.tags.itemMin,
    itemMax: LIMITS.tags.itemMax,
    dedupe: true,
  });
}
