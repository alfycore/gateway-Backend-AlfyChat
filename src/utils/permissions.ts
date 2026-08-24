// ==========================================
// ALFYCHAT — BITMASK DE PERMISSIONS (source unique)
// ==========================================
// ⚠️  Ce fichier est la référence. Il est MIROIRÉ à l'identique dans :
//       servers/src/permissions.ts
//       Frontend-AlfyChat/src/lib/server-perms.ts   (mêmes valeurs)
//     Toute modification doit être reportée dans les trois.
//
// Historique : KICK/BAN (0x10/0x20) sont l'ancienne paire du microservice,
// KICK_MEMBERS/BAN_MEMBERS (0x400/0x800) celle du gateway et de l'UI. Les deux
// coexistent dans les rôles déjà créés : les helpers `KICK_ANY`/`BAN_ANY`
// acceptent l'une ou l'autre pour qu'aucune permission accordée d'un côté ne
// soit ignorée de l'autre.

export const PERM = {
  READ:            0x1,
  SEND:            0x2,
  REACT:           0x4,
  MANAGE_MESSAGES: 0x8,
  KICK:            0x10,
  BAN:             0x20,
  ADMIN:           0x40,
  MANAGE_CHANNELS: 0x80,
  MANAGE_ROLES:    0x100,
  KICK_MEMBERS:    0x400,
  BAN_MEMBERS:     0x800,
} as const;

/** Tous les bits valides. Sert à masquer `permissions: -1` ou 0x80000000. */
export const ALL_PERMS_MASK = 0xFFF;

/** Expulser : l'une ou l'autre des deux paires historiques suffit. */
export const KICK_ANY = PERM.KICK | PERM.KICK_MEMBERS;
/** Bannir : idem. */
export const BAN_ANY = PERM.BAN | PERM.BAN_MEMBERS;

/** Normalise une valeur de permissions venue de la base (nombre, chaîne, JSON). */
export function normalizePerms(raw: unknown): number {
  if (typeof raw === 'number') return Number.isFinite(raw) ? (raw & ALL_PERMS_MASK) : 0;
  if (typeof raw === 'string') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) return parsed & ALL_PERMS_MASK;
    try {
      const fromJson = Number(JSON.parse(raw));
      return Number.isFinite(fromJson) ? (fromJson & ALL_PERMS_MASK) : 0;
    } catch { return 0; }
  }
  return 0;
}

/** L'utilisateur détient-il TOUS les bits demandés ? (ADMIN vaut tout) */
export function hasAll(perms: number, required: number): boolean {
  if (perms & PERM.ADMIN) return true;
  return (perms & required) === required;
}

/** L'utilisateur détient-il AU MOINS UN des bits demandés ? (ADMIN vaut tout) */
export function hasAny(perms: number, anyOf: number): boolean {
  if (perms & PERM.ADMIN) return true;
  return (perms & anyOf) !== 0;
}
