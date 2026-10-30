"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.BAN_ANY = exports.KICK_ANY = exports.V2_BASELINE_GRANT = exports.DEFAULT_EVERYONE_PERMS = exports.ALL_PERMS_MASK = exports.PERM = void 0;
exports.normalizePerms = normalizePerms;
exports.hasAll = hasAll;
exports.hasAny = hasAny;
exports.PERM = {
    READ: 0x1,
    SEND: 0x2,
    REACT: 0x4,
    MANAGE_MESSAGES: 0x8,
    KICK: 0x10,
    BAN: 0x20,
    ADMIN: 0x40,
    MANAGE_CHANNELS: 0x80,
    MANAGE_ROLES: 0x100,
    KICK_MEMBERS: 0x400,
    BAN_MEMBERS: 0x800,
    // ── Extension « Discord » (2026-10-19) ──────────────────────────────────
    // Les bits « de base » (CONNECT, SPEAK, VIDEO, CREATE_INVITE, ATTACH_FILES,
    // CHANGE_NICKNAME, MENTION_EVERYONE) ont été accordés une fois pour toutes
    // au rôle par défaut existant (migration `perm_bits_v2`) : un serveur déjà
    // en place ne perd aucun droit à l'apparition de ces bits.
    CONNECT: 0x1000,
    SPEAK: 0x2000,
    VIDEO: 0x4000,
    CREATE_INVITE: 0x8000,
    MANAGE_SERVER: 0x10000,
    MENTION_EVERYONE: 0x20000,
    ATTACH_FILES: 0x40000,
    CHANGE_NICKNAME: 0x80000,
    MANAGE_NICKNAMES: 0x100000,
    MUTE_MEMBERS: 0x200000,
    MOVE_MEMBERS: 0x400000,
    VIEW_AUDIT_LOG: 0x800000,
    MANAGE_EMOJIS: 0x1000000,
    MANAGE_WEBHOOKS: 0x2000000,
    MANAGE_EVENTS: 0x4000000,
};
/** Tous les bits valides. Sert à masquer `permissions: -1` ou 0x80000000. */
exports.ALL_PERMS_MASK = 0x7FFFFFF;
/** Droits accordés par défaut au rôle @everyone d'un nouveau serveur. */
exports.DEFAULT_EVERYONE_PERMS = exports.PERM.READ | exports.PERM.SEND | exports.PERM.REACT | exports.PERM.CONNECT | exports.PERM.SPEAK | exports.PERM.VIDEO
    | exports.PERM.CREATE_INVITE | exports.PERM.ATTACH_FILES | exports.PERM.CHANGE_NICKNAME | exports.PERM.MENTION_EVERYONE;
/** Bits ajoutés par l'extension v2 et accordés une fois au rôle par défaut existant. */
exports.V2_BASELINE_GRANT = exports.PERM.CONNECT | exports.PERM.SPEAK | exports.PERM.VIDEO | exports.PERM.CREATE_INVITE | exports.PERM.ATTACH_FILES
    | exports.PERM.CHANGE_NICKNAME | exports.PERM.MENTION_EVERYONE;
/** Expulser : l'une ou l'autre des deux paires historiques suffit. */
exports.KICK_ANY = exports.PERM.KICK | exports.PERM.KICK_MEMBERS;
/** Bannir : idem. */
exports.BAN_ANY = exports.PERM.BAN | exports.PERM.BAN_MEMBERS;
/** Normalise une valeur de permissions venue de la base (nombre, chaîne, JSON). */
function normalizePerms(raw) {
    if (typeof raw === 'number')
        return Number.isFinite(raw) ? (raw & exports.ALL_PERMS_MASK) : 0;
    if (typeof raw === 'string') {
        const parsed = Number(raw);
        if (Number.isFinite(parsed))
            return parsed & exports.ALL_PERMS_MASK;
        try {
            const fromJson = Number(JSON.parse(raw));
            return Number.isFinite(fromJson) ? (fromJson & exports.ALL_PERMS_MASK) : 0;
        }
        catch {
            return 0;
        }
    }
    return 0;
}
/** L'utilisateur détient-il TOUS les bits demandés ? (ADMIN vaut tout) */
function hasAll(perms, required) {
    if (perms & exports.PERM.ADMIN)
        return true;
    return (perms & required) === required;
}
/** L'utilisateur détient-il AU MOINS UN des bits demandés ? (ADMIN vaut tout) */
function hasAny(perms, anyOf) {
    if (perms & exports.PERM.ADMIN)
        return true;
    return (perms & anyOf) !== 0;
}
//# sourceMappingURL=permissions.js.map