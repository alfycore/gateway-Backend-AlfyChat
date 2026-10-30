export declare const PERM: {
    readonly READ: 1;
    readonly SEND: 2;
    readonly REACT: 4;
    readonly MANAGE_MESSAGES: 8;
    readonly KICK: 16;
    readonly BAN: 32;
    readonly ADMIN: 64;
    readonly MANAGE_CHANNELS: 128;
    readonly MANAGE_ROLES: 256;
    readonly KICK_MEMBERS: 1024;
    readonly BAN_MEMBERS: 2048;
    readonly CONNECT: 4096;
    readonly SPEAK: 8192;
    readonly VIDEO: 16384;
    readonly CREATE_INVITE: 32768;
    readonly MANAGE_SERVER: 65536;
    readonly MENTION_EVERYONE: 131072;
    readonly ATTACH_FILES: 262144;
    readonly CHANGE_NICKNAME: 524288;
    readonly MANAGE_NICKNAMES: 1048576;
    readonly MUTE_MEMBERS: 2097152;
    readonly MOVE_MEMBERS: 4194304;
    readonly VIEW_AUDIT_LOG: 8388608;
    readonly MANAGE_EMOJIS: 16777216;
    readonly MANAGE_WEBHOOKS: 33554432;
    readonly MANAGE_EVENTS: 67108864;
};
/** Tous les bits valides. Sert à masquer `permissions: -1` ou 0x80000000. */
export declare const ALL_PERMS_MASK = 134217727;
/** Droits accordés par défaut au rôle @everyone d'un nouveau serveur. */
export declare const DEFAULT_EVERYONE_PERMS: number;
/** Bits ajoutés par l'extension v2 et accordés une fois au rôle par défaut existant. */
export declare const V2_BASELINE_GRANT: number;
/** Expulser : l'une ou l'autre des deux paires historiques suffit. */
export declare const KICK_ANY: number;
/** Bannir : idem. */
export declare const BAN_ANY: number;
/** Normalise une valeur de permissions venue de la base (nombre, chaîne, JSON). */
export declare function normalizePerms(raw: unknown): number;
/** L'utilisateur détient-il TOUS les bits demandés ? (ADMIN vaut tout) */
export declare function hasAll(perms: number, required: number): boolean;
/** L'utilisateur détient-il AU MOINS UN des bits demandés ? (ADMIN vaut tout) */
export declare function hasAny(perms: number, anyOf: number): boolean;
//# sourceMappingURL=permissions.d.ts.map