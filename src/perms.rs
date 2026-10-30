//! Bitmask de permissions (source unique côté gateway ; miroirs : servers/src/permissions.ts,
//! Frontend-AlfyChat/src/components/alfy/guild/perms.ts). Toute modification doit être reportée dans les trois.
//!
//! KICK/BAN (0x10/0x20) sont l'ancienne paire du microservice, KICK_MEMBERS/BAN_MEMBERS (0x400/0x800)
//! celle du gateway et de l'UI : `KICK_ANY`/`BAN_ANY` acceptent l'une ou l'autre.

use serde_json::Value;

pub const READ: i64 = 0x1;
pub const SEND: i64 = 0x2;
pub const REACT: i64 = 0x4;
pub const MANAGE_MESSAGES: i64 = 0x8;
pub const KICK: i64 = 0x10;
pub const BAN: i64 = 0x20;
pub const ADMIN: i64 = 0x40;
pub const MANAGE_CHANNELS: i64 = 0x80;
pub const MANAGE_ROLES: i64 = 0x100;
pub const KICK_MEMBERS: i64 = 0x400;
pub const BAN_MEMBERS: i64 = 0x800;
pub const CONNECT: i64 = 0x1000;
pub const SPEAK: i64 = 0x2000;
pub const VIDEO: i64 = 0x4000;
pub const CREATE_INVITE: i64 = 0x8000;
pub const MANAGE_SERVER: i64 = 0x10000;
pub const MENTION_EVERYONE: i64 = 0x20000;
pub const ATTACH_FILES: i64 = 0x40000;
pub const CHANGE_NICKNAME: i64 = 0x80000;
pub const MANAGE_NICKNAMES: i64 = 0x100000;
pub const MUTE_MEMBERS: i64 = 0x200000;
pub const MOVE_MEMBERS: i64 = 0x400000;
pub const VIEW_AUDIT_LOG: i64 = 0x800000;
pub const MANAGE_EMOJIS: i64 = 0x1000000;
pub const MANAGE_WEBHOOKS: i64 = 0x2000000;
pub const MANAGE_EVENTS: i64 = 0x4000000;

/// Tous les bits valides. Sert à masquer `permissions: -1` ou 0x80000000.
pub const ALL_PERMS_MASK: i64 = 0x7FFFFFF;

pub const KICK_ANY: i64 = KICK | KICK_MEMBERS;
pub const BAN_ANY: i64 = BAN | BAN_MEMBERS;

/// `ToInt32` de JavaScript : l'opérateur `&` ramène d'abord son opérande sur 32 bits signés.
pub fn to_int32(f: f64) -> i32 {
    if !f.is_finite() {
        return 0;
    }
    (f.trunc().rem_euclid(4_294_967_296.0) as u32) as i32
}

/// `Number(x) & ALL_PERMS_MASK` pour un nombre fini, sinon 0.
pub fn mask_number(f: f64) -> i64 {
    if f.is_finite() {
        (to_int32(f) as i64) & ALL_PERMS_MASK
    } else {
        0
    }
}

/// Équivalent de `Number(value)` pour une valeur JSON (nombre, chaîne numérique, booléen, null → 0).
pub fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Value::Bool(b) => *b as i64 as f64,
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

/// Normalise une valeur de permissions venue de la base (nombre, chaîne, JSON).
pub fn normalize_perms(raw: &Value) -> i64 {
    match raw {
        Value::Number(_) => mask_number(js_number(raw)),
        Value::String(s) => {
            let n = js_number(raw);
            if n.is_finite() {
                return mask_number(n);
            }
            match serde_json::from_str::<Value>(s) {
                Ok(v) => mask_number(js_number(&v)),
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

/// Le titulaire détient-il TOUS les bits demandés ? (ADMIN vaut tout)
pub fn has_all(perms: i64, required: i64) -> bool {
    if perms & ADMIN != 0 {
        return true;
    }
    perms & required == required
}

/// Le titulaire détient-il AU MOINS UN des bits demandés ? (ADMIN vaut tout)
pub fn has_any(perms: i64, any_of: i64) -> bool {
    if perms & ADMIN != 0 {
        return true;
    }
    perms & any_of != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn int32_semantics() {
        assert_eq!(to_int32(-1.0), -1);
        assert_eq!(mask_number(-1.0), ALL_PERMS_MASK);
        assert_eq!(mask_number(2147483648.0), 0);
        assert_eq!(mask_number(4294967297.0), 1);
        assert_eq!(mask_number(f64::NAN), 0);
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_perms(&json!(3)), 3);
        assert_eq!(normalize_perms(&json!("7")), 7);
        assert_eq!(normalize_perms(&json!("\"5\"")), 5);
        assert_eq!(normalize_perms(&json!("abc")), 0);
        assert_eq!(normalize_perms(&json!(null)), 0);
        assert_eq!(normalize_perms(&json!(-1)), ALL_PERMS_MASK);
    }

    #[test]
    fn admin_wins() {
        assert!(has_all(ADMIN, SEND | READ));
        assert!(has_any(ADMIN, KICK_ANY));
        assert!(!has_all(READ, READ | SEND));
        assert!(has_any(KICK_MEMBERS, KICK_ANY));
    }
}
