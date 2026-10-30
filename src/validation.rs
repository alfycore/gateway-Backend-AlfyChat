//! Validation des entrées utilisateur appliquée par le gateway (équivalent de `utils/validation.ts`).
//! Le frontend peut mentir — jamais le gateway.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::perms::{js_number, to_int32, ALL_PERMS_MASK};

/// Erreur de validation : le message est `champ: détail`, exposé tel quel au client.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: &str, message: impl Into<String>) -> Self {
        Self { field: field.into(), message: message.into() }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

pub type VResult<T> = Result<T, ValidationError>;

// ── Limites par champ ───────────────────────────────────────────────────────

pub struct Lim {
    pub min: usize,
    pub max: usize,
}

pub const DISPLAY_NAME: Lim = Lim { min: 1, max: 32 };
pub const USERNAME: Lim = Lim { min: 1, max: 32 };
pub const BIO: Lim = Lim { min: 0, max: 500 };
pub const CUSTOM_STATUS: Lim = Lim { min: 0, max: 100 };
pub const MESSAGE_CONTENT: Lim = Lim { min: 1, max: 4000 };
/// Un ciphertext Signal dépasse largement 4 000 caractères ; le service messages accepte 131 072 octets.
pub const CIPHER_CONTENT_MAX: usize = 131_072;
pub const GROUP_NAME: Lim = Lim { min: 1, max: 64 };
pub const SERVER_NAME: Lim = Lim { min: 1, max: 64 };
pub const SERVER_DESCRIPTION: Lim = Lim { min: 0, max: 500 };
pub const CHANNEL_NAME: Lim = Lim { min: 1, max: 64 };
pub const CHANNEL_TOPIC: Lim = Lim { min: 0, max: 200 };
pub const ROLE_NAME: Lim = Lim { min: 1, max: 32 };
pub const NICKNAME: Lim = Lim { min: 0, max: 32 };
pub const PARTICIPANTS_MAX: usize = 100;
pub const ROLE_IDS_MAX: usize = 50;
pub const ATTACHMENTS_MAX: usize = 10;

// ── Mots filtrés (FR/EN/IT/ES/DE) ───────────────────────────────────────────

const BAD_WORDS: &[&str] = &[
    "fuck", "shit", "bitch", "asshole", "cunt", "dick", "pussy", "nigger", "nigga", "faggot", "retard", "putain", "merde", "salope",
    "connard", "encule", "enculé", "pute", "bite", "chatte", "nique", "niquer", "tapette", "batard", "bâtard", "fdp", "cazzo",
    "stronzo", "puta", "mierda", "scheisse", "scheiße",
];

static BAD_WORDS_RE: Lazy<Regex> = Lazy::new(|| {
    let words: Vec<&str> = BAD_WORDS.to_vec();
    Regex::new(&format!(r"(?i)(?-u:\b)(?:{})(?-u:\b)", words.join("|"))).unwrap()
});

fn leet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '@' => 'a',
        '$' => 's',
        '!' => 'i',
        o => o,
    }
}

/// Normalise pour la comparaison en CONSERVANT les séparateurs (évite le problème de Scunthorpe).
fn normalize(value: &str) -> String {
    let mut out = String::new();
    let mut last_sep = false;
    for c in value.to_lowercase().nfd().filter(|c| !('\u{300}'..='\u{36f}').contains(c)).map(leet) {
        if c.is_ascii_lowercase() {
            out.push(c);
            last_sep = false;
        } else if !last_sep {
            out.push(' ');
            last_sep = true;
        }
    }
    out.trim().to_string()
}

pub fn contains_profanity(text: &str) -> bool {
    let n = normalize(text);
    !n.is_empty() && BAD_WORDS_RE.is_match(&n)
}

pub fn sanitize_text(text: &str) -> String {
    BAD_WORDS_RE.replace_all(text, |c: &regex::Captures| "*".repeat(c[0].encode_utf16().count())).into_owned()
}

fn is_nullish(v: &Value) -> bool {
    v.is_null() || v == ""
}

/// Longueur en unités UTF-16, comme `String.prototype.length`.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

// ── Primitives ──────────────────────────────────────────────────────────────

pub struct TextOpts<'a> {
    pub field: &'a str,
    pub min: usize,
    pub max: usize,
    pub required: bool,
    pub allow_profanity: bool,
    pub sanitize: bool,
}

impl<'a> TextOpts<'a> {
    pub fn new(field: &'a str, lim: &Lim) -> Self {
        Self { field, min: lim.min, max: lim.max, required: false, allow_profanity: false, sanitize: false }
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

pub fn validate_text(value: &Value, o: &TextOpts) -> VResult<Option<String>> {
    if is_nullish(value) {
        if o.required {
            return Err(ValidationError::new(o.field, "required"));
        }
        return Ok(None);
    }
    let Value::String(s) = value else { return Err(ValidationError::new(o.field, "must be a string")) };
    let trimmed = js_trim(s);
    let len = js_len(&trimmed);
    if o.min > 0 && len < o.min {
        return Err(ValidationError::new(o.field, format!("too short (min {})", o.min)));
    }
    if len > o.max {
        return Err(ValidationError::new(o.field, format!("too long (max {})", o.max)));
    }
    if !o.allow_profanity && contains_profanity(&trimmed) {
        if o.sanitize {
            return Ok(Some(sanitize_text(&trimmed)));
        }
        return Err(ValidationError::new(o.field, "inappropriate content"));
    }
    Ok(Some(trimmed))
}

/// `String.prototype.trim` : espaces Unicode et terminateurs de ligne.
pub fn js_trim(s: &str) -> String {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}').to_string()
}

pub struct ArrayOpts<'a> {
    pub field: &'a str,
    pub max: usize,
    pub item_min: usize,
    pub item_max: usize,
    pub dedupe: bool,
}

pub fn validate_string_array(value: &Value, o: &ArrayOpts) -> VResult<Option<Vec<String>>> {
    if value.is_null() {
        return Ok(None);
    }
    let Value::Array(arr) = value else { return Err(ValidationError::new(o.field, "must be an array")) };
    if arr.len() > o.max {
        return Err(ValidationError::new(o.field, format!("too many items (max {})", o.max)));
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in arr {
        let Value::String(r) = raw else { return Err(ValidationError::new(o.field, "items must be strings")) };
        let t = js_trim(r);
        if t.is_empty() {
            continue;
        }
        let len = js_len(&t);
        if o.item_min > 0 && len < o.item_min {
            return Err(ValidationError::new(o.field, format!("item too short (min {})", o.item_min)));
        }
        if o.item_max > 0 && len > o.item_max {
            return Err(ValidationError::new(o.field, format!("item too long (max {})", o.item_max)));
        }
        if contains_profanity(&t) {
            return Err(ValidationError::new(o.field, "inappropriate content"));
        }
        if o.dedupe && !seen.insert(t.to_lowercase()) {
            continue;
        }
        out.push(t);
    }
    Ok(Some(out))
}

pub fn validate_int(value: &Value, field: &str, min: f64, max: f64) -> VResult<Option<i64>> {
    if value.is_null() {
        return Ok(None);
    }
    let n = js_number(value);
    if !n.is_finite() || n.fract() != 0.0 {
        return Err(ValidationError::new(field, "must be an integer"));
    }
    if n < min || n > max {
        return Err(ValidationError::new(field, format!("out of range [{}-{}]", crate::json::js_number(min), crate::json::js_number(max))));
    }
    Ok(Some(n as i64))
}

pub fn validate_bool(value: &Value, field: &str) -> VResult<Option<bool>> {
    match value {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        _ => Err(ValidationError::new(field, "must be a boolean")),
    }
}

static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)^https?://[^\s<>"']+$"#).unwrap());

pub fn validate_url(value: &Value, field: &str, max_len: usize) -> VResult<Option<String>> {
    if is_nullish(value) {
        return Ok(None);
    }
    let Value::String(s) = value else { return Err(ValidationError::new(field, "must be a string")) };
    let t = js_trim(s);
    if js_len(&t) > max_len {
        return Err(ValidationError::new(field, format!("url too long (max {max_len})")));
    }
    if !URL_RE.is_match(&t) {
        return Err(ValidationError::new(field, "invalid url"));
    }
    Ok(Some(t))
}

static SLUG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[a-z0-9][a-z0-9-]*[a-z0-9]$").unwrap());

pub fn validate_slug(value: &Value, field: &str, min: usize, max: usize) -> VResult<Option<String>> {
    if is_nullish(value) {
        return Ok(None);
    }
    let Value::String(s) = value else { return Err(ValidationError::new(field, "must be a string")) };
    let t = js_trim(s);
    let len = js_len(&t);
    if len < min || len > max {
        return Err(ValidationError::new(field, format!("length must be {min}-{max}")));
    }
    if !SLUG_RE.is_match(&t) {
        return Err(ValidationError::new(field, "only letters, digits, hyphens"));
    }
    if contains_profanity(&t) {
        return Err(ValidationError::new(field, "inappropriate content"));
    }
    Ok(Some(t))
}

// ── Schémas haut niveau ─────────────────────────────────────────────────────

static NULL: Value = Value::Null;

/// `data[key]` — `undefined` (ici `Null`) si `data` n'est pas un objet ou si la clé manque.
pub fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

fn has(v: &Value, key: &str) -> bool {
    v.get(key).is_some()
}

fn set(out: &mut Map<String, Value>, key: &str, v: Option<impl Into<Value>>) {
    if let Some(v) = v {
        out.insert(key.into(), v.into());
    }
}

pub fn validate_profile(data: &Value) -> VResult<Map<String, Value>> {
    if !data.is_object() {
        return Err(ValidationError::new("profile", "invalid payload"));
    }
    let mut out = Map::new();
    set(&mut out, "displayName", validate_text(field(data, "displayName"), &TextOpts::new("displayName", &DISPLAY_NAME))?);
    set(&mut out, "username", validate_text(field(data, "username"), &TextOpts::new("username", &USERNAME))?);
    set(&mut out, "bio", validate_text(field(data, "bio"), &TextOpts::new("bio", &BIO))?);
    set(&mut out, "customStatus", validate_text(field(data, "customStatus"), &TextOpts::new("customStatus", &CUSTOM_STATUS))?);
    let interests = validate_string_array(field(data, "interests"), &ArrayOpts { field: "interests", max: 10, item_min: 1, item_max: 24, dedupe: true })?;
    set(&mut out, "interests", interests);
    set(&mut out, "avatarUrl", validate_url(field(data, "avatarUrl"), "avatarUrl", 500)?);
    set(&mut out, "bannerUrl", validate_url(field(data, "bannerUrl"), "bannerUrl", 500)?);
    // Champs pass-through sûrs (booléens, couleurs, etc.)
    if has(data, "cardColor") {
        let s = crate::http::routes_misc::js_string(data.get("cardColor"));
        out.insert("cardColor".into(), json!(s.chars().take(16).collect::<String>()));
    }
    if has(data, "showBadges") {
        // `validateBool` renvoie undefined pour null : la clé existe alors avec la valeur undefined (omise du JSON).
        if let Some(b) = validate_bool(field(data, "showBadges"), "showBadges")? {
            out.insert("showBadges".into(), json!(b));
        }
    }
    let hidden = validate_string_array(field(data, "hiddenBadgeIds"), &ArrayOpts { field: "hiddenBadgeIds", max: 50, item_min: 1, item_max: 64, dedupe: true })?;
    set(&mut out, "hiddenBadgeIds", hidden);
    Ok(out)
}

fn filter_strings(v: &Value) -> Vec<Value> {
    v.as_array().map(|a| a.iter().filter(|x| x.is_string()).cloned().collect()).unwrap_or_default()
}

pub fn validate_group_input(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    let group_id_present = crate::http::routes_misc::truthy(data.get("groupId"));
    let mut o = TextOpts::new("name", &GROUP_NAME);
    o.required = !group_id_present;
    set(&mut out, "name", validate_text(field(data, "name"), &o)?);
    set(&mut out, "avatarUrl", validate_url(field(data, "avatarUrl"), "avatarUrl", 500)?);
    for key in ["participantIds", "addParticipants", "removeParticipants"] {
        if let Some(v) = data.get(key) {
            let Value::Array(a) = v else { return Err(ValidationError::new(key, "must be an array")) };
            if a.len() > PARTICIPANTS_MAX {
                return Err(ValidationError::new(key, format!("too many (max {PARTICIPANTS_MAX})")));
            }
            out.insert(key.into(), Value::Array(filter_strings(v)));
        }
    }
    if has(data, "isOpen") {
        if let Some(b) = validate_bool(field(data, "isOpen"), "isOpen")? {
            out.insert("isOpen".into(), json!(b));
        }
    }
    Ok(out)
}

pub fn validate_server_input(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    if has(data, "name") {
        set(&mut out, "name", validate_text(field(data, "name"), &TextOpts::new("name", &SERVER_NAME).required())?);
    }
    if has(data, "description") {
        set(&mut out, "description", validate_text(field(data, "description"), &TextOpts::new("description", &SERVER_DESCRIPTION))?);
    }
    // Les URL invalides sont ignorées (try/catch vide d'origine).
    if let Ok(Some(i)) = validate_url(field(data, "iconUrl"), "iconUrl", 500) {
        out.insert("iconUrl".into(), json!(i));
    }
    if let Ok(Some(b)) = validate_url(field(data, "bannerUrl"), "bannerUrl", 500) {
        out.insert("bannerUrl".into(), json!(b));
    }
    if let Some(p) = validate_bool(field(data, "isPublic"), "isPublic")? {
        out.insert("isPublic".into(), json!(p));
    }
    Ok(out)
}

const CHANNEL_TYPES: [&str; 16] = [
    "text", "voice", "forum", "announcement", "stage", "category", "gallery", "poll", "suggestion", "doc", "counting", "vent", "thread", "media",
    "minigame", "trivia",
];

static CHANNEL_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());

pub fn validate_channel_input(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    if has(data, "name") {
        set(&mut out, "name", validate_text(field(data, "name"), &TextOpts::new("name", &CHANNEL_NAME).required())?);
    }
    if has(data, "topic") {
        set(&mut out, "topic", validate_text(field(data, "topic"), &TextOpts::new("topic", &CHANNEL_TOPIC))?);
    }
    if has(data, "type") {
        let t = field(data, "type");
        if !t.as_str().map(|s| CHANNEL_TYPES.contains(&s)).unwrap_or(false) {
            return Err(ValidationError::new("type", "invalid channel type"));
        }
        out.insert("type".into(), t.clone());
    }
    if has(data, "parentId") {
        // `null` = sortir le salon de sa catégorie.
        let p = field(data, "parentId");
        if p.is_null() || p == "" {
            out.insert("parentId".into(), Value::Null);
        } else if p.as_str().map(|s| CHANNEL_ID_RE.is_match(s)).unwrap_or(false) {
            out.insert("parentId".into(), p.clone());
        } else {
            return Err(ValidationError::new("parentId", "invalid id"));
        }
    }
    if has(data, "isNsfw") {
        if let Some(b) = validate_bool(field(data, "isNsfw"), "isNsfw")? {
            out.insert("isNsfw".into(), json!(b));
        }
    }
    // Mode lent : 0 à 6 h, comme Discord.
    if has(data, "slowMode") {
        set(&mut out, "slowMode", validate_int(field(data, "slowMode"), "slowMode", 0.0, 21_600.0)?);
    }
    // Limite d'utilisateurs d'un salon vocal : 0 = illimité.
    if has(data, "userLimit") {
        set(&mut out, "userLimit", validate_int(field(data, "userLimit"), "userLimit", 0.0, 99.0)?);
    }
    if has(data, "position") {
        set(&mut out, "position", validate_int(field(data, "position"), "position", 0.0, 100_000.0)?);
    }
    if has(data, "isPrivate") {
        if let Some(b) = validate_bool(field(data, "isPrivate"), "isPrivate")? {
            out.insert("isPrivate".into(), json!(b));
        }
    }
    Ok(out)
}

/// Réorganisation par lot (glisser-déposer) : au plus 500 salons.
pub fn validate_channel_reorder(data: &Value) -> VResult<Vec<Value>> {
    let Some(arr) = data.as_array().filter(|a| !a.is_empty() && a.len() <= 500) else {
        return Err(ValidationError::new("positions", "must be a non-empty array (max 500)"));
    };
    arr.iter()
        .enumerate()
        .map(|(i, row)| {
            let id = field(row, "id").as_str().filter(|s| CHANNEL_ID_RE.is_match(s));
            let Some(id) = id else { return Err(ValidationError::new(&format!("positions[{i}].id"), "invalid id")) };
            let mut input = Map::new();
            if let Some(p) = row.get("position") {
                input.insert("position".into(), p.clone());
            }
            if let Some(p) = row.get("parentId") {
                input.insert("parentId".into(), p.clone());
            }
            let clean = validate_channel_input(&Value::Object(input))?;
            let Some(position) = clean.get("position").cloned() else {
                return Err(ValidationError::new(&format!("positions[{i}].position"), "required"));
            };
            let mut o = Map::new();
            o.insert("id".into(), json!(id));
            o.insert("position".into(), position);
            if let Some(p) = clean.get("parentId") {
                o.insert("parentId".into(), p.clone());
            }
            Ok(Value::Object(o))
        })
        .collect()
}

static HEX_COLOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^#[0-9a-f]{6}$").unwrap());

pub fn validate_role_input(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    if has(data, "name") {
        set(&mut out, "name", validate_text(field(data, "name"), &TextOpts::new("name", &ROLE_NAME).required())?);
    }
    if has(data, "color") {
        let c = field(data, "color");
        if !c.as_str().map(|s| HEX_COLOR_RE.is_match(s)).unwrap_or(false) {
            return Err(ValidationError::new("color", "invalid hex color"));
        }
        out.insert("color".into(), c.clone());
    }
    let perms = field(data, "permissions");
    if !perms.is_null() {
        let n = js_number(perms);
        if !n.is_finite() || n.fract() != 0.0 || n < 0.0 {
            return Err(ValidationError::new("permissions", "must be a non-negative integer"));
        }
        // Masque pour empêcher permissions:-1 / bits hors plage (contournement de hasPermission).
        out.insert("permissions".into(), json!((to_int32(n) as i64) & ALL_PERMS_MASK));
    }
    if has(data, "mentionable") {
        if let Some(b) = validate_bool(field(data, "mentionable"), "mentionable")? {
            out.insert("mentionable".into(), json!(b));
        }
    }
    // « Afficher les membres ayant ce rôle séparément »
    if has(data, "hoist") {
        if let Some(b) = validate_bool(field(data, "hoist"), "hoist")? {
            out.insert("hoist".into(), json!(b));
        }
    }
    if has(data, "iconEmoji") {
        let e = field(data, "iconEmoji");
        if e.is_null() || e == "" {
            out.insert("iconEmoji".into(), Value::Null);
        } else {
            let lim = Lim { min: 1, max: 16 };
            set(&mut out, "iconEmoji", validate_text(e, &TextOpts::new("iconEmoji", &lim))?);
        }
    }
    Ok(out)
}

pub fn validate_member_update(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    if has(data, "nickname") {
        set(&mut out, "nickname", validate_text(field(data, "nickname"), &TextOpts::new("nickname", &NICKNAME))?);
    }
    if let Some(v) = data.get("roleIds") {
        let Value::Array(a) = v else { return Err(ValidationError::new("roleIds", "must be an array")) };
        if a.len() > ROLE_IDS_MAX {
            return Err(ValidationError::new("roleIds", format!("too many (max {ROLE_IDS_MAX})")));
        }
        out.insert("roleIds".into(), Value::Array(filter_strings(v)));
    }
    Ok(out)
}

pub struct CleanMessage {
    pub content: String,
    pub attachments: Option<Vec<Value>>,
}

pub fn validate_message_content(content: &Value, attachments: &Value, e2ee_type: &Value) -> VResult<CleanMessage> {
    let has_attachments = attachments.as_array().map(|a| !a.is_empty()).unwrap_or(false);
    // 1 / 3 : formats Signal (MP), 4 : enveloppe multi-destinataires (groupes).
    let is_cipher = matches!(e2ee_type.as_f64(), Some(n) if n == 1.0 || n == 3.0 || n == 4.0);
    let lim = Lim { min: if has_attachments { 0 } else { MESSAGE_CONTENT.min }, max: if is_cipher { CIPHER_CONTENT_MAX } else { MESSAGE_CONTENT.max } };
    let mut o = TextOpts::new("content", &lim);
    o.required = !has_attachments;
    o.allow_profanity = true; // messages privés / chat : pas de filtre de contenu (libre expression)
    let c = validate_text(content, &o)?;
    let mut out = CleanMessage { content: c.unwrap_or_default(), attachments: None };
    if has_attachments {
        let a = attachments.as_array().unwrap();
        if a.len() > ATTACHMENTS_MAX {
            return Err(ValidationError::new("attachments", format!("too many (max {ATTACHMENTS_MAX})")));
        }
        out.attachments = Some(a.iter().filter(|x| x.is_string()).cloned().collect());
    }
    Ok(out)
}

pub fn validate_invite_input(data: &Value) -> VResult<Map<String, Value>> {
    let mut out = Map::new();
    if has(data, "maxUses") {
        set(&mut out, "maxUses", validate_int(field(data, "maxUses"), "maxUses", 1.0, 1000.0)?);
    }
    if !field(data, "expiresIn").is_null() {
        set(&mut out, "expiresIn", validate_int(field(data, "expiresIn"), "expiresIn", 60.0, 60.0 * 60.0 * 24.0 * 365.0)?);
    }
    if has(data, "customSlug") && field(data, "customSlug") != "" {
        set(&mut out, "customSlug", validate_slug(field(data, "customSlug"), "customSlug", 3, 32)?);
    }
    if let Some(p) = validate_bool(field(data, "isPermanent"), "isPermanent")? {
        out.insert("isPermanent".into(), json!(p));
    }
    Ok(out)
}

pub fn validate_tags(value: &Value) -> VResult<Option<Vec<String>>> {
    validate_string_array(value, &ArrayOpts { field: "tags", max: 5, item_min: 1, item_max: 30, dedupe: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profanity_with_word_boundaries() {
        assert!(contains_profanity("Tu es un connard"));
        assert!(!contains_profanity("f.u.c.k you"));
        assert!(!contains_profanity("Scunthorpe classic"));
        assert!(!contains_profanity("assistant"));
        assert!(contains_profanity("sh1t"));
        assert_eq!(sanitize_text("quelle merde ici"), "quelle ***** ici");
    }

    #[test]
    fn text_rules() {
        let o = TextOpts::new("name", &GROUP_NAME).required();
        assert_eq!(validate_text(&json!("  Salut  "), &o).unwrap().as_deref(), Some("Salut"));
        assert_eq!(validate_text(&json!(""), &o).unwrap_err().to_string(), "name: required");
        assert_eq!(validate_text(&json!(5), &o).unwrap_err().to_string(), "name: must be a string");
        assert_eq!(validate_text(&json!("a".repeat(65)), &o).unwrap_err().to_string(), "name: too long (max 64)");
    }

    #[test]
    fn message_limits() {
        assert!(validate_message_content(&json!("a".repeat(4001)), &Value::Null, &Value::Null).is_err());
        assert!(validate_message_content(&json!("a".repeat(5000)), &Value::Null, &json!(3)).is_ok());
        assert!(validate_message_content(&json!(""), &Value::Null, &Value::Null).is_err());
        let r = validate_message_content(&json!(""), &json!(["u"]), &Value::Null).unwrap();
        assert_eq!(r.content, "");
        assert_eq!(r.attachments.unwrap().len(), 1);
    }

    #[test]
    fn role_perms_masked() {
        let r = validate_role_input(&json!({"permissions": 2147483647})).unwrap();
        assert_eq!(r["permissions"], json!(2147483647i64 & 0x7FFFFFF));
        assert!(validate_role_input(&json!({"permissions": -1})).is_err());
        assert!(validate_role_input(&json!({"color": "red"})).is_err());
    }

    #[test]
    fn channel_reorder() {
        let r = validate_channel_reorder(&json!([{"id":"a","position":1,"parentId":null}])).unwrap();
        assert_eq!(r[0], json!({"id":"a","position":1,"parentId":null}));
        assert!(validate_channel_reorder(&json!([])).is_err());
    }
}
