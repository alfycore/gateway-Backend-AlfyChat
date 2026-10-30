//! Fonctions partagées par les handlers temps réel (équivalents des helpers d'`index.ts`, lignes 537→1190).

use std::sync::Arc;
use std::time::Instant;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tracing::{info, warn};

use super::ch_room;
use crate::http::routes_misc::{is_id, is_uuid, truthy};
use crate::perms::{self, ADMIN, ALL_PERMS_MASK, READ};
use crate::state::{event, AppState, Moderation};

// ── Identifiants venant du client ───────────────────────────────────────────

static DM_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^dm_([0-9a-f-]{36})_([0-9a-f-]{36})$").unwrap());

pub fn val_is_id(v: &Value) -> bool {
    v.as_str().map(is_id).unwrap_or(false)
}

pub fn val_is_uuid(v: &Value) -> bool {
    v.as_str().map(is_uuid).unwrap_or(false)
}

/// Les deux participants d'un identifiant de MP `dm_<a>_<b>`.
pub fn parse_dm_id(conversation_id: &Value) -> Option<(String, String)> {
    let c = DM_ID_RE.captures(conversation_id.as_str()?)?;
    Some((c[1].to_string(), c[2].to_string()))
}

/// L'autre participant d'un MP, ou `None` si `user_id` n'en fait pas partie.
pub fn dm_peer(conversation_id: &Value, user_id: &str) -> Option<String> {
    let (a, b) = parse_dm_id(conversation_id)?;
    if a == user_id {
        Some(b)
    } else if b == user_id {
        Some(a)
    } else {
        None
    }
}

pub fn dm_id_for(a: &str, b: &str) -> String {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    format!("dm_{x}_{y}")
}

// ── Modération : mute global ────────────────────────────────────────────────

const MODERATION_CACHE_TTL_MS: u128 = 30_000;

pub struct Mute {
    pub until: Option<String>,
    pub reason: Option<String>,
}

/// Mute actif d'un utilisateur, ou `None` s'il peut écrire (une sanction s'applique en moins de 30 s).
pub async fn get_active_mute(app: &Arc<AppState>, user_id: &str) -> Option<Mute> {
    let cached = app.moderation_cache.lock().get(user_id).cloned();
    let mut status = cached.as_ref().and_then(|(s, _)| s.clone());
    let stale = cached.as_ref().map(|(_, at)| at.elapsed().as_millis() > MODERATION_CACHE_TTL_MS).unwrap_or(true);
    if stale {
        status = match app.svc.users_get_moderation_status(user_id).await {
            Ok(v) => Some(Moderation::from_value(&v)),
            Err(_) => cached.and_then(|(s, _)| s),
        };
        app.moderation_cache.lock().insert(user_id.to_string(), (status.clone(), Instant::now()));
    }
    let s = status?;
    if !s.muted {
        return None;
    }
    Some(Mute { until: s.muted_until, reason: s.mute_reason })
}

/// `new Date(x).toLocaleString('fr-FR')`
pub fn fr_date(iso: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(iso) {
        Ok(d) => d.with_timezone(&chrono::Utc).format("%d/%m/%Y %H:%M:%S").to_string(),
        Err(_) => "Invalid Date".into(),
    }
}

pub fn mute_message(m: &Mute) -> String {
    let until = match &m.until {
        Some(u) => format!("jusqu'au {}", fr_date(u)),
        None => "de façon permanente".to_string(),
    };
    format!("Vous êtes réduit au silence {until}. Motif : {}", m.reason.as_deref().unwrap_or("non précisé"))
}

// ── Accès aux conversations ─────────────────────────────────────────────────

const CONV_ACCESS_TTL: u64 = 120;

/// L'utilisateur participe-t-il à cette conversation ? Les MP sont décomposés strictement, les groupes
/// vérifiés auprès du service messages avec un cache Redis court (fail-closed).
pub async fn has_conversation_access(app: &Arc<AppState>, user_id: &str, conversation_id: &Value) -> bool {
    let Some(cid) = conversation_id.as_str().filter(|s| !s.is_empty()) else { return false };
    if cid.starts_with("dm_") {
        return match DM_ID_RE.captures(cid) {
            Some(m) => &m[1] == user_id || &m[2] == user_id,
            None => false,
        };
    }
    let key = format!("convacc:{cid}:{user_id}");
    if let Ok(Some(c)) = app.redis.get(&key).await {
        if c == "1" {
            return true;
        }
        if c == "0" {
            return false;
        }
    }
    let allowed = app.svc.messages_is_participant(cid, user_id).await;
    // Les refus sont mis en cache moins longtemps : un ajout à un groupe doit devenir effectif vite.
    let _ = app.redis.set(&key, if allowed { "1" } else { "0" }, Some(if allowed { CONV_ACCESS_TTL } else { 10 })).await;
    allowed
}

/// Purge le cache d'accès d'une conversation (ajout / retrait de participant).
pub async fn invalidate_conversation_access(app: &Arc<AppState>, conversation_id: &str, user_id: Option<&str>) {
    match user_id {
        Some(u) => {
            let _ = app.redis.del(&format!("convacc:{conversation_id}:{u}")).await;
        }
        None => {
            let _ = app.redis.delete_by_pattern(&format!("convacc:{conversation_id}:*"), 200).await;
        }
    }
}

// ── Permissions serveur ─────────────────────────────────────────────────────

const PERM_CACHE_TTL: u64 = 60;

#[derive(Clone, Copy, Debug, Default)]
pub struct PermBits {
    pub is_owner: bool,
    pub perms: i64,
}

fn parse_perm_cache(raw: &str) -> Option<PermBits> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let perms = v.get("perms")?.as_f64()?;
    Some(PermBits { is_owner: v.get("isOwner") == Some(&Value::Bool(true)), perms: perms as i64 })
}

fn compute_bits(raw: &Value) -> PermBits {
    let n = perms::js_number(raw.get("permissions").unwrap_or(&Value::Null));
    let mut r = PermBits { is_owner: raw.get("isOwner") == Some(&Value::Bool(true)), perms: if n.is_finite() { perms::mask_number(n) } else { 0 } };
    // Le propriétaire et ADMIN impliquent tout.
    if r.is_owner || r.perms & ADMIN != 0 {
        r.perms = ALL_PERMS_MASK;
    }
    r
}

/// Permissions cumulées d'un utilisateur sur un serveur (un entier calculé en SQL, mis en cache 60 s).
/// Échec technique → aucun droit (fail-closed).
pub async fn get_user_perm_bits(app: &Arc<AppState>, user_id: &str, server_id: &str) -> PermBits {
    let key = format!("perm:{server_id}:{user_id}");
    if let Ok(Some(c)) = app.redis.get(&key).await {
        if let Some(p) = parse_perm_cache(&c) {
            return p;
        }
    }
    let raw = match app.svc.servers_get_member_permissions(server_id, user_id, None).await {
        Ok(v) => v,
        Err(e) => {
            warn!("getUserPermBits: échec du calcul pour {user_id}@{server_id}: {}", e.message);
            return PermBits::default();
        }
    };
    let result = compute_bits(&raw);
    let _ = app.redis.set(&key, &json!({ "isOwner": result.is_owner, "perms": result.perms }).to_string(), Some(PERM_CACHE_TTL)).await;
    result
}

/// Purge le cache de permissions d'un serveur (un membre précis, ou tous).
pub async fn invalidate_server_perms(app: &Arc<AppState>, server_id: &str, user_id: Option<&str>) {
    match user_id {
        Some(u) => {
            let _ = app.redis.del(&format!("perm:{server_id}:{u}")).await;
            let _ = app.redis.delete_by_pattern(&format!("perm:{server_id}:{u}:ch:*"), 200).await;
        }
        None => {
            // Changement de rôle → tous les membres du serveur sont concernés.
            let _ = app.redis.delete_by_pattern(&format!("perm:{server_id}:*"), 200).await;
        }
    }
}

/// TOUS les bits demandés ; le propriétaire passe tout.
pub async fn check_server_permission(app: &Arc<AppState>, user_id: &str, server_id: &str, required: i64) -> bool {
    if server_id.is_empty() || user_id.is_empty() {
        return false;
    }
    let b = get_user_perm_bits(app, user_id, server_id).await;
    b.is_owner || b.perms & required == required
}

/// Au moins UN des bits demandés (paires historiques KICK/KICK_MEMBERS).
pub async fn check_server_permission_any(app: &Arc<AppState>, user_id: &str, server_id: &str, any_of: i64) -> bool {
    if server_id.is_empty() || user_id.is_empty() {
        return false;
    }
    let b = get_user_perm_bits(app, user_id, server_id).await;
    b.is_owner || b.perms & any_of != 0
}

/// Bits d'un membre DANS un salon (surcharges appliquées). Les serveurs auto-hébergés gèrent leurs
/// surcharges sur leur node : on s'en tient alors aux droits du serveur.
pub async fn get_channel_perm_bits(app: &Arc<AppState>, user_id: &str, server_id: &str, channel_id: &str) -> PermBits {
    if !is_id(channel_id) || app.has_node(server_id) {
        return get_user_perm_bits(app, user_id, server_id).await;
    }
    let key = format!("perm:{server_id}:{user_id}:ch:{channel_id}");
    if let Ok(Some(c)) = app.redis.get(&key).await {
        if let Some(p) = parse_perm_cache(&c) {
            return p;
        }
    }
    let raw = match app.svc.servers_get_member_permissions(server_id, user_id, Some(channel_id)).await {
        Ok(v) => v,
        Err(e) => {
            warn!("getChannelPermBits: échec du calcul pour {user_id}@{server_id}#{channel_id}: {}", e.message);
            return PermBits::default();
        }
    };
    let result = compute_bits(&raw);
    let _ = app.redis.set(&key, &json!({ "isOwner": result.is_owner, "perms": result.perms }).to_string(), Some(PERM_CACHE_TTL)).await;
    result
}

pub async fn check_channel_permission(app: &Arc<AppState>, user_id: &str, server_id: &str, channel_id: &str, required: i64) -> bool {
    if server_id.is_empty() || user_id.is_empty() {
        return false;
    }
    let b = get_channel_perm_bits(app, user_id, server_id, channel_id).await;
    b.is_owner || b.perms & required == required
}

/// Un modérateur ne peut agir que sur un membre dont les permissions sont incluses dans les siennes.
pub async fn can_act_on_member(app: &Arc<AppState>, actor_id: &str, target_id: &str, server_id: &str) -> bool {
    if actor_id == target_id {
        return false;
    }
    let actor = get_user_perm_bits(app, actor_id, server_id).await;
    if actor.is_owner {
        return true;
    }
    let target = get_user_perm_bits(app, target_id, server_id).await;
    if target.is_owner {
        return false;
    }
    target.perms & !actor.perms == 0
}

// ── Confidentialité ─────────────────────────────────────────────────────────

const PRIVACY_CACHE_TTL: u64 = 60;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DmMode {
    Everyone,
    Friends,
    None,
}

impl DmMode {
    fn as_str(self) -> &'static str {
        match self {
            DmMode::Everyone => "everyone",
            DmMode::Friends => "friends",
            DmMode::None => "none",
        }
    }
}

fn normalize_dm_mode(v: Option<&Value>) -> DmMode {
    match v {
        Some(Value::String(s)) if s == "none" => DmMode::None,
        Some(Value::String(s)) if s == "friends" => DmMode::Friends,
        Some(Value::Bool(false)) => DmMode::Friends,
        _ => DmMode::Everyone,
    }
}

#[derive(Clone, Copy)]
pub struct Privacy {
    pub dm_mode: DmMode,
    pub show_online: bool,
}

/// Préférences de confidentialité du destinataire. `None` = illisibles (l'appelant refuse : fail-closed).
pub async fn get_privacy_prefs(app: &Arc<AppState>, user_id: &str) -> Option<Privacy> {
    let key = format!("privacy:{user_id}");
    if let Ok(Some(c)) = app.redis.get(&key).await {
        if let Ok(v) = serde_json::from_str::<Value>(&c) {
            return Some(Privacy { dm_mode: normalize_dm_mode(v.get("dmMode")), show_online: v.get("showOnline") != Some(&Value::Bool(false)) });
        }
    }
    let prefs = match app.svc.users_get_preferences(user_id).await {
        Ok(raw) => Privacy {
            dm_mode: normalize_dm_mode(raw.get("privacyAllowDmMode").filter(|v| truthy(Some(v))).or_else(|| raw.get("privacyAllowDm"))),
            show_online: raw.get("privacyShowOnline") != Some(&Value::Bool(false)),
        },
        // Pas de ligne de préférences = réglages par défaut. Toute autre erreur : on ne sait pas.
        Err(e) if e.status == Some(404) => Privacy { dm_mode: DmMode::Everyone, show_online: true },
        Err(_) => return None,
    };
    let _ = app.redis.set(&key, &json!({ "dmMode": prefs.dm_mode.as_str(), "showOnline": prefs.show_online }).to_string(), Some(PRIVACY_CACHE_TTL)).await;
    Some(prefs)
}

/// `sender_id` peut-il ouvrir / écrire un MP à `recipient_id` selon les réglages de ce dernier ?
pub async fn can_direct_message(app: &Arc<AppState>, sender_id: &str, recipient_id: &str) -> bool {
    let key = format!("dmok:{sender_id}:{recipient_id}");
    if let Ok(Some(c)) = app.redis.get(&key).await {
        if c == "1" {
            return true;
        }
        if c == "0" {
            return false;
        }
    }
    let Some(prefs) = get_privacy_prefs(app, recipient_id).await else { return false };
    let allowed = match prefs.dm_mode {
        DmMode::Everyone => true,
        DmMode::None => false,
        DmMode::Friends => {
            let friends = app.svc.friends_get_friends(recipient_id).await;
            friends.as_array().map(|a| a.iter().any(|f| {
                let id = f.get("id").filter(|v| !v.is_null()).or_else(|| f.get("friendId"));
                id.and_then(|v| v.as_str()) == Some(sender_id)
            })).unwrap_or(false)
        }
    };
    let _ = app.redis.set(&key, if allowed { "1" } else { "0" }, Some(PRIVACY_CACHE_TTL)).await;
    allowed
}

/// Le statut en ligne de cet utilisateur doit-il être masqué aux autres ?
pub async fn is_presence_hidden(app: &Arc<AppState>, user_id: &str) -> bool {
    get_privacy_prefs(app, user_id).await.map(|p| !p.show_online).unwrap_or(false)
}

// ── Métadonnées de salon (mode lent, limite vocale) ─────────────────────────

const CHANNEL_META_TTL_MS: u128 = 30_000;

pub async fn get_channel_meta(app: &Arc<AppState>, server_id: &str, channel_id: &str) -> Option<crate::state::ChannelMeta> {
    use crate::state::ChannelMeta;
    if !is_id(server_id) || !is_id(channel_id) {
        return None;
    }
    let fresh = {
        let g = app.channel_meta_cache.lock();
        g.get(server_id).filter(|(at, by_id)| at.elapsed().as_millis() <= CHANNEL_META_TTL_MS && by_id.contains_key(channel_id)).map(|(_, by_id)| by_id.get(channel_id).cloned())
    };
    if let Some(m) = fresh {
        return m;
    }
    let list: Vec<Value> = match crate::nodes::forward_to_node(app, server_id, "CHANNEL_LIST", &json!({}), 5_000).await {
        Ok(r) => r.get("channels").and_then(|c| c.as_array()).cloned().unwrap_or_default(),
        Err(_) => match app.svc.servers_get_channels(server_id, None).await {
            Ok(v) => v.as_array().cloned().unwrap_or_default(),
            Err(_) => return None,
        },
    };
    let num = |c: &Value, a: &str, b: &str| -> i64 {
        let v = c.get(a).filter(|v| !v.is_null()).or_else(|| c.get(b)).unwrap_or(&Value::Null);
        let n = perms::js_number(v);
        if n.is_finite() && n > 0.0 {
            n as i64
        } else {
            0
        }
    };
    let s = |c: &Value, k: &str, d: &str| c.get(k).filter(|v| !v.is_null()).map(|v| crate::http::routes_misc::js_string(Some(v))).unwrap_or_else(|| d.to_string());
    let by_id: std::collections::HashMap<String, ChannelMeta> = list
        .iter()
        .filter(|c| c.get("id").map(val_is_id).unwrap_or(false))
        .map(|c| {
            let id = c["id"].as_str().unwrap().to_string();
            (id.clone(), ChannelMeta { id, kind: s(c, "type", "text"), name: s(c, "name", ""), slow_mode: num(c, "slowMode", "slow_mode"), user_limit: num(c, "userLimit", "user_limit") })
        })
        .collect();
    let out = by_id.get(channel_id).cloned();
    app.channel_meta_cache.lock().insert(server_id.to_string(), (Instant::now(), by_id));
    out
}

pub async fn invalidate_channel_meta(app: &Arc<AppState>, server_id: &str) {
    app.channel_meta_cache.lock().remove(server_id);
    let _ = app.redis.del(&format!("nodechans:{server_id}")).await;
}

// ── Rooms de salons : recalcul après un changement de permissions ───────────

/// Reporte à 400 ms le recalcul des rooms de salons d'un serveur (ou d'un seul membre).
pub fn schedule_channel_resync(app: &Arc<AppState>, server_id: &str, only_user: Option<&str>) {
    if !is_id(server_id) || app.has_node(server_id) {
        return;
    }
    let key = match only_user {
        Some(u) => format!("{server_id}:{u}"),
        None => server_id.to_string(),
    };
    let (a, sid, ou) = (app.clone(), server_id.to_string(), only_user.map(str::to_string));
    let k2 = key.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        a.resync_timers.lock().remove(&k2);
        resync_channel_rooms(&a, &sid, ou.as_deref()).await;
    });
    if let Some(prev) = app.resync_timers.lock().insert(key, handle.abort_handle()) {
        prev.abort();
    }
}

pub async fn resync_channel_rooms(app: &Arc<AppState>, server_id: &str, only_user: Option<&str>) {
    let target = match only_user {
        Some(u) => format!("user:{u}"),
        None => format!("server:{server_id}"),
    };
    let sockets = match app.io().within(target.clone()).fetch_sockets().await {
        Ok(s) => s,
        Err(e) => {
            warn!("resyncChannelRooms {server_id}: {e}");
            return;
        }
    };
    let server_room = format!("server:{server_id}");
    // Les sockets d'une autre instance n'exposent pas leur userId (comme l'original) : elles sont ignorées.
    let mut by_user: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
    for s in sockets {
        let sid = s.data().id.to_string();
        let uid = app.conns.clients.lock().get(&sid).map(|c| c.user_id.clone());
        let Some(uid) = uid else { continue };
        let rooms = s.rooms().await.unwrap_or_default();
        if !rooms.iter().any(|r| r.as_ref() == server_room) {
            continue;
        }
        by_user.entry(uid).or_default().push((s, rooms));
    }
    let prefix = format!("ch:{server_id}:");
    for (uid, list) in by_user {
        let channels = match app.svc.servers_get_channels(server_id, Some(&uid)).await {
            Ok(v) => v,
            Err(_) => continue, // en cas d'échec, on ne retire rien
        };
        let visible: Vec<String> = channels
            .as_array()
            .map(|a| a.iter().filter_map(|c| c.get("id").and_then(|i| i.as_str()).filter(|i| is_id(i)).map(str::to_string)).collect())
            .unwrap_or_default();
        let wanted: std::collections::HashSet<String> = visible.iter().map(|id| ch_room(server_id, id)).collect();
        for (s, rooms) in list {
            for room in rooms.iter().map(|r| r.to_string()) {
                if room.starts_with(&prefix) && !wanted.contains(&room) {
                    let _ = s.leave(room).await;
                }
            }
            for room in &wanted {
                if !rooms.iter().any(|r| r.as_ref() == room.as_str()) {
                    let _ = s.join(room.clone()).await;
                }
            }
        }
    }
    let ev = "CHANNELS_INVALIDATE";
    let _ = app.io().to(target).emit(ev, &event(ev, json!({ "serverId": server_id }))).await;
}

/// Après une écriture de surcharge : caches, rooms et clients.
pub async fn after_overrides_changed(app: &Arc<AppState>, server_id: &str, channel_id: &str) {
    invalidate_server_perms(app, server_id, None).await;
    schedule_channel_resync(app, server_id, None);
    let ev = "CHANNEL_PERMS_UPDATE";
    let _ = app.io().to(format!("server:{server_id}")).emit(ev, &event(ev, json!({ "serverId": server_id, "channelId": channel_id }))).await;
}

/// Diffuse un salon créé / modifié. Un salon soumis à des surcharges n'est jamais diffusé tel quel
/// (son nom fuirait) : chacun recharge sa liste filtrée à la place.
pub async fn announce_channel(app: &Arc<AppState>, server_id: &str, channel: &Value, ev: &'static str) {
    let Some(cid) = channel.get("id").filter(|v| truthy(Some(v))).map(|v| crate::http::routes_misc::js_string(Some(v))) else { return };
    let overrides_of = |c: String| {
        let app = app.clone();
        let sid = server_id.to_string();
        async move { app.svc.servers_get_channel_overrides(&sid, &c).await.map(|o| o.get("overrides").and_then(|x| x.as_array()).map(|a| !a.is_empty()).unwrap_or(false)) }
    };
    let restricted = match overrides_of(cid.clone()).await {
        Ok(true) => true,
        Ok(false) => match channel.get("parentId").filter(|v| truthy(Some(v))) {
            Some(p) => overrides_of(crate::http::routes_misc::js_string(Some(p))).await.unwrap_or(true),
            None => false,
        },
        Err(_) => true, // doute → on ne diffuse pas le nom
    };
    if restricted {
        schedule_channel_resync(app, server_id, None);
        return;
    }
    if ev == "CHANNEL_CREATE" {
        let _ = app.io().within(format!("server:{server_id}")).join(ch_room(server_id, &cid)).await;
    }
    let mut payload = channel.as_object().cloned().unwrap_or_default();
    payload.insert("serverId".into(), json!(server_id));
    let _ = app.io().to(format!("server:{server_id}")).emit(ev, &event(ev, Value::Object(payload))).await;
}

// ── Présence vocale ─────────────────────────────────────────────────────────

/// Diffuse l'état complet d'un salon vocal à tout le serveur (liste des salons).
pub async fn broadcast_voice_state(app: &Arc<AppState>, server_id: &str, channel_id: &str) {
    let (participants, status) = {
        let v = app.conns.voice.lock();
        (
            v.channels.get(channel_id).map(|m| m.values().map(|p| p.public()).collect::<Vec<_>>()).unwrap_or_default(),
            v.status.get(channel_id).cloned(),
        )
    };
    let body = json!({ "channelId": channel_id, "serverId": server_id, "participants": participants, "status": status });
    let _ = app.io().to(format!("server:{server_id}")).emit("VOICE_STATE_UPDATE", &body).await;
}

/// Retire un utilisateur de la présence vocale d'un salon. Le statut du salon est éphémère :
/// il disparaît quand le salon se vide.
pub async fn remove_voice_participant(app: &Arc<AppState>, user_id: &str, channel_id: &str) {
    let participant = {
        let mut v = app.conns.voice.lock();
        let p = v.channels.get(channel_id).and_then(|m| m.get(user_id)).cloned();
        let Some(p) = p else {
            if v.user_channel.get(user_id).map(|c| c == channel_id).unwrap_or(false) {
                v.user_channel.remove(user_id);
            }
            return;
        };
        if let Some(m) = v.channels.get_mut(channel_id) {
            m.shift_remove(user_id);
        }
        if v.user_channel.get(user_id).map(|c| c == channel_id).unwrap_or(false) {
            v.user_channel.remove(user_id);
        }
        if v.channels.get(channel_id).map(|m| m.is_empty()).unwrap_or(false) {
            v.channels.shift_remove(channel_id);
            v.status.remove(channel_id);
        }
        p
    };
    let _ = app.io().within(participant.socket_id.clone()).leave(format!("voice:{channel_id}")).await;
    let _ = app.io().to(format!("voice:{channel_id}")).emit("VOICE_USER_LEFT", &json!({ "channelId": channel_id, "userId": user_id })).await;
    broadcast_voice_state(app, &participant.server_id, channel_id).await;
    info!("User {user_id} left voice channel {channel_id}");
}

/// Retire l'utilisateur de son salon vocal — seulement si c'est CETTE socket qui y est connectée.
pub async fn leave_voice_channel(app: &Arc<AppState>, user_id: &str, socket_id: &str) {
    let target = {
        let v = app.conns.voice.lock();
        let Some(channel_id) = v.user_channel.get(user_id).cloned() else { return };
        if let Some(p) = v.channels.get(&channel_id).and_then(|m| m.get(user_id)) {
            if p.socket_id != socket_id {
                return;
            }
        }
        channel_id
    };
    remove_voice_participant(app, user_id, &target).await;
}

/// Niveau de lecture minimal pour être « membre » d'un serveur (mentions).
pub const MEMBER_PERM: i64 = READ;
