//! Endpoints HTTP internes appelés par le media-server et le service users (protégés par `X-Internal-Secret`).

use std::time::Duration;

use serde_json::{json, Value};
use tracing::warn;

use crate::http::routes_misc::{is_id, is_uuid, truthy};
use crate::http::{err_json, handler, json, Req, Router};
use crate::security::safe_secret_equal;

pub fn register(r: &mut Router) {
    // Le media-server signale un changement de palier de qualité.
    r.post(
        "/internal/call-quality",
        handler(|req: Req| async move {
            if !safe_secret_equal(req.header("x-internal-secret"), Some(&req.app.cfg.internal_secret)) {
                return err_json(401, "Accès interne requis");
            }
            let call_id = req.body.get("callId").and_then(|c| c.as_str()).filter(|c| is_id(c));
            let tier = req.body.get("tier");
            let (Some(call_id), Some(tier)) = (call_id, tier) else { return err_json(400, "callId et tier requis") };
            let null = Value::Null;
            super::calls::broadcast_quality_update(&req.app, call_id, tier, req.body.get("participantCount").unwrap_or(&null), req.body.get("tierParams").unwrap_or(&null)).await;
            json(200, &json!({ "success": true }))
        }),
    );

    // Le service users applique une sanction en direct : un ban / kick coupe la session sans attendre l'expiration du JWT.
    r.post(
        "/internal/moderation/enforce",
        handler(|req: Req| async move {
            if !safe_secret_equal(req.header("x-internal-secret"), Some(&req.app.cfg.internal_secret)) {
                return err_json(401, "Accès interne requis");
            }
            let user_id = req.body.get("userId").and_then(|u| u.as_str()).filter(|u| is_uuid(u));
            let kind = req.body.get("type").filter(|t| truthy(Some(t)));
            let (Some(user_id), Some(kind)) = (user_id, kind) else { return err_json(400, "userId et type requis") };

            // Le cache mémoire doit être purgé, sinon un mute mettrait 30 s à s'appliquer
            req.app.moderation_cache.lock().remove(user_id);

            let mut body = serde_json::Map::new();
            body.insert("type".into(), kind.clone());
            for k in ["reason", "expiresAt"] {
                if let Some(v) = req.body.get(k) {
                    body.insert(k.into(), v.clone());
                }
            }
            let room = format!("user:{user_id}");
            let io = req.app.io().clone();
            let _ = io.to(room.clone()).emit("MODERATION_ENFORCED", &Value::Object(body)).await;
            if matches!(kind.as_str(), Some("ban") | Some("kick")) {
                // Laisser le temps à l'événement de partir avant de couper les sockets
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let _ = io.within(room).disconnect().await;
                });
            }
            warn!("[MODÉRATION] {} appliqué en direct sur {user_id}", crate::http::routes_misc::js_string(Some(kind)));
            json(200, &json!({ "success": true }))
        }),
    );

    // Révocation de sessions (changement de mot de passe, « déconnecter tous les appareils »).
    r.post(
        "/internal/users/disconnect",
        handler(|req: Req| async move {
            if !safe_secret_equal(req.header("x-internal-secret"), Some(&req.app.cfg.internal_secret)) {
                return err_json(401, "Accès interne requis");
            }
            let Some(user_id) = req.body.get("userId").and_then(|u| u.as_str()).filter(|u| is_uuid(u)) else { return err_json(400, "userId requis") };
            let room = format!("user:{user_id}");
            let io = req.app.io().clone();
            let _ = io.to(room.clone()).emit("SESSION_REVOKED", &json!({ "reason": "sessions_revoked" })).await;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let _ = io.within(room).disconnect().await;
            });
            json(200, &json!({ "success": true }))
        }),
    );
}
