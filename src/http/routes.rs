//! Table de routes complète, dans l'ordre d'enregistrement d'`index.ts` (le premier motif gagnant l'emporte).

use super::proxy::proxy_raw_webhook;
use super::routes_misc::{self, proxy_h};
use super::{accepts_html, handler, html_file, json, Req, Router, INDEX_HTML};

pub fn build() -> Router {
    let mut r = Router::default();

    // Auth & utilisateurs
    for p in ["/api/auth/*", "/api/users/*", "/api/users", "/api/rgpd/*"] {
        r.all(p, proxy_h("users", |c| &c.users_url, true, false));
    }

    // Modules de routes : amorçage, interne, LB, statistiques
    routes_misc::register_all_part1(&mut r);
    routes_misc::register_stats(&mut r);
    super::routes_admin::register(&mut r);

    // Messages
    for p in [
        "/api/messages/*",
        "/api/messages",
        "/api/conversations/*",
        "/api/conversations",
        "/api/archive/*",
        "/api/archive",
        "/api/notifications/*",
        "/api/notifications",
    ] {
        r.all(p, proxy_h("messages", |c| &c.messages_url, true, false));
    }
    routes_misc::register_friends_routes(&mut r);

    // Appels
    for p in ["/api/calls/*", "/api/calls"] {
        r.all(p, proxy_h("calls", |c| &c.calls_url, true, false));
    }

    // Hooks claim-admin et webhook entrant (avant les routes serveurs)
    routes_misc::register_hooks_routes(&mut r);
    routes_misc::register_servers_routes(&mut r);

    // OAuth2 (avant /api/bots) et bots
    for p in ["/api/oauth2/*", "/api/oauth2", "/api/bots/*", "/api/bots"] {
        r.all(p, proxy_h("bots", |c| &c.bots_url, true, false));
    }

    // Hébergement et abonnements : corps brut + signatures relayés tels quels pour les webhooks
    r.all(
        "/api/subscriptions/webhooks/*",
        handler(|req: Req| async move {
            let base = req.app.service_url_or_env("subscriptions", &req.app.cfg.subscriptions_url);
            proxy_raw_webhook(req, &base).await
        }),
    );
    for p in ["/api/hosting/*", "/api/hosting"] {
        r.all(p, proxy_h("serverhosting", |c| &c.serverhosting_url, true, true));
    }
    for p in ["/api/subscriptions/plans*", "/api/subscriptions/checkout/*", "/api/subscriptions/*", "/api/subscriptions"] {
        r.all(p, proxy_h("subscriptions", |c| &c.subscriptions_url, true, true));
    }

    routes_misc::register_media_routes(&mut r);
    routes_misc::register_health(&mut r);

    // Endpoints internes appelés par le media-server et le service users
    crate::ws::internal::register(&mut r);

    // Page d'accueil (HTML si le client l'accepte, sinon 404 JSON via le gestionnaire final)
    r.get(
        "/",
        handler(|req: Req| async move {
            if accepts_html(&req.headers) {
                html_file(200, INDEX_HTML)
            } else {
                json(404, &serde_json::json!({ "error": "Route not found", "path": req.path() }))
            }
        }),
    );
    r
}
