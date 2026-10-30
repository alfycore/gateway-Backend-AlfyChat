//! AlfyChat — gateway (Rust). Port de `gateway/src` (TypeScript/Express + Socket.IO).

mod anomaly;
mod channel_kinds;
mod config;
mod http;
mod iso;
mod json;
mod lb;
mod mailer;
mod monitoring;
mod monitoring_db;
mod nodes;
mod perms;
mod ratelimit;
mod redis_client;
mod security;
mod state;
mod svc;
mod validation;
mod ws;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use parking_lot::Mutex;
use socketioxide::handler::ConnectHandler;
use socketioxide::SocketIo;
use socketioxide_redis::{RedisAdapter, RedisAdapterConfig, RedisAdapterCtr};
use tracing::{error, info, warn};

use crate::lb::gateway_registry::GatewayRegistry;
use crate::lb::registry::{LbRegistry, PreRegister};
use crate::ratelimit::{RedisLimiter, WsLimits};
use crate::redis_client::RedisClient;
use crate::state::{AppState, Connections, HttpLimiters};

#[derive(Clone)]
struct Shared {
    app: Arc<AppState>,
    router: Arc<http::Router>,
}

/// Toutes les requêtes HTTP hors Socket.IO : chaîne de middlewares puis table de routes.
async fn dispatch(State(sh): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, req: Request) -> Response {
    http::middleware::handle(sh.app, sh.router, Some(addr.ip()), req).await
}

/// CORS des routes `/socket.io` (identique à celui du reste de l'API : origine reflétée, credentials).
async fn socketio_cors(req: Request, next: Next) -> Response {
    if !req.uri().path().starts_with("/socket.io") {
        return next.run(req).await;
    }
    let mut base = axum::http::HeaderMap::new();
    let preflight = http::middleware::apply_cors(&mut base, req.method(), req.headers());
    let mut resp = if preflight { http::empty(204) } else { next.run(req).await };
    http::middleware::merge_base(&mut resp, &base);
    resp
}

fn env_str(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string())
}

/// Charge les instances de service depuis MySQL (repli : variables d'environnement).
async fn load_instances_from_db(app: &Arc<AppState>) {
    let rows = app.monitoring.load_service_instances().await;
    if !rows.is_empty() {
        let mut loaded = 0;
        for row in &rows {
            app.lb.pre_register(PreRegister {
                id: &row.id,
                service_type: &row.service_type,
                location: &row.location,
                enabled: Some(row.enabled),
                key_hash: None,
                endpoint: Some(&row.endpoint),
                domain: Some(&row.domain),
            });
            // Liste blanche : tous les identifiants en base peuvent envoyer des heartbeats
            app.allowed_service_ids.lock().insert(row.id.clone());
            if let Some(h) = row.service_key_hash.as_deref().filter(|h| !h.is_empty()) {
                app.lb.add_key_hash(&row.id, h);
            }
            if !row.enabled {
                app.banned_service_ids.lock().insert(row.id.clone());
            } else {
                loaded += 1;
            }
        }
        info!("ServiceRegistry: {loaded} instances actives + {} désactivées chargées depuis la DB", rows.len() - loaded);
        return;
    }
    // Aucune entrée en base → variables d'environnement
    let cfg = app.cfg;
    let location = env_str("DEFAULT_LOCATION", "EU").to_uppercase();
    let defaults = [
        ("users-default", "users", &cfg.users_url),
        ("messages-default", "messages", &cfg.messages_url),
        ("friends-default", "friends", &cfg.friends_url),
        ("calls-default", "calls", &cfg.calls_url),
        ("servers-default", "servers", &cfg.servers_url),
        ("bots-default", "bots", &cfg.bots_url),
        ("media-default", "media", &cfg.media_url),
        ("serverhosting-default", "serverhosting", &cfg.serverhosting_url),
        ("subscriptions-default", "subscriptions", &cfg.subscriptions_url),
    ];
    for (id, kind, url) in defaults {
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| match u.port() { Some(p) => format!("{h}:{p}"), None => h.to_string() }))
            .unwrap_or_else(|| url.clone());
        app.lb.pre_register(PreRegister { id, service_type: kind, location: &location, enabled: None, key_hash: None, endpoint: Some(url), domain: Some(&domain) });
    }
    info!("ServiceRegistry: {} instances initialisées depuis les vars d'environnement (fallback)", defaults.len());
}

/// Écoute dual-stack (IPv6 + IPv4), comme `server.listen(PORT)` de Node.
fn bind(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let try_v6 = || -> std::io::Result<std::net::TcpListener> {
        let sock = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        sock.set_only_v6(false)?;
        sock.set_reuse_address(true)?;
        sock.bind(&SocketAddr::from(([0u16; 8], port)).into())?;
        sock.listen(1024)?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    };
    let std_listener = match try_v6() {
        Ok(l) => l,
        Err(_) => {
            let l = std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
            l.set_nonblocking(true)?;
            l
        }
    };
    tokio::net::TcpListener::from_std(std_listener)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let cfg = match config::init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    // ── Redis (réessayé tant qu'il est indisponible, comme ioredis) ──────
    let (host, port) = (env_str("REDIS_HOST", "localhost"), env_str("REDIS_PORT", "6379").parse::<u16>().unwrap_or(6379));
    let password = std::env::var("REDIS_PASSWORD").ok().filter(|p| !p.is_empty());
    let redis = loop {
        match RedisClient::connect(&host, port, password.as_deref()).await {
            Ok(r) => break r,
            Err(e) => {
                error!("Redis indisponible ({host}:{port}) : {e} — nouvel essai dans 2 s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    let http_client = reqwest::Client::builder().connect_timeout(Duration::from_secs(10)).build().expect("client HTTP");
    let lb = LbRegistry::new();
    let ws_limits = Arc::new(WsLimits::new());
    ws_limits.spawn_sweeper();
    let gateway_id = env_str("GATEWAY_ID", "gateway-default");

    let app = Arc::new(AppState {
        cfg,
        redis: redis.clone(),
        http: http_client.clone(),
        lb: lb.clone(),
        gateways: GatewayRegistry::default(),
        svc: svc::Services::new(http_client, lb.clone(), cfg.internal_secret.clone(), cfg.is_production, cfg.admin_alert_emails.clone(), svc::ServiceUrls::from_env()),
        monitoring: monitoring_db::MonitoringDb::new(),
        gateway_id: gateway_id.clone(),
        started: Instant::now(),
        io: OnceLock::new(),
        conns: Connections::default(),
        ws_limits,
        limiters: HttpLimiters {
            anon: RedisLimiter::new("rl_anon", cfg.rate_limit_anon, cfg.rate_limit_window),
            user: RedisLimiter::new("rl_user", cfg.rate_limit_user, cfg.rate_limit_window),
            admin: RedisLimiter::new("rl_admin", cfg.rate_limit_admin, cfg.rate_limit_window),
            auth: RedisLimiter::new("rl_auth", cfg.rate_limit_auth_points, cfg.rate_limit_auth_window),
        },
        banned_service_ids: Mutex::new(Default::default()),
        allowed_service_ids: Mutex::new(Default::default()),
        block_cache: Mutex::new(Default::default()),
        moderation_cache: Mutex::new(Default::default()),
        channel_meta_cache: Mutex::new(Default::default()),
        resync_timers: Mutex::new(Default::default()),
        webhook_hits: Mutex::new(Default::default()),
        stats_cache: Mutex::new(None),
    });
    info!("Rate limiters initialisés");

    // ── Socket.IO avec adaptateur Redis (multi-instances) ────────────────
    // Redis ≥ 7 (RESP3). Préfixe distinct : l'adaptateur n'est PAS compatible avec @socket.io/redis-adapter.
    let auth = password
        .as_deref()
        .map(|p| format!(":{}@", percent_encoding::utf8_percent_encode(p, percent_encoding::NON_ALPHANUMERIC)))
        .unwrap_or_default();
    let adapter_client = redis::Client::open(format!("redis://{auth}{host}:{port}?protocol=resp3")).expect("URL Redis");
    let adapter = RedisAdapterCtr::new_with_redis_config(&adapter_client, RedisAdapterConfig::new().with_prefix("alfy-gw"))
        .await
        .expect("adaptateur Socket.IO Redis");
    let (sio_layer, io) = SocketIo::builder()
        .ping_interval(Duration::from_millis(25_000))
        .ping_timeout(Duration::from_millis(60_000))
        .max_payload(1_000_000)
        .with_state(app.clone())
        .with_adapter::<RedisAdapter<_>>(adapter)
        .build_layer();
    let _ = app.io.set(io.clone());
    let _ = io.ns("/", ws::connect::on_connect.with(ws::connect::auth_middleware)).await;
    let _ = io.ns("/server-nodes", ws::nodes_ns::on_connect.with(ws::nodes_ns::auth_middleware)).await;
    info!("Socket.IO: Redis adapter initialisé (multi-instances)");

    // ── HTTP ─────────────────────────────────────────────────────────────
    let router = Arc::new(http::routes::build());
    let shared = Shared { app: app.clone(), router };
    let axum_app = axum::Router::new().fallback(dispatch).with_state(shared).layer(sio_layer).layer(axum::middleware::from_fn(socketio_cors));

    let listener = match bind(cfg.port) {
        Ok(l) => l,
        Err(e) => {
            error!("Impossible d'écouter sur le port {} : {e}", cfg.port);
            std::process::exit(1);
        }
    };
    info!("🚀 Gateway AlfyChat démarré sur le port {}", cfg.port);
    info!("📡 WebSocket prêt à recevoir des connexions");

    // ── Tâches de fond ───────────────────────────────────────────────────
    {
        let app = app.clone();
        tokio::spawn(async move {
            app.monitoring.init().await;
            load_instances_from_db(&app).await;

            // Ce gateway dans le registre (multi-gateway), puis les autres depuis la base
            let name = env_str("GATEWAY_NAME", "Gateway Principal");
            let url = env_str("GATEWAY_PUBLIC_URL", &format!("http://localhost:{}", app.cfg.port));
            app.gateways.register(&app.gateway_id, &name, &url, None, true);
            app.monitoring.upsert_gateway(&app.gateway_id, &name, &url, true).await;
            for gw in app.monitoring.load_gateways().await {
                if gw.id != app.gateway_id {
                    app.gateways.register(&gw.id, &gw.name, &gw.url, Some(gw.enabled), false);
                }
            }

            ws::presence::spawn_auto_idle(&app);

            // Premier cycle immédiat puis toutes les MONITORING_INTERVAL ms
            let a2 = app.clone();
            tokio::spawn(async move {
                monitoring::run_cycle(&a2).await;
                let mut tick = tokio::time::interval(monitoring::interval());
                tick.tick().await;
                loop {
                    tick.tick().await;
                    monitoring::run_cycle(&a2).await;
                }
            });
            // Purge au démarrage puis toutes les 24 h
            let a3 = app.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
                loop {
                    tick.tick().await;
                    a3.monitoring.prune(30).await;
                }
            });
        });
    }

    // ── Arrêt gracieux (SIGTERM / Ctrl-C) ────────────────────────────────
    let shutdown = {
        let io = io.clone();
        async move {
            #[cfg(unix)]
            {
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            info!("Signal d'arrêt reçu, arrêt gracieux...");
            io.close().await;
        }
    };
    if let Err(e) = axum::serve(listener, axum_app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown).await {
        warn!("Serveur HTTP arrêté : {e}");
    }
}
