//! AlfyChat — gateway (Rust). Port de `gateway/src` (TypeScript/Express + Socket.IO).

mod anomaly;
mod config;
mod http;
mod json;
mod nodes;
mod state;
mod ws;
mod iso;
mod lb;
mod mailer;
mod monitoring_db;
mod perms;
mod ratelimit;
mod redis_client;
mod security;
mod svc;
mod validation;
mod monitoring;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    if let Err(e) = config::init() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::security::*;

    #[test]
    fn api_path_strips_version() {
        assert_eq!(api_path("/api/v1/users?x=1"), "/api/users?x=1");
        assert_eq!(api_path("/API/V12"), "/api");
        assert_eq!(api_path("/api/v1x/users"), "/api/v1x/users");
        assert_eq!(api_path("/api/users"), "/api/users");
    }

    #[test]
    fn rewrite_node_path_cases() {
        assert_eq!(rewrite_node_path("/api/servers/s1/channels", "s1"), "/channels");
        assert_eq!(rewrite_node_path("/api/servers/s1", "s1"), "/");
        assert_eq!(rewrite_node_path("/api/servers/s1/channels/c 1/messages?limit=5", "s1"), "/messages?limit=5&channelId=c%201");
        assert_eq!(rewrite_node_path("/api/servers/s1/channels/c1/messages", "s1"), "/messages?channelId=c1");
        assert_eq!(rewrite_node_path("/api/v1/servers/s1/members?a=1?b=2", "s1"), "/members?a=1");
    }

    #[test]
    fn uri_component() {
        assert_eq!(encode_uri_component("a b/é!'()*~"), "a%20b%2F%C3%A9!'()*~");
    }

    #[test]
    fn safe_segment() {
        assert!(is_safe_file_segment("a.png"));
        assert!(!is_safe_file_segment("../a"));
        assert!(!is_safe_file_segment("a..b"));
        assert!(!is_safe_file_segment(".a"));
    }
}
