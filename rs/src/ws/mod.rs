//! Temps réel Socket.IO.

pub mod internal;

/// Room Socket.IO d'un salon de serveur, NAMESPACÉE par serveur : un salon revendiqué à tort
/// ne reçoit jamais que les diffusions de son propre serveur.
pub fn ch_room(server_id: &str, channel_id: &str) -> String {
    format!("ch:{server_id}:{channel_id}")
}
