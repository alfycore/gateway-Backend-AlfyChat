# AlfyChat — gateway (Rust)

Point d'entrée unique de la plateforme (port 3000) : API HTTP (proxy vers les microservices, répartition de charge,
administration), Socket.IO (temps réel) et espace de noms `/server-nodes` (serveurs auto-hébergés).

Réécriture en Rust du gateway TypeScript/Express : mêmes routes, mêmes événements Socket.IO, mêmes variables
d'environnement, mêmes tables MySQL et clés Redis. La version TypeScript reste sur la branche `main`.

## Pile
`axum` (HTTP) · `socketioxide` + `socketioxide-redis` (Socket.IO v4, multi-instances) · `redis` · `sqlx` (MySQL) ·
`reqwest` (proxy et appels aux services) · `jsonwebtoken` · `lettre` (alertes e-mail).

## Prérequis
- **Redis ≥ 7** (protocole RESP3 exigé par l'adaptateur Socket.IO).
- ⚠️ L'adaptateur `socketioxide-redis` n'est **pas compatible** avec `@socket.io/redis-adapter` : ne jamais faire
  cohabiter un gateway Node et un gateway Rust sur le même Redis pendant une bascule (préfixe Redis distinct : `alfy-gw`).

## Lancer
```bash
cargo run --release            # variables : voir .env (JWT_SECRET et INTERNAL_SECRET obligatoires)
cargo test                     # tests unitaires
docker build -t alfychat-gateway .
```

## Tests de parité avec la version TypeScript
`tools/go-rewrite-parity/gateway/` (dépôt racine) : faux microservices + scénario Socket.IO (50 évènements) + 44 requêtes
HTTP rejouées sur le TS (`git archive main`, construit) et sur le Rust, puis comparées.

## Écarts connus
- Une erreur d'authentification Socket.IO n'expose que `message` (pas le champ `data` du TS, p. ex. `bannedUntil`) :
  socketioxide ne transmet que le texte.
- Les paquets d'événements portant plusieurs arguments de données ne sont pas pris en charge (le client n'en envoie qu'un).
