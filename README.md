# AlfyChat — Gateway

Gateway centralisée WebSocket et reverse proxy pour AlfyChat.

![Node.js](https://img.shields.io/badge/Bun-1.2-black?logo=bun)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Socket.io](https://img.shields.io/badge/Socket.io-4-010101?logo=socket.io)
![License](https://img.shields.io/badge/License-Source_Available-blue)

## Rôle

La gateway est le point d'entrée unique de l'infrastructure AlfyChat. Elle assure :

- **Reverse proxy** vers les microservices REST
- **WebSocket** (Socket.io) pour la messagerie temps réel, la présence et les appels
- **Service registry** — enregistrement et découverte dynamique des instances
- **Rate limiting** par rôle (anonyme, utilisateur, admin)
- **Load balancing** avec fallback automatique
- **Monitoring** de la santé des services
- **Gestion des incidents** (page de statut publique)

## Stack technique

| Catégorie | Technologies |
|-----------|-------------|
| Runtime | Bun |
| Langage | TypeScript |
| WebSocket | Socket.io |
| Proxy | HTTP natif |
| Auth | JWT |
| Cache / Présence | Redis |
| Monitoring DB | SQLite (interne) |

## Architecture globale

```
Frontend (:4000)  →  Gateway (:3000)  ←  ce service
                         │
                         ├── users    (:3001)
                         ├── messages  (:3002)
                         ├── friends   (:3003)
                         ├── calls     (:3004)
                         ├── servers   (:3005)
                         ├── bots      (:3006)
                         └── media     (:3007)
```

## Démarrage

### Prérequis

- [Bun](https://bun.sh/) ≥ 1.2
- Redis 7

### Variables d'environnement

```env
PORT=3000
REDIS_URL=redis://localhost:6379
JWT_SECRET=
USERS_SERVICE_URL=http://localhost:3001
MESSAGES_SERVICE_URL=http://localhost:3002
FRIENDS_SERVICE_URL=http://localhost:3003
CALLS_SERVICE_URL=http://localhost:3004
SERVERS_SERVICE_URL=http://localhost:3005
BOTS_SERVICE_URL=http://localhost:3006
MEDIA_SERVICE_URL=https://media.alfychat.com
```

### Installation

```bash
bun install
```

### Développement

```bash
bun run dev
```

### Build production

```bash
bun run build
bun run start
```

### Docker

```bash
docker compose up gateway
```

## Structure du projet

```
src/
├── index.ts             # Point d'entrée, initialisation Socket.io
├── handlers/            # Gestionnaires d'événements WebSocket
├── services/            # Service registry, monitoring, Redis
├── types/               # Types TypeScript
└── utils/               # Proxy, rate limiting, utilitaires
```

## Contribution

Voir [CONTRIBUTING.md](./CONTRIBUTING.md).
