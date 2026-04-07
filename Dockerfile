FROM oven/bun:1-alpine AS builder

WORKDIR /app

# Copier les fichiers de dépendances
COPY package.json bun.lockb* ./

# Installer les dépendances
RUN bun install

# Copier le code source
COPY . .

# Compiler TypeScript
RUN bun run build

FROM oven/bun:1-alpine
WORKDIR /app
COPY package.json bun.lockb* ./
RUN bun install --production
COPY --from=builder /app/dist ./dist

# Exposer le port
EXPOSE 3000

# Démarrer l'application
CMD ["bun", "run", "start"]
