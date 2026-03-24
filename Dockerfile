FROM oven/bun:1-alpine

WORKDIR /app

# Copier les fichiers de dépendances
COPY package.json bun.lockb* ./

# Installer les dépendances
RUN bun install

# Copier le code source
COPY . .

# Exposer le port
EXPOSE 3000

# Démarrer l'application (Bun exécute TypeScript nativement)
CMD ["bun", "src/index.ts"]
