# Gateway AlfyChat (Rust) — build multi-étapes. Le contexte de build est ce dossier.
FROM rust:1-bookworm AS build
WORKDIR /src

# Dépendances d'abord : cette couche n'est reconstruite que si Cargo.toml / Cargo.lock changent.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src public/errors && echo 'fn main() {}' > src/main.rs \
    && touch public/index.html public/errors/404.html public/errors/500.html \
    && cargo build --release; \
    rm -rf src public

# Code réel. `public/` est embarqué dans le binaire (pages d'accueil et d'erreur).
COPY public ./public
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 gateway
COPY --from=build /src/target/release/gateway /usr/local/bin/gateway
USER gateway
EXPOSE 3000
CMD ["gateway"]
