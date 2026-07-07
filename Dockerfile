# Multi-stage build: Nuxt UI -> static Rust binary -> minimal runtime.

FROM oven/bun:1 AS web
WORKDIR /web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run generate

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
# Bring in the prebuilt UI so rust-embed can bundle it.
COPY --from=web /web/.output/public ./web/.output/public
RUN cargo build --release && strip target/release/airlift

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/airlift /usr/local/bin/airlift
VOLUME ["/var/lib/airlift"]
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/airlift"]
CMD ["--config", "/etc/airlift/config.toml", "serve"]
