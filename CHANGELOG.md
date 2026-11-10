# Changelog

## [Unreleased]

## [0.1.0] - 2026-11-10

First release.

### Protocol and delivery

- Expo Updates protocol v0 + v1: multipart manifests, `noUpdateAvailable` /
  `rollBackToEmbedded` directives, RSA-SHA256 manifest signing with per-app
  generated certificates.
- Signing-key rotation: multiple code-signing keys per app; each manifest is
  signed with the `keyid` the build asks for, so builds in the field keep
  verifying after a rotation.
- Assets served as 307 redirects to presigned storage/CDN URLs,
  content-addressed and deduplicated per org.
- bsdiff incremental launch-bundle patches (SDK 55+ `A-IM: bsdiff` → `226 IM
  Used`, classic BSDIFF40): lazy background generation, integrity-gated
  inputs, not-beneficial cutoff, automatic full-bundle fallback.
- Manifest cache: check-ins are answered with no SQL and no RSA work
  (invalidated by SQLite update hooks; ~78k req/s, p95 0.6 ms on a laptop).

### Releases

- EAS-style branches + channels with per-channel auto-release/gated releases,
  promote, rollback, channel→branch repointing. Rollback republishes the
  previous update under a fresh identity, so devices already on the newer
  update move back.
- Progressive rollouts (release to N% of a channel's devices, stable
  `sha256(EAS-Client-ID:salt)` bucketing) and A/B channel splits (serve a
  second branch to a share of a channel). The asset endpoint enforces the
  same membership.
- Crash protection: updates a device reports in
  `Expo-Recent-Failed-Update-IDs` are never served to it again (remembered
  via `expo-server-defined-headers`); per-update and per-rollout crash-rate
  health.
- Republish an older update group as the newest.

### Governance

- Orgs, members, teams; custom roles over fine-grained capabilities (read,
  publish, release, channels, keys, protected); branch protection.
- Personal access tokens (`alt_`; all/org/app scope × read/publish/admin
  cap) with optional IP allowlists.
- Audit log with CSV / JSONL export.
- Sign-in: password, Google, generic OIDC (PKCE, JWKS RS256/384/512 + ES256)
  and SAML 2.0 (pure-Rust exclusive c14n + XML-DSig).

### Observability

- Device check-ins, adoption per update, daily series; Prometheus `/metrics`.
- Device geo map (GeoLite2 `.mmdb` or CDN country/city headers; IPs are
  never stored).
- JS error groups symbolicated with each update's uploaded sourcemap (Hermes
  stacks included), from `airlift-reporter` or OTLP.
- OTLP/HTTP JSON log and metric ingest with log search and metric charts.
  All telemetry lives in SQLite with retention pruning.

### Agents

- MCP server at `/mcp` (Streamable HTTP) with airlift as its own OAuth 2.1
  authorization server (RFC 9728 / 8414 discovery, RFC 7591 dynamic
  registration, PKCE S256, rotating refresh tokens). Agents act with the
  signed-in user's permissions, capped at what the consent screen granted.

### Operations

- Single binary: embedded SQLite (WAL), embedded Nuxt 4 dashboard, automatic
  Let's Encrypt TLS, figment config (`AIRLIFT_*` env, DB overrides win).
- Garbage collection with a grace window (`airlift gc` + background loop) for
  unreferenced assets, their sourcemaps, and bsdiff patch objects of deleted
  updates.

### Packages

- `airlift-cli` 0.1.1 (0.1.0 was an early preview): `init` (with `--keyid` for a rotated key), `publish`
  (uploads sourcemaps by default), `promote`, `rollback`, `republish`,
  `rollout`, `split`, `list`, `doctor`, `generate-certs`.
- `airlift-reporter` 0.1.0: reports uncaught errors, unhandled rejections and
  handled errors from React Native with the running update's id, for
  server-side symbolication.

### Testing

- On-device e2e in CI (real Expo SDK 58 release builds on an Android
  emulator and an iOS simulator, driven by Maestro): OTA update, rollback,
  rollback-to-embedded, new assets, bsdiff patch applied, gated channels,
  rollouts, channel repointing, a rotated signing key, symbolicated error
  reports and crash blocking.

[Unreleased]: https://github.com/jacobsamro/airlift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jacobsamro/airlift/releases/tag/v0.1.0
