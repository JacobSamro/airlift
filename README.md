# airlift

A self-hosted **Expo OTA update server**: a single Rust binary that implements
the [Expo Updates protocol](https://docs.expo.dev/technical-specs/expo-updates-1/)
(v0 + v1) with S3-compatible storage ([Tigris](https://www.tigrisdata.com/)),
an embedded web dashboard, and a small `npx` CLI for publishing. No Expo
account, no EAS subscription, no external database.

```
┌──────────────┐  npx airlift-cli publish   ┌─────────────────────────┐
│  your CI /   │ ─────────────────────────▶ │  airlift (one binary)   │
│  laptop      │                            │  SQLite + dashboard     │
└──────────────┘                            └───────────┬─────────────┘
                                                307 ▲   │ bundles/assets
        expo-updates client (your app) ────────────┘   ▼
                     manifest + signed updates      Tigris / S3
```

## Features

- **Full protocol implementation** — multipart manifests, protocol 0 and 1,
  `noUpdateAvailable` and `rollBackToEmbedded` directives, RSA-SHA256 code
  signing with per-app certificates (generated for you).
- **EAS-style branches + channels** — publish to a branch; channels (what
  builds point at) map to branches. Promote staging → production or roll back
  instantly by repointing, no re-upload.
- **Per-channel release gating** — channels are auto-release or gated: gated
  channels serve nothing new until a human promotes in the dashboard/CLI.
- **Assets never transit the server twice** — files are content-addressed,
  deduplicated per org, and served as `307` redirects to presigned S3/CDN
  URLs.
- **bsdiff incremental updates (SDK 55+)** — devices that send `A-IM: bsdiff`
  get a binary patch between their current launch bundle and the new one
  (often 5–20× smaller), generated lazily in the background and served as
  `226 IM Used`; anything else falls back to the full bundle automatically.
- **Progressive rollouts & A/B splits** — release to N% of a channel's
  devices (stable `sha256(EAS-Client-ID:salt)` bucketing, no per-device
  state; devices in at N% stay in as it grows), or serve a second branch to a
  share of a channel. The asset endpoint enforces the same check.
- **Crash protection & per-update health** — updates a device reports in
  `Expo-Recent-Failed-Update-IDs` are never served to it again (remembered via
  `expo-server-defined-headers`); each update/rollout shows a crash-rate badge.
- **Fast manifests** — an in-process cache (auto-invalidated by SQLite hooks)
  answers check-ins with no SQL and no RSA work: ~78k req/s, p95 0.6 ms on a
  laptop.
- **Device observability (SQLite only)** — device geo map (GeoLite2 or CDN
  headers), JS error groups symbolicated with each update's sourcemap
  (`airlift-reporter` or OTLP), OTLP log and metric viewers.
- **Client monitoring** — device check-ins, per-update adoption, daily
  activity series; Prometheus metrics at `/metrics`.
- **Multi-tenant & governance** — orgs, members, teams; custom roles over
  fine-grained capabilities; branch protection; personal access tokens with
  scopes, caps and IP allowlists; audit log with CSV/JSONL export; Google,
  OIDC and SAML 2.0 single sign-on.
- **MCP server for agents** — `/mcp` (Streamable HTTP) with airlift as its own
  OAuth 2.1 authorization server (discovery, dynamic registration, PKCE):
  agents list, publish, roll out and roll back with the signed-in user's
  permissions.
- **Key rotation** — multiple code-signing keys per app; builds pick theirs
  by `keyid`, so rotating never breaks binaries in the field.
- **Single self-contained binary** — embedded SQLite (WAL), embedded Nuxt
  dashboard, automatic Let's Encrypt TLS. Runs on a minimal VPS.

## Quick start

### 1. Run the server

One-liner on a Linux box (installs a systemd service):

```sh
curl -fsSL https://raw.githubusercontent.com/jacobsamro/airlift/master/install.sh | sudo sh
```

or Docker:

```sh
docker run -d --name airlift \
  -p 80:80 -p 443:443 \
  -v airlift-data:/var/lib/airlift \
  -e AIRLIFT_STORAGE__BUCKET=my-updates-bucket \
  -e AIRLIFT_STORAGE__ACCESS_KEY_ID=... \
  -e AIRLIFT_STORAGE__SECRET_ACCESS_KEY=... \
  ghcr.io/jacobsamro/airlift:latest
```

Open the server's address, complete the first-run setup (creates the admin
account and your org), add your domain under **Settings → Domains** for
automatic TLS, and create an **app** — airlift generates its RSA signing
certificate. Create a personal access token under **Tokens** (scope it to the
org, cap `publish`).

### 2. Wire up your Expo app

```sh
cd my-expo-app
npx airlift-cli init --server https://updates.example.com --org acme --app mobile
```

This points `updates.url` at your server, downloads the app's code-signing
certificate, and configures `codeSigningMetadata` + the `expo-channel-name`
request header. **Make a new native build after this step** — these values are
baked into the binary.

### 3. Publish

```sh
export AIRLIFT_TOKEN=alt_…
npx airlift-cli publish --branch production --message "fix login crash"
```

The CLI runs `expo export`, uploads the bundle + assets (deduplicated), and
the update goes live on every auto-release channel tracking that branch.
Gated channels show up as `pending` until promoted:

```sh
npx airlift-cli promote --channel production --group <group-id>
npx airlift-cli rollback --channel production --runtime-version 1.0.0
```

## Concepts

| | |
|---|---|
| **Branch** | A stream of published updates (auto-created on publish). |
| **Channel** | What a build points at (`expo-channel-name`). Maps to a branch. |
| **Update group** | One publish event (iOS + Android updates together). |
| **Release pointer** | Per (channel, runtime version): which group is served. |
| **Auto vs gated** | Auto channels advance on publish; gated wait for promote. |
| **Rollback to embedded** | Protocol directive: devices revert to the update embedded in the binary. |

## Server endpoints

- `GET /u/{app-id}/manifest` — the Expo Updates manifest endpoint (this is
  what `updates.url` points at).
- `GET /u/{app-id}/assets/{sha256}` — 307 redirect to a presigned storage URL.
- `GET /metrics` — Prometheus exposition (`Bearer <server.metrics_token>`, or an
  instance-admin session).
- `GET /healthz` — liveness.
- `/api/v1/…` — dashboard/CLI REST API (session cookie or `Bearer alt_…` PAT).
- `POST /u/{app-id}/errors`, `/u/{app-id}/otlp/v1/{logs,metrics}` — device
  telemetry (airlift-reporter / OTLP HTTP JSON).
- `POST /mcp` — MCP server for agents (OAuth: `/.well-known/oauth-protected-resource`,
  `/.well-known/oauth-authorization-server`, `/oauth/register`, `/oauth/authorize`,
  `/oauth/token`).

## Agents (MCP)

Add `https://updates.example.com/mcp` as a remote MCP server in your agent
(Claude Code: `claude mcp add --transport http airlift https://updates.example.com/mcp`).
The client discovers airlift's OAuth server, registers itself, and opens a
consent page where you choose what it may do (read / publish / admin, all orgs
or one). It then acts with exactly your permissions (plus that cap); the grant
shows up under **Access Tokens** as `MCP: <client>` and can be revoked there.
Tools: `list_apps`, `get_app`, `list_updates`, `publish` (base64 export zip),
`promote`, `start_rollout`, `set_rollout`, `rollback`, `republish`,
`list_errors`, `app_stats`.

## Configuration

Config file (`/etc/airlift/config.toml`, see `config.example.toml`) or
`AIRLIFT_*` environment variables (nested keys use `__`, e.g.
`AIRLIFT_STORAGE__BUCKET`). Storage, TLS contact email, and Google OAuth are
also editable live in the dashboard (stored in the DB, override the file).

Any S3-compatible store works (Tigris, R2, MinIO, DigitalOcean Spaces, AWS);
set `storage.cdn_url` to serve asset redirects from a custom domain/CDN.

## Development

```sh
cd web && bun install && bun run generate   # dashboard (rust-embed needs it)
cargo test                                  # unit + e2e (in-process S3 stub, no Docker)
cargo clippy --all-targets -- -D warnings
cargo run -- --config ./config.toml serve
```

The e2e suite boots the real binary against an in-process S3 stub and drives
it like a device: it parses multipart manifests, verifies the RSA signatures
against the served certificate, and exercises publish/promote/rollback/
directive flows.

```sh
e2e-cli/run.sh                              # CLI e2e (~1 min after builds)
```

The CLI suite runs every `airlift-cli` command (init, publish, list, promote,
rollback, rollout, split, republish, doctor, generate-certs, flag overrides,
token and connection errors) against a real `airlift serve` and a real Expo
project (`e2e-device/app`, so `publish` runs a real `expo export`). Each step
checks the CLI output, the server state, and what an expo-updates client is
served: signature, bundle hash, and which publish the bundle came from.

## Disclaimer

airlift is **not officially supported or affiliated with [Expo](https://expo.dev/)**.
This is an independent open-source project.

## License

MIT
