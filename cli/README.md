# airlift-cli

Publish CLI for **airlift**, a self-hosted Expo OTA update server. Run it with `npx`:

```sh
npx airlift-cli --help
# or, once installed:
airlift --help
```

Requires Node 18+ (also works under Bun).

## Authentication

Every command needs a personal access token (`alt_...`). Provide it either way:

- **`AIRLIFT_TOKEN`** environment variable (recommended):

  ```sh
  export AIRLIFT_TOKEN=alt_xxxxxxxxxxxx
  ```

- `--token <pat>` flag on any command (takes precedence over the env var).

## Project configuration

`airlift init` writes an `airlift.json` at the project root:

```json
{
  "server": "https://updates.example.com",
  "org": "my-org",
  "app": "my-app",
  "appId": "…"
}
```

All commands read it (searching upward from the current directory). `--server`, `--org`, and `--app` flags override the file, which is useful for one-off commands against another app.

## Commands

### `airlift init`

```sh
airlift init --server https://updates.example.com --org my-org --app my-app [--token <pat>]
```

- Verifies the app exists on the server.
- Writes `airlift.json`.
- Downloads the code-signing certificate to `certs/certificate.pem`.
- If the project has an `app.json`, patches it:
  - `expo.updates.url` = `{server}/u/{appId}/manifest`
  - `expo.updates.enabled` = `true`
  - `expo.updates.codeSigningCertificate` = `./certs/certificate.pem`
  - `expo.updates.codeSigningMetadata` = `{ "keyid": "main", "alg": "rsa-v1_5-sha256" }`
  - `expo.updates.requestHeaders` = `{ "expo-channel-name": "production" }`
  - `expo.runtimeVersion` = `{ "policy": "appVersion" }` (only if not already set)
- If the project uses a dynamic config (`app.config.js`/`app.config.ts`), the CLI does not edit code; it prints the JSON snippet for you to merge manually.

**Important:** changing the update URL, code signing settings, or runtime version requires a new native build of your app.

### `airlift publish`

```sh
airlift publish --branch main [--channel production] [--message "fix crash"] [--platform all|ios|android]
```

1. Resolves your public Expo config via `npx expo config --json --type public`.
2. Determines the runtime version:
   - a literal `runtimeVersion` string is used as-is;
   - `{ "policy": "appVersion" }` uses the config's `version`;
   - `{ "policy": "sdkVersion" }` uses `exp@<sdkVersion>` (what builds request);
   - `ios.runtimeVersion` / `android.runtimeVersion` override the top-level value per platform
     (if they differ, publish each platform separately with `--platform`);
   - anything else (e.g. `fingerprint`, `nativeVersion`) requires an explicit `--runtime-version <rv>`.
3. Runs `npx expo export` into a temporary directory (all platforms by default, or one via `--platform`).
4. Zips the export output and uploads it, along with the resolved Expo config and best-effort git branch/commit metadata.
5. Prints the new update group id and a per-channel released/pending table.

Channels that auto-release from the branch show `released`; channels requiring manual release show `pending`. With `--channel <name>`, if that channel is pending the CLI prints the exact `airlift promote` command to run — it never auto-promotes.

If the server responds with 409, an update with identical contents is already at the head of that branch; nothing is published.

With `--rollout <percent>`, auto-release channels start a progressive rollout at that share instead of releasing to everyone (see `airlift rollout`).

### `airlift promote`

```sh
airlift promote --channel production --group <group_id>
```

Releases a previously published update group to a channel.

### `airlift rollback`

```sh
airlift rollback --channel production --runtime-version 1.2.0
```

Rolls the channel back to the previous release it shipped for that runtime version. The old update is re-served under a fresh identity, so devices already on the newer one actually switch back.

### `airlift rollout`

```sh
airlift rollout --channel production --group <group_id> --percent 10        # start
airlift rollout --channel production --runtime-version 1.2.0 --percent 50   # grow
airlift rollout --channel production --runtime-version 1.2.0 --percent 100  # complete
```

Progressive rollout: only the given share of devices gets the update; the rest keep the last full release. Devices are bucketed by `sha256(EAS-Client-ID:salt)`, so a device that is in at 10% stays in at 50%. Devices without a client id are never in. To pull a rollout back from devices, use `airlift rollback`.

### `airlift split`

```sh
airlift split --channel production --branch experiment --percent 20
airlift split --channel production --off
```

A/B split: a stable share of the channel's devices gets another branch (served through a managed `production~experiment` channel with its own releases, rollouts and rollbacks).

### `airlift republish`

```sh
airlift republish --group <group_id> [--channel production]
```

Publishes an existing update group again as a brand-new update (new ids, fresh timestamp, same assets). With `--channel` the copy is released there; otherwise it advances the group's branch like a publish.

### `airlift generate-certs`

```sh
airlift generate-certs [--keyid k2]
```

Rotates the code-signing key without breaking builds in the field: the server creates a new key (the private key never leaves it), the CLI writes `certs/certificate-<keyid>.pem` and points `app.json` at it (`codeSigningCertificate`, `codeSigningMetadata.keyid`). Existing builds keep verifying with their old key; make a new native build to switch.

### `airlift doctor`

```sh
airlift doctor
```

Checks the project against the server: update URL, code-signing certificate/keyid/alg match one of the app's keys, the request-header channel exists, each platform's runtime version has a release on it, and `expo-updates` is installed. Exits non-zero on problems.

### `airlift list`

```sh
airlift list [--branch main] [--limit 20]
```

Prints a table of updates: short id, branch, runtime version, platforms, group type, message, and creation time.

## Development

```sh
bun install
bun run typecheck   # tsc --noEmit
bun run build       # tsc -> dist/
node dist/index.js --help
```
