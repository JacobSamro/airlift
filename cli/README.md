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
   - `{ "policy": "sdkVersion" }` uses the config's `sdkVersion`;
   - anything else (e.g. `fingerprint`, `nativeVersion`) requires an explicit `--runtime-version <rv>`.
3. Runs `npx expo export` into a temporary directory (all platforms by default, or one via `--platform`).
4. Zips the export output and uploads it, along with the resolved Expo config and best-effort git branch/commit metadata.
5. Prints the new update group id and a per-channel released/pending table.

Channels that auto-release from the branch show `released`; channels requiring manual release show `pending`. With `--channel <name>`, if that channel is pending the CLI prints the exact `airlift promote` command to run — it never auto-promotes.

If the server responds with 409, an update with identical contents is already at the head of that branch; nothing is published.

### `airlift promote`

```sh
airlift promote --channel production --group <group_id>
```

Releases a previously published update group to a channel.

### `airlift rollback`

```sh
airlift rollback --channel production --runtime-version 1.2.0
```

Rolls the channel back to the previous release for that runtime version.

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
