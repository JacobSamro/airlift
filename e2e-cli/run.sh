#!/usr/bin/env bash
# CLI end-to-end suite: every airlift CLI command against a real airlift
# server (with the S3 stub), using the real Expo project in e2e-device/app
# so `publish` runs a real `expo export`. No device needed.
#
#   e2e-cli/run.sh                 # build everything, then run the suite
#   SKIP_BUILD=1 e2e-cli/run.sh    # reuse existing builds
#
# Env overrides: AIRLIFT_BIN, S3_STUB_BIN (default: target/debug builds).
# Shares e2e-device/app with the device e2e: do not run both at once. The
# suite edits app.json / marker.js / airlift.json / certs there and puts
# them back when it finishes.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [ "${SKIP_BUILD:-}" != "1" ]; then
  if [ -z "${AIRLIFT_BIN:-}" ]; then
    log "cargo build (airlift + s3 stub)"
    (cd "$ROOT" && cargo build --locked --bin airlift --example s3_stub)
  fi
  log "build the CLI"
  (cd "$ROOT/cli" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)
  log "install the Expo fixture app"
  # The app depends on file:../../reporter, so its dist must exist first.
  (cd "$ROOT/reporter" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)
  (cd "$ROOT/e2e-device/app" && bun install --frozen-lockfile >/dev/null)
fi

log "run the CLI suite"
cd "$HERE"
exec bun test ./cli.test.ts --timeout 300000 "$@"
