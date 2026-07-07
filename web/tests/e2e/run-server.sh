#!/usr/bin/env bash
# Start an airlift instance for the Playwright dashboard e2e: fresh temp DB, TLS
# off, lazy/dummy storage (most UI flows need no S3).
#
# In CI set AIRLIFT_BIN to a prebuilt (release) binary — it embeds the UI. Locally
# this builds the debug binary, which serves web/.output/public from disk, so the
# UI is regenerated first.
set -euo pipefail

WEB="$(cd "$(dirname "$0")/../.." && pwd)"   # web/
ROOT="$(cd "$WEB/.." && pwd)"                # repo root
PORT="${E2E_PORT:-8099}"
DB="$WEB/tests/e2e/.tmp/e2e.db"

mkdir -p "$(dirname "$DB")"
rm -f "$DB" "$DB-shm" "$DB-wal"

export AIRLIFT_SERVER__HTTP_ADDR="127.0.0.1:${PORT}"
export AIRLIFT_SERVER__PUBLIC_URL="http://127.0.0.1:${PORT}"
export AIRLIFT_TLS__ENABLED=false
export AIRLIFT_DATABASE__PATH="$DB"
export AIRLIFT_STORAGE__ENDPOINT="${AIRLIFT_STORAGE__ENDPOINT:-http://127.0.0.1:59000}"
export AIRLIFT_STORAGE__BUCKET="${AIRLIFT_STORAGE__BUCKET:-airlift}"
export AIRLIFT_STORAGE__REGION="${AIRLIFT_STORAGE__REGION:-us-east-1}"
export AIRLIFT_STORAGE__ACCESS_KEY_ID="${AIRLIFT_STORAGE__ACCESS_KEY_ID:-test}"
export AIRLIFT_STORAGE__SECRET_ACCESS_KEY="${AIRLIFT_STORAGE__SECRET_ACCESS_KEY:-test}"
export AIRLIFT_STORAGE__FORCE_PATH_STYLE=true
export RUST_LOG="${RUST_LOG:-warn}"

# CI sets AIRLIFT_BIN to a prebuilt (release) binary that embeds the UI. Locally,
# regenerate the on-disk UI (the debug build reads it from disk) and let cargo
# build + locate the binary — no hardcoded target path, so it stays portable.
if [ -n "${AIRLIFT_BIN:-}" ]; then
  exec "$AIRLIFT_BIN" -c /nonexistent serve
else
  (cd "$WEB" && bun run generate)
  cd "$ROOT"
  exec cargo run --quiet --bin airlift -- -c /nonexistent serve
fi
