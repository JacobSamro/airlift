#!/usr/bin/env bash
# On-device OTA e2e: a real Expo release build with expo-updates, talking to
# a real airlift server, driven by Maestro.
#
#   e2e-device/run.sh android   # needs a running emulator/device (adb)
#   e2e-device/run.sh ios       # needs a booted simulator (SIM_UDID or "booted")
#
# What it covers, all on the device:
#   embedded launch → publish v2 → fetch+reload → up-to-date → cold start
#   keeps v2 → publish v3 → channel rollback (back to v2) →
#   rollback-to-embedded → cold start stays embedded → publish v4 recovers.
#
# Needs: cargo, bun, node (npx), maestro, plus Xcode or the Android SDK.
# Env overrides: AIRLIFT_BIN, S3_STUB_BIN, SKIP_CARGO_BUILD=1, SIM_UDID,
# AIRLIFT_PORT, S3_PORT, E2E_WORK_DIR, E2E_DRY_RUN=1 (no device: exercises
# server + CLI + real `expo export` publishes only).
set -euo pipefail

PLATFORM="${1:-}"
case "$PLATFORM" in
  android | ios) ;;
  *) echo "usage: $0 android|ios" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
APP="$HERE/app"
WORK="${E2E_WORK_DIR:-$HERE/.work}"
PORT="${AIRLIFT_PORT:-47300}"
S3_PORT="${S3_PORT:-47301}"
SERVER="http://127.0.0.1:$PORT"
ORG=acme
APP_SLUG=e2e
RUNTIME=1.0.0
CHANNEL=production
CLI="$ROOT/cli/dist/index.js"
AIRLIFT_BIN="${AIRLIFT_BIN:-$ROOT/target/release/airlift}"
S3_STUB_BIN="${S3_STUB_BIN:-$ROOT/target/release/examples/s3_stub}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/maestro"

# The run edits app.json (airlift init) and marker.js (per publish); put
# both back however we exit.
cp "$APP/app.json" "$WORK/app.json.orig"
cp "$APP/marker.js" "$WORK/marker.js.orig"
PIDS=()
cleanup() {
  local code=$?
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  cp "$WORK/app.json.orig" "$APP/app.json"
  cp "$WORK/marker.js.orig" "$APP/marker.js"
  if [ $code -ne 0 ]; then
    echo "---- airlift.log (tail) ----"
    tail -n 80 "$WORK/airlift.log" 2>/dev/null || true
  fi
  exit $code
}
trap cleanup EXIT

# ───────────── build server + stub + CLI ─────────────
if [ "${SKIP_CARGO_BUILD:-}" != "1" ]; then
  log "cargo build (airlift + s3 stub)"
  (cd "$ROOT" && cargo build --release --locked --bin airlift --example s3_stub)
fi
log "build publish CLI"
(cd "$ROOT/cli" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)

# ───────────── start S3 stub + airlift ─────────────
log "start s3 stub on :$S3_PORT and airlift on :$PORT"
"$S3_STUB_BIN" "127.0.0.1:$S3_PORT" >"$WORK/s3.log" 2>&1 &
PIDS+=($!)
RUST_LOG="${RUST_LOG:-info}" \
  AIRLIFT_DATABASE__PATH="$WORK/airlift.db" \
  AIRLIFT_SERVER__HTTP_ADDR="127.0.0.1:$PORT" \
  AIRLIFT_SERVER__PUBLIC_URL="$SERVER" \
  AIRLIFT_TLS__ENABLED=false \
  AIRLIFT_PATCHES__POLL_SECS=1 \
  AIRLIFT_STORAGE__ENDPOINT="http://127.0.0.1:$S3_PORT" \
  AIRLIFT_STORAGE__BUCKET=e2e \
  AIRLIFT_STORAGE__REGION=us-east-1 \
  AIRLIFT_STORAGE__ACCESS_KEY_ID=e2e \
  AIRLIFT_STORAGE__SECRET_ACCESS_KEY=e2e \
  AIRLIFT_STORAGE__FORCE_PATH_STYLE=true \
  "$AIRLIFT_BIN" --config "$WORK/none.toml" serve >"$WORK/airlift.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  curl -fsS "$SERVER/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "$SERVER/healthz" >/dev/null || die "airlift did not become healthy"

# ───────────── instance setup: admin, app, publish token ─────────────
log "setup instance, app, token"
JAR="$WORK/cookies.txt"
api() { # method path [json]
  curl -fsS -b "$JAR" -c "$JAR" -X "$1" "$SERVER$2" \
    -H 'content-type: application/json' ${3:+-d "$3"}
}
api POST /api/v1/setup '{"email":"admin@example.com","username":"admin","password":"password123","org_slug":"'$ORG'","org_name":"Acme"}' >/dev/null
api POST "/api/v1/orgs/$ORG/apps" '{"slug":"'$APP_SLUG'","name":"airlift e2e"}' >/dev/null
export AIRLIFT_TOKEN
AIRLIFT_TOKEN="$(api POST /api/v1/tokens '{"name":"device-e2e","org":"'$ORG'","permission":"publish"}' | jq -r .token)"
[ -n "$AIRLIFT_TOKEN" ] && [ "$AIRLIFT_TOKEN" != null ] || die "no token"

cli() { (cd "$APP" && node "$CLI" "$@"); }

log "airlift init (cert + expo.updates config)"
cli init --server "$SERVER" --org "$ORG" --app "$APP_SLUG"

# ───────────── native release build + install ─────────────
(cd "$APP" && bun install --frozen-lockfile)

DEVICE_ARGS=()
if [ "${E2E_DRY_RUN:-}" = 1 ]; then
  log "E2E_DRY_RUN=1: skipping native build and Maestro (server + CLI only)"
elif [ "$PLATFORM" = android ]; then
  adb wait-for-device
  ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
  log "prebuild + assembleRelease (abi $ABI)"
  (cd "$APP" && CI=1 npx expo prebuild --platform android --clean --no-install)
  (cd "$APP/android" && ./gradlew assembleRelease --no-daemon -PreactNativeArchitectures="$ABI")
  adb install -r "$APP/android/app/build/outputs/apk/release/app-release.apk"
  # The emulator's 127.0.0.1 is itself; tunnel the server + stub ports.
  adb reverse "tcp:$PORT" "tcp:$PORT"
  adb reverse "tcp:$S3_PORT" "tcp:$S3_PORT"
else
  UDID="${SIM_UDID:-booted}"
  log "prebuild + xcodebuild Release (simulator $UDID)"
  (cd "$APP" && CI=1 npx expo prebuild --platform ios --clean)
  WS="$(ls -d "$APP"/ios/*.xcworkspace | head -n1)"
  SCHEME="$(basename "$WS" .xcworkspace)"
  DEST='generic/platform=iOS Simulator'
  if [ "$UDID" != booted ]; then DEST="id=$UDID"; fi
  xcodebuild -workspace "$WS" -scheme "$SCHEME" -configuration Release \
    -sdk iphonesimulator -destination "$DEST" ONLY_ACTIVE_ARCH=YES \
    -derivedDataPath "$WORK/xcode" CODE_SIGNING_ALLOWED=NO build -quiet
  xcrun simctl install "$UDID" "$WORK/xcode/Build/Products/Release-iphonesimulator/$SCHEME.app"
  if [ "$UDID" != booted ]; then DEVICE_ARGS=(--device "$UDID"); fi
fi

# ───────────── the scenario ─────────────
STEP=0
flow() { # flow-file KEY=VAL...
  local file="$1"; shift
  STEP=$((STEP + 1))
  local env_args=()
  for kv in "$@"; do env_args+=(-e "$kv"); done
  log "[$STEP] maestro $file $*"
  if [ "${E2E_DRY_RUN:-}" = 1 ]; then return 0; fi
  maestro ${DEVICE_ARGS[@]+"${DEVICE_ARGS[@]}"} test --debug-output "$WORK/maestro/$STEP-${file%.yaml}" \
    ${env_args[@]+"${env_args[@]}"} "$HERE/flows/$file"
}
publish() { # marker
  printf "// Rewritten by e2e-device/run.sh before each publish; the build embeds \"embedded\".\nexport const MARKER = '%s';\n" "$1" >"$APP/marker.js"
  log "publish $1"
  cli publish --branch "$CHANNEL" --platform "$PLATFORM" --message "$1"
}

flow launch.yaml MARKER=embedded ORIGIN=embedded

publish v2
flow update.yaml MARKER=v2 ORIGIN=update
flow up-to-date.yaml
flow launch.yaml MARKER=v2 ORIGIN=update

publish v3
flow update.yaml MARKER=v3 ORIGIN=update

log "rollback channel $CHANNEL (v3 → v2)"
cli rollback --channel "$CHANNEL" --runtime-version "$RUNTIME"
flow update.yaml MARKER=v2 ORIGIN=update

log "rollback-to-embedded on branch $CHANNEL"
curl -fsS -X POST "$SERVER/api/v1/orgs/$ORG/apps/$APP_SLUG/branches/$CHANNEL/rollback-to-embedded" \
  -H "authorization: Bearer $AIRLIFT_TOKEN" -H 'content-type: application/json' \
  -d '{"runtime_version":"'$RUNTIME'"}' >/dev/null
flow update.yaml MARKER=embedded ORIGIN=embedded
flow launch.yaml MARKER=embedded ORIGIN=embedded

publish v4
flow update.yaml MARKER=v4 ORIGIN=update

log "server-side counters"
curl -fsS "$SERVER/metrics" | grep -E '^airlift_(manifest|asset|patch)' || true

log "PASS ($PLATFORM)"
