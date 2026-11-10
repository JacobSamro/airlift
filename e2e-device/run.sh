#!/usr/bin/env bash
# On-device OTA e2e: a real Expo release build with expo-updates, talking to
# a real airlift server, driven by Maestro.
#
#   e2e-device/run.sh android   # needs a running emulator/device (adb)
#   e2e-device/run.sh ios       # needs a booted simulator (SIM_UDID or "booted")
#
# What it covers, all on the device (built against a rotated signing key,
# so every update must be signed with the keyid the build asks for):
#   embedded launch → publish v2 → fetch+reload → up-to-date → cold start
#   keeps v2 → publish v3 → channel rollback (back to v2) →
#   rollback-to-embedded → cold start stays embedded → publish v4 recovers →
#   update-only image asset → bsdiff patch applied (no full fallback) →
#   gated channel + promote → staged rollout 0.001% → 100% → channel
#   repoint to another branch and back → airlift-reporter error symbolicated
#   to the App.js line → crash-on-launch update rolled back by the client
#   and refused by the server from then on.
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
RUNTIME="$(jq -r .expo.runtimeVersion "$APP/app.json")"
CHANNEL=production
CLI="$ROOT/cli/dist/index.js"
AIRLIFT_BIN="${AIRLIFT_BIN:-$ROOT/target/release/airlift}"
S3_STUB_BIN="${S3_STUB_BIN:-$ROOT/target/release/examples/s3_stub}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[[ "$RUNTIME" =~ ^[0-9A-Za-z._-]+$ ]] || die "app.json expo.runtimeVersion must be a plain string (got '$RUNTIME')"

# Only ever wipe the default dir or one this script created (tagged .e2e-work).
if [ "$WORK" != "$HERE/.work" ] && [ -e "$WORK" ] && [ ! -e "$WORK/.e2e-work" ] \
  && [ -n "$(ls -A "$WORK" 2>/dev/null)" ]; then
  die "refusing to wipe $WORK: not an e2e work dir (no .e2e-work marker)"
fi
rm -rf "$WORK"
mkdir -p "$WORK/maestro"
touch "$WORK/.e2e-work"

# The run edits app.json (airlift init) and marker.js (per publish); put
# both back however we exit. The marker snapshot is normalized to
# "embedded" so a run killed mid-way (trap skipped) can't poison the next
# build's embedded bundle.
cp "$APP/app.json" "$WORK/app.json.orig"
sed "s/MARKER = '.*'/MARKER = 'embedded'/" "$APP/marker.js" >"$WORK/marker.js.orig"
cp "$WORK/marker.js.orig" "$APP/marker.js"
PIDS=()
cleanup() {
  local code=$?
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  cp "$WORK/app.json.orig" "$APP/app.json"
  cp "$WORK/marker.js.orig" "$APP/marker.js"
  if [ $code -ne 0 ]; then
    echo "---- airlift.log (tail) ----"
    tail -n 80 "$WORK/airlift.log" 2>/dev/null || true
    echo "---- s3.log (tail) ----"
    tail -n 40 "$WORK/s3.log" 2>/dev/null || true
  fi
  exit $code
}
trap cleanup EXIT

# ───────────── build server + stub + CLI ─────────────
if [ "${SKIP_CARGO_BUILD:-}" != "1" ]; then
  log "cargo build (airlift + s3 stub)"
  (cd "$ROOT" && cargo build --release --locked --bin airlift --example s3_stub)
fi
log "build publish CLI + airlift-reporter"
(cd "$ROOT/cli" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)
# The app depends on file:../../reporter, so its dist must exist first.
(cd "$ROOT/reporter" && bun install --frozen-lockfile >/dev/null && bun run build >/dev/null)

# ───────────── start S3 stub + airlift ─────────────
log "start s3 stub on :$S3_PORT and airlift on :$PORT"
for p in "$PORT" "$S3_PORT"; do
  if curl -s -o /dev/null "http://127.0.0.1:$p/"; then
    die "port $p is already in use (leftover run?); stop it or set AIRLIFT_PORT/S3_PORT"
  fi
done
"$S3_STUB_BIN" "127.0.0.1:$S3_PORT" >"$WORK/s3.log" 2>&1 &
PIDS+=($!)
RUST_LOG="${RUST_LOG:-info,tower_http=debug}" \
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
AIRLIFT_PID=$!
PIDS+=("$AIRLIFT_PID")
for _ in $(seq 1 100); do
  kill -0 "$AIRLIFT_PID" 2>/dev/null || die "airlift exited during startup (see $WORK/airlift.log)"
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

# Key rotation: the build embeds a second key's certificate, so every OTA
# step below only passes if the server signs with the keyid this build asks
# for (a "main" signature fails the device's verification).
KEYID=k2
log "rotate signing key: add $KEYID, build against it"
api POST "/api/v1/orgs/$ORG/apps/$APP_SLUG/signing-keys" '{"keyid":"'$KEYID'"}' >/dev/null

log "airlift init (cert + expo.updates config, keyid $KEYID)"
cli init --server "$SERVER" --org "$ORG" --app "$APP_SLUG" --keyid "$KEYID"
[ "$(jq -r .expo.updates.codeSigningMetadata.keyid "$APP/app.json")" = "$KEYID" ] \
  || die "init did not set codeSigningMetadata.keyid to $KEYID"

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
  # Fresh install: a previous run's downloaded updates must not leak in.
  adb uninstall dev.airlift.e2e >/dev/null 2>&1 || true
  adb install "$APP/android/app/build/outputs/apk/release/app-release.apk"
  # The emulator's 127.0.0.1 is itself; tunnel the server + stub ports.
  adb reverse "tcp:$PORT" "tcp:$PORT"
  adb reverse "tcp:$S3_PORT" "tcp:$S3_PORT"
else
  # Pin one concrete simulator so build, install and Maestro all agree.
  UDID="${SIM_UDID:-$(xcrun simctl list devices booted -j | jq -r '[.devices[][] | select(.state == "Booted")][0].udid // empty')}"
  [ -n "$UDID" ] || die "no booted iOS simulator (boot one or set SIM_UDID)"
  log "prebuild + xcodebuild Release (simulator $UDID)"
  (cd "$APP" && CI=1 npx expo prebuild --platform ios --clean)
  WS="$(find "$APP/ios" -maxdepth 1 -name '*.xcworkspace' | head -n1)"
  SCHEME="$(basename "$WS" .xcworkspace)"
  xcodebuild -workspace "$WS" -scheme "$SCHEME" -configuration Release \
    -sdk iphonesimulator -destination "id=$UDID" ONLY_ACTIVE_ARCH=YES \
    -derivedDataPath "$WORK/xcode" CODE_SIGNING_ALLOWED=NO build -quiet
  # Fresh install: a previous run's downloaded updates must not leak in.
  xcrun simctl uninstall "$UDID" dev.airlift.e2e >/dev/null 2>&1 || true
  xcrun simctl install "$UDID" "$WORK/xcode/Build/Products/Release-iphonesimulator/$SCHEME.app"
  DEVICE_ARGS=(--device "$UDID")
fi

# ───────────── the scenario ─────────────
STEP=0
flow() { # flow-file KEY=VAL...
  local file="$1"; shift
  STEP=$((STEP + 1))
  local env_args=()
  for kv in "$@"; do env_args+=(-e "$kv"); done
  case " $* " in *" EXTRA="*) ;; *) env_args+=(-e EXTRA=none) ;; esac
  case " $* " in *" REASON="*) ;; *) env_args+=(-e 'REASON=.*') ;; esac
  log "[$STEP] maestro $file $*"
  if [ "${E2E_DRY_RUN:-}" = 1 ]; then return 0; fi
  local out="$WORK/maestro/$STEP-${file%.yaml}.out"
  # Reinstalling the driver costs ~1 min per step on iOS; once one step
  # passed, the installed driver is known good, so keep it.
  local reinstall=()
  if [ -n "$DRIVER_OK" ]; then reinstall=(--no-reinstall-driver); fi
  if run_maestro "$out" "$file" ${reinstall[@]+"${reinstall[@]}"} ${env_args[@]+"${env_args[@]}"}; then
    DRIVER_OK=1
    return 0
  fi
  # Maestro's iOS XCTest driver sometimes misses its startup window on a
  # loaded runner; that fails before any flow command ran, so retry once
  # with a fresh driver install.
  if grep -q "driver not ready in time" "$out"; then
    log "[$STEP] Maestro driver startup timed out; retrying once"
    if run_maestro "$out.retry" "$file" ${env_args[@]+"${env_args[@]}"}; then return 0; fi
  fi
  device_diagnostics
  die "step $STEP ($file $*) failed"
}
DRIVER_OK=""
run_maestro() { # out-file flow-file maestro-args...
  local out="$1" file="$2"; shift 2
  maestro ${DEVICE_ARGS[@]+"${DEVICE_ARGS[@]}"} test --debug-output "$WORK/maestro/$STEP-${file%.yaml}" \
    "$@" "$HERE/flows/$file" 2>&1 | tee "$out"
  return "${PIPESTATUS[0]}"
}
# Give Maestro's iOS driver longer than its default to come up on CI.
export MAESTRO_DRIVER_STARTUP_TIMEOUT="${MAESTRO_DRIVER_STARTUP_TIMEOUT:-180000}"
# On a failed step: print what the app shows (status carries the
# expo-updates error) and save the device log next to the server logs.
device_diagnostics() {
  echo "---- app screen (key:value labels) ----"
  maestro ${DEVICE_ARGS[@]+"${DEVICE_ARGS[@]}"} hierarchy 2>/dev/null \
    | grep -oE '(marker|origin|update-id|channel|status|extra):[^"]*' | sort -u || true
  if [ "$PLATFORM" = android ]; then
    adb logcat -d >"$WORK/device.log" 2>&1 || true
    echo "---- device log (expo-updates, tail) ----"
    grep -iE 'expo|updates|ReactNativeJS' "$WORK/device.log" | tail -n 60 || true
  else
    xcrun simctl spawn "$UDID" log show --last 15m --style compact \
      --predicate 'process CONTAINS "airlift" OR subsystem CONTAINS "expo"' >"$WORK/device.log" 2>&1 || true
    echo "---- device log (expo-updates, tail) ----"
    grep -iE 'expo|update|error|ATS|App Transport' "$WORK/device.log" | tail -n 60 || true
  fi
}
GROUP=""
publish() { # marker [branch] [flags: extra,report,crash] — sets GROUP to the new update group
  local marker="$1" branch="${2:-$CHANNEL}" flags=",${3:-},"
  local sed_args=(-e "s/MARKER = '.*'/MARKER = '$marker'/")
  case "$flags" in *,extra,*) sed_args+=(-e "s|EXTRA = null|EXTRA = require('./assets/extra.png')|") ;; esac
  case "$flags" in *,report,*) sed_args+=(-e "s|REPORT = null|REPORT = '$SERVER/u/$APP_ID'|") ;; esac
  case "$flags" in *,crash,*) sed_args+=(-e "s|CRASH = false|CRASH = true|") ;; esac
  sed "${sed_args[@]}" "$WORK/marker.js.orig" >"$APP/marker.js"
  log "publish $marker → branch $branch${3:+ ($3)}"
  cli publish --branch "$branch" --platform "$PLATFORM" --message "$marker" | tee "$WORK/publish.out"
  GROUP="$(sed -n 's/^Published update group //p' "$WORK/publish.out")"
  [ -n "$GROUP" ] || die "publish $marker: no group id in CLI output"
}
APP_PATH="/api/v1/orgs/$ORG/apps/$APP_SLUG"
APP_ID="$(jq -r .appId "$APP/airlift.json")"
# What the production channel serves right now, as the manifest part JSON.
manifest() {
  curl -fsS "$SERVER/u/$APP_ID/manifest" -H 'expo-protocol-version: 1' \
    -H "expo-platform: $PLATFORM" -H "expo-runtime-version: $RUNTIME" \
    -H "expo-channel-name: $CHANNEL" -H 'accept: multipart/mixed' \
    | tr -d '\r' | grep -m1 '"launchAsset"'
}
metric() { # name [label-substring] → sum over matching label sets (0 if absent)
  curl -fsS -b "$JAR" "$SERVER/metrics" | awk -v m="$1" -v l="${2:-}" \
    '($1 == m || index($1, m "{") == 1) && index($1, l) { s += $2 } END { print s + 0 }'
}
# Generate the from→(current release) bsdiff patch ahead of time (the server
# builds patches lazily on first request), so the device's fetch gets 226.
prewarm_patch() { # from-update-id
  local m to url code=""
  m="$(manifest)"
  to="$(jq -r .id <<<"$m")"
  url="$(jq -r .launchAsset.url <<<"$m")"
  for _ in $(seq 1 90); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$url" -H 'a-im: bsdiff' \
      -H "expo-current-update-id: $1" -H "expo-requested-update-id: $to")"
    if [ "$code" = 226 ]; then return 0; fi
    sleep 1
  done
  die "bsdiff patch $1 → $to never became ready (last HTTP $code; see airlift.log)"
}
# The probe error the app reported (App.js reportProbe) must arrive for the
# right update, with a frame symbolicated back to the line that threw.
check_symbolicated() { # marker update-id
  local want gid="" event
  want="$(grep -n 'e2e:probe-line' "$APP/App.js" | cut -d: -f1)"
  log "error report for $1: expect a frame at App.js:$want"
  for _ in $(seq 1 60); do
    gid="$(api GET "$APP_PATH/errors?window=1h" \
      | jq -r --arg m "airlift-e2e-probe $1" '[.groups[] | select(.message | startswith($m))][0].id // empty')"
    [ -n "$gid" ] && break
    sleep 1
  done
  [ -n "$gid" ] || die "the app's error report never reached the server"
  event="$(api GET "$APP_PATH/errors/$gid" | jq -c '.events[0]')"
  echo "$event" | jq '{update_id, platform, frames: [.frames[]? | {function, file, line, column, source, source_line, symbolicated}][:4]}'
  [ "$(jq -r .update_id <<<"$event")" = "$2" ] || die "error report not attributed to update $2"
  jq -e --argjson l "$want" \
    'any(.frames[]?; .symbolicated and ((.source // "") | endswith("App.js")) and .source_line == $l)' \
    <<<"$event" >/dev/null || die "no frame symbolicated to App.js:$want (raw stack: $(jq -r .raw_stack <<<"$event"))"
}
# Tap "check" on an update that throws while its JS loads. The device
# downloads it, crashes, and expo-updates relaunches the previous update.
# A dropped tap looks the same on screen (idle, old marker), so ask the
# server whether the device actually fetched the manifest, and re-tap if not.
crash_update() { # marker
  local before
  for attempt in 1 2 3; do
    before="$(metric airlift_manifest_requests_total 'result="manifest"')"
    flow crash.yaml
    if [ "${E2E_DRY_RUN:-}" = 1 ] \
      || [ "$(metric airlift_manifest_requests_total 'result="manifest"')" -gt "$before" ]; then
      return 0
    fi
    log "crash update $1: the device never asked for it (attempt $attempt); tapping again"
  done
  die "crash update $1: the device never fetched it"
}

# ── basics: embedded → OTA → persisted → rollback → rollback-to-embedded ──
flow launch.yaml MARKER=embedded ORIGIN=embedded

publish v2
# The rotated-key setup must check out (cert ↔ keyid ↔ server key).
log "airlift doctor"
cli doctor
flow update.yaml MARKER=v2 ORIGIN=update
flow up-to-date.yaml MARKER=v2
flow launch.yaml MARKER=v2 ORIGIN=update

publish v3
flow update.yaml MARKER=v3 ORIGIN=update

log "rollback channel $CHANNEL (v3 → v2)"
cli rollback --channel "$CHANNEL" --runtime-version "$RUNTIME"
flow update.yaml MARKER=v2 ORIGIN=update

log "rollback-to-embedded on branch $CHANNEL"
curl -fsS -X POST "$SERVER$APP_PATH/branches/$CHANNEL/rollback-to-embedded" \
  -H "authorization: Bearer $AIRLIFT_TOKEN" -H 'content-type: application/json' \
  -d '{"runtime_version":"'"$RUNTIME"'"}' >/dev/null
flow update.yaml MARKER=embedded ORIGIN=embedded
flow launch.yaml MARKER=embedded ORIGIN=embedded

publish v4
flow update.yaml MARKER=v4 ORIGIN=update

# ── an asset the build never had: downloaded, loadable, survives a restart ──
publish v5 "$CHANNEL" extra
flow update.yaml MARKER=v5 ORIGIN=update EXTRA=loaded
flow launch.yaml MARKER=v5 ORIGIN=update EXTRA=loaded

# ── bsdiff: the real client applies our BSDIFF40 patch (no full fallback) ──
FROM_ID="$(manifest | jq -r .id)" # the update the device runs (v5)
publish v6
log "prewarm bsdiff patch $FROM_ID → v6"
prewarm_patch "$FROM_ID"
PATCHES_BEFORE="$(metric airlift_patch_served_total)"
REDIRECTS_BEFORE="$(metric airlift_asset_redirects_total)"
flow update.yaml MARKER=v6 ORIGIN=update
if [ "${E2E_DRY_RUN:-}" != 1 ]; then
  PATCHES_AFTER="$(metric airlift_patch_served_total)"
  REDIRECTS_AFTER="$(metric airlift_asset_redirects_total)"
  log "patches served $PATCHES_BEFORE → $PATCHES_AFTER, asset redirects $REDIRECTS_BEFORE → $REDIRECTS_AFTER"
  [ "$PATCHES_AFTER" -gt "$PATCHES_BEFORE" ] || die "device did not request the bsdiff patch"
  # A rejected patch makes the client re-download the full bundle (a 307).
  [ "$REDIRECTS_AFTER" -eq "$REDIRECTS_BEFORE" ] || die "device fell back to the full bundle after the patch"
fi

# ── gated channel: a publish waits for promote ──
log "gate channel $CHANNEL (auto_release=false)"
api PATCH "$APP_PATH/channels/$CHANNEL" '{"auto_release":false}' >/dev/null
publish v7
flow up-to-date.yaml MARKER=v6
cli promote --channel "$CHANNEL" --group "$GROUP"
flow update.yaml MARKER=v7 ORIGIN=update

# ── staged rollout: held back at 0.001%, delivered at 100% ──
publish v8
log "start rollout of v8 at 0.001%"
api POST "$APP_PATH/channels/$CHANNEL/rollout" '{"group_id":"'"$GROUP"'","percent":0.001}' >/dev/null
flow up-to-date.yaml MARKER=v7
log "grow rollout to 100%"
api PATCH "$APP_PATH/channels/$CHANNEL/rollout" '{"runtime_version":"'"$RUNTIME"'","percent":100}' >/dev/null
flow update.yaml MARKER=v8 ORIGIN=update
api PATCH "$APP_PATH/channels/$CHANNEL" '{"auto_release":true}' >/dev/null

# ── repoint the channel to another branch, then back (older head re-served
#    under a fresh identity, or the client would ignore it) ──
publish v9 hotfix
log "repoint channel $CHANNEL → branch hotfix"
api PATCH "$APP_PATH/channels/$CHANNEL" '{"branch":"hotfix"}' >/dev/null
flow update.yaml MARKER=v9 ORIGIN=update
log "repoint channel $CHANNEL → branch $CHANNEL"
api PATCH "$APP_PATH/channels/$CHANNEL" '{"branch":"'"$CHANNEL"'"}' >/dev/null
flow update.yaml MARKER=v8 ORIGIN=update
flow launch.yaml MARKER=v8 ORIGIN=update

# ── error reporting: airlift-reporter sends a handled error with its Hermes
#    stack; the server symbolicates it to the exact App.js line ──
publish v10 "$CHANNEL" report
V10_ID="$(manifest | jq -r .id)"
flow update.yaml MARKER=v10 ORIGIN=update
if [ "${E2E_DRY_RUN:-}" != 1 ]; then
  check_symbolicated v10 "$V10_ID"
fi

# ── crash protection: an update that dies on launch is rolled back by the
#    client and never offered to that device again ──
publish v11 "$CHANNEL" crash
crash_update v11
flow up-to-date.yaml MARKER=v10 REASON=noUpdateAvailableOnServer
if [ "${E2E_DRY_RUN:-}" != 1 ]; then
  [ "$(metric airlift_manifest_requests_total 'result="blocked"')" -gt 0 ] \
    || die "server never refused the crashed update (no blocked manifest requests)"
fi
flow launch.yaml MARKER=v10 ORIGIN=update

log "server-side counters"
curl -fsS -b "$JAR" "$SERVER/metrics" | grep -E '^airlift_(manifest|asset|patch)' || true

log "PASS ($PLATFORM)"
