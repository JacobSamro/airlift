#!/bin/sh
# airlift one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/jacobsamro/airlift/master/install.sh | sh
#
# Downloads the matching binary (verified against SHA256SUMS), installs a
# systemd service, and writes a starter config. Re-running upgrades in place.
#
# Environment:
#   AIRLIFT_VERSION   pin a release (default: latest)
#   AIRLIFT_REPO      github owner/repo (default: jacobsamro/airlift)
#   AIRLIFT_PREFIX    install prefix for the binary (default: /usr/local/bin)
#   AIRLIFT_FORCE     set to 1 to reinstall even if already on the target version
set -eu

REPO="${AIRLIFT_REPO:-jacobsamro/airlift}"
VERSION="${AIRLIFT_VERSION:-latest}"
PREFIX="${AIRLIFT_PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/airlift"
DATA_DIR="/var/lib/airlift"
SERVICE="/etc/systemd/system/airlift.service"

log()  { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "please run as root (e.g. pipe into 'sudo sh')"

# ── detect platform ──────────────────────────────────────────────
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = "linux" ] || err "airlift's installer targets Linux (got: $os)"
case "$(uname -m)" in
  x86_64|amd64)   arch="x86_64" ;;
  aarch64|arm64)  arch="aarch64" ;;
  *) err "unsupported architecture: $(uname -m)" ;;
esac
asset="airlift-${arch}-unknown-linux-gnu"

for tool in curl tar sha256sum install; do
  command -v "$tool" >/dev/null 2>&1 || err "missing required tool: $tool"
done

# ── resolve version ──────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
  log "resolving latest release of $REPO"
  # Buffer the response before grepping: piping curl straight into `grep -m1`
  # lets grep close the pipe on the first match, and curl then reports
  # "(23) Failure writing output to destination" on the broken pipe.
  release_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"
  VERSION="$(printf '%s\n' "$release_json" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
  [ -n "$VERSION" ] || err "could not determine latest version"
fi

# Release tags carry a leading "v" (v0.8.1); the binary reports a bare semver
# (0.8.1). Compare and display the bare form so re-running an up-to-date install
# isn't mistaken for an upgrade. The download URL below still uses $VERSION (tag).
VERSION_NUM="${VERSION#v}"

# Detect an existing install so we can report (and behave like) an upgrade.
OLD_VERSION=""
if [ -x "$PREFIX/airlift" ]; then
  OLD_VERSION="$("$PREFIX/airlift" --version 2>/dev/null | awk '{print $2}')"
fi
# Already on the target version? Nothing to do — skip the download/reinstall.
# Set AIRLIFT_FORCE=1 to reinstall the same version anyway (e.g. repair).
if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" = "$VERSION_NUM" ] && [ "${AIRLIFT_FORCE:-0}" != "1" ]; then
  log "airlift $VERSION_NUM is already installed — nothing to do (AIRLIFT_FORCE=1 to reinstall)"
  exit 0
fi
if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" != "$VERSION_NUM" ]; then
  log "upgrading airlift $OLD_VERSION -> $VERSION_NUM ($arch)"
elif [ -n "$OLD_VERSION" ]; then
  log "reinstalling airlift $VERSION_NUM ($arch)"
else
  log "installing airlift $VERSION_NUM ($arch)"
fi

base="https://github.com/${REPO}/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ── download + verify ────────────────────────────────────────────
log "downloading $asset.tar.gz"
curl -fsSL "$base/${asset}.tar.gz" -o "$tmp/airlift.tar.gz"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"

log "verifying checksum"
want="$(grep " ${asset}.tar.gz\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
[ -n "$want" ] || err "checksum for ${asset}.tar.gz not found in SHA256SUMS"
got="$(sha256sum "$tmp/airlift.tar.gz" | awk '{print $1}')"
[ "$want" = "$got" ] || err "checksum mismatch (expected $want, got $got)"

tar -xzf "$tmp/airlift.tar.gz" -C "$tmp"

# ── install binary ───────────────────────────────────────────────
log "installing binary to $PREFIX/airlift"
install -m 0755 "$tmp/airlift" "$PREFIX/airlift"

# ── user, dirs, config ───────────────────────────────────────────
if ! id airlift >/dev/null 2>&1; then
  log "creating system user 'airlift'"
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin airlift 2>/dev/null \
    || adduser --system --home "$DATA_DIR" --no-create-home airlift 2>/dev/null || true
fi
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown -R airlift:airlift "$DATA_DIR" 2>/dev/null || chown -R airlift "$DATA_DIR" 2>/dev/null || true

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  log "writing starter config to $CONFIG_DIR/config.toml"
  cat > "$CONFIG_DIR/config.toml" <<'TOML'
[server]
http_addr = "0.0.0.0:80"
https_addr = "0.0.0.0:443"
# public_url = "https://registry.example.com"

[database]
path = "/var/lib/airlift/airlift.db"

[storage]
endpoint = "https://t3.storage.dev"
bucket = ""                # <-- your Tigris bucket
region = "auto"
# Prefer setting these via environment in the systemd unit / drop-in:
#   AIRLIFT_STORAGE__ACCESS_KEY_ID, AIRLIFT_STORAGE__SECRET_ACCESS_KEY
access_key_id = ""
secret_access_key = ""

[tls]
# Automatic Let's Encrypt is on. The server stays on plain HTTP until you add a
# domain in the dashboard, then provisions a cert on :443 automatically.
enabled = true
contact_email = ""         # recommended: your email, for Let's Encrypt notices
TOML
  chmod 640 "$CONFIG_DIR/config.toml"
  chown root:airlift "$CONFIG_DIR/config.toml" 2>/dev/null || true
fi

# ── database migrations ──────────────────────────────────────────
# `serve` also migrates on start, but run it now (as the airlift user, so the
# DB file keeps the right owner) so an upgrade's schema changes land before the
# service comes back up. Idempotent and safe to repeat.
if id airlift >/dev/null 2>&1 && command -v su >/dev/null 2>&1; then
  log "applying database migrations"
  # Pass paths as positional args ($1, $2) rather than interpolating them into
  # the shell command, so a crafted AIRLIFT_PREFIX can't inject shell syntax.
  su -s /bin/sh airlift -c 'exec "$1" --config "$2" migrate' airlift-migrate \
    "$PREFIX/airlift" "$CONFIG_DIR/config.toml" \
    >/dev/null 2>&1 || log "migrations will run on next service start"
fi

# ── systemd service ──────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1; then
  log "installing systemd service"
  curl -fsSL "$base/airlift.service" -o "$SERVICE" 2>/dev/null || cat > "$SERVICE" <<'UNIT'
[Unit]
Description=airlift container registry
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=airlift
Group=airlift
ExecStart=/usr/local/bin/airlift --config /etc/airlift/config.toml serve
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/airlift
StateDirectory=airlift
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable airlift >/dev/null 2>&1 || true
  log "starting airlift"
  systemctl restart airlift || log "could not start yet — finish editing $CONFIG_DIR/config.toml, then: systemctl restart airlift"
fi

if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" != "$VERSION_NUM" ]; then
  cat <<EOF

airlift upgraded: $OLD_VERSION -> $VERSION_NUM

  Binary : $PREFIX/airlift   (replaced)
  Config : $CONFIG_DIR/config.toml   (kept)
  Data   : $DATA_DIR   (kept; migrations applied)

The service was restarted on the new version. Logs: journalctl -u airlift -f
EOF
elif [ -n "$OLD_VERSION" ]; then
  cat <<EOF

airlift is already at $VERSION_NUM — reinstalled and restarted.

Logs: journalctl -u airlift -f
EOF
else
  cat <<EOF

airlift $VERSION_NUM installed.

  Binary : $PREFIX/airlift
  Config : $CONFIG_DIR/config.toml   (set your Tigris bucket + keys)
  Data   : $DATA_DIR

Next steps:
  1. Edit $CONFIG_DIR/config.toml (Tigris bucket + credentials).
  2. systemctl restart airlift
  3. Open http://<server> and complete the setup wizard.
  4. Add your domain in Settings → Domains & TLS to enable HTTPS.

Logs: journalctl -u airlift -f
EOF
fi
