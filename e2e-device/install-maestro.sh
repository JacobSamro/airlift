#!/usr/bin/env bash
# Install a pinned Maestro CLI, verified against its release checksum
# (instead of piping get.maestro.mobile.dev, which installs whatever is
# latest). Bump both values together, from the release's
# checksums_sha256.txt: https://github.com/mobile-dev-inc/maestro/releases
#
#   e2e-device/install-maestro.sh   # → $HOME/.maestro/bin/maestro
set -euo pipefail

MAESTRO_VERSION="${MAESTRO_VERSION:-2.12.1}"
MAESTRO_SHA256="${MAESTRO_SHA256:-54dbb0716425626604973cbb374c585ca30272375d9ce15177a1152765ddd9d7}"
DEST="${MAESTRO_DIR:-$HOME/.maestro}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/maestro.zip" \
  "https://github.com/mobile-dev-inc/maestro/releases/download/cli-$MAESTRO_VERSION/maestro.zip"

if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$tmp/maestro.zip" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/maestro.zip" | cut -d' ' -f1)"
fi
if [ "$actual" != "$MAESTRO_SHA256" ]; then
  echo "maestro.zip $MAESTRO_VERSION: sha256 $actual, expected $MAESTRO_SHA256" >&2
  exit 1
fi

unzip -q "$tmp/maestro.zip" -d "$tmp"
rm -rf "$DEST/bin" "$DEST/lib"
mkdir -p "$DEST"
cp -R "$tmp/maestro/." "$DEST/"
"$DEST/bin/maestro" --version
