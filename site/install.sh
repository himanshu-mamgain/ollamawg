#!/bin/sh
# Installs the ollamawg binary from GitHub Releases on Linux, macOS or FreeBSD.
#
#   curl -fsSL https://himanshu-mamgain.github.io/ollamawg/install.sh | sh
#
# Environment:
#   OLLAMAWG_VERSION      release to install, e.g. 0.4.0 (default: latest)
#   OLLAMAWG_INSTALL_DIR  where to put the binary (default: /usr/local/bin if
#                         writable, else ~/.local/bin). Never uses sudo.
set -eu

REPO="himanshu-mamgain/ollamawg"

say() { printf '%s\n' "$*"; }
die() { printf 'ollamawg install: %s\n' "$*" >&2; exit 1; }

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin|freebsd) ;;
  mingw*|msys*|cygwin*) die "on Windows, run in PowerShell: irm https://himanshu-mamgain.github.io/ollamawg/install.ps1 | iex" ;;
  *) die "unsupported OS: $os (build from source: go install github.com/$REPO/cmd/ollamawg@latest)" ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported CPU: $arch (build from source: go install github.com/$REPO/cmd/ollamawg@latest)" ;;
esac
[ "$os" = freebsd ] && [ "$arch" = arm64 ] && die "no prebuilt binary for freebsd/arm64; build from source with go install"

asset="ollamawg-$os-$arch"
if [ -n "${OLLAMAWG_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/v${OLLAMAWG_VERSION#v}"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "needs curl or wget"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t ollamawg)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset ..."
fetch "$base/$asset" "$tmp/ollamawg" || die "download failed: $base/$asset"

# Verify against the release's SHA256SUMS (published from 0.4.1 on; older releases skip this).
if fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null; then
  want=$(awk -v f="$asset" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")
  [ -n "$want" ] || die "SHA256SUMS has no entry for $asset"
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/ollamawg" | awk '{ print $1 }')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/ollamawg" | awk '{ print $1 }')
  else
    got=$(sha256 -q "$tmp/ollamawg")
  fi
  [ "$got" = "$want" ] || die "checksum mismatch for $asset (expected $want, got $got)"
  say "Checksum OK."
else
  say "This release has no SHA256SUMS; skipping checksum verification."
fi
chmod +x "$tmp/ollamawg"

dir="${OLLAMAWG_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir" || die "cannot create $dir"
mv "$tmp/ollamawg" "$dir/ollamawg" || die "cannot write $dir/ollamawg (set OLLAMAWG_INSTALL_DIR to a writable directory)"

say "Installed $("$dir/ollamawg" version 2>/dev/null || echo ollamawg) to $dir/ollamawg"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Note: $dir is not on your PATH. Add it, e.g.: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
esac
say "Next: ollamawg init --endpoint <your-public-ip-or-dns>:51820   (see https://himanshu-mamgain.github.io/ollamawg/)"
