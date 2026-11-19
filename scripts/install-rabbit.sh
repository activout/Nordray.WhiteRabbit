#!/bin/sh
# Installs the rabbit CLI (Nordray White Rabbit) from a GitHub release, after checking its SHA-256 checksum.
#
#   install-rabbit.sh [VERSION]     e.g. install-rabbit.sh v0.1.0 (default: the latest release)
#
# Environment:
#   RABBIT_INSTALL_DIR   where to put the binary (default: $HOME/.local/bin)
#   RABBIT_RELEASE_BASE  release download base, for mirrors and tests
#                        (default: https://github.com/activout/Nordray.WhiteRabbit/releases/download)
#
# Pin a version in CI so a job always installs exactly what was reviewed.
set -eu

repo_url="https://github.com/activout/Nordray.WhiteRabbit"
base="${RABBIT_RELEASE_BASE:-$repo_url/releases/download}"
install_dir="${RABBIT_INSTALL_DIR:-$HOME/.local/bin}"
version="${1:-}"

fail() { echo "install-rabbit: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
need curl
need tar
need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s); on Windows download the zip from $repo_url/releases" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$version" ]; then
  # The latest-release redirect names the tag without using the rate-limited API.
  location=$(curl -fsSI "$repo_url/releases/latest" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -n1)
  version="${location##*/}"
  [ -n "$version" ] && [ "$version" != "latest" ] || fail "cannot determine the latest version; pass one, e.g. v0.1.0"
fi
case "$version" in v*) ;; *) version="v$version" ;; esac
number="${version#v}"
archive="nordray-rabbit_${number}_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "install-rabbit: downloading rabbit $version for $os/$arch"
curl -fsSL "$base/$version/$archive" -o "$tmp/$archive" || fail "download failed: $base/$version/$archive"
curl -fsSL "$base/$version/SHA256SUMS" -o "$tmp/SHA256SUMS" || fail "checksums not found for $version; refusing to install"

expected=$(awk -v f="$archive" '$2==f || $2=="*"f {print $1}' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "$archive is not listed in SHA256SUMS; refusing to install"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
else
  fail "sha256sum or shasum is required to verify the download"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive (expected $expected, got $actual); refusing to install"

tar -xzf "$tmp/$archive" -C "$tmp" rabbit
mkdir -p "$install_dir"
install -m 0755 "$tmp/rabbit" "$install_dir/rabbit" 2>/dev/null || { cp "$tmp/rabbit" "$install_dir/rabbit" && chmod 0755 "$install_dir/rabbit"; }

echo "install-rabbit: installed $("$install_dir/rabbit" --version) to $install_dir/rabbit"
case ":$PATH:" in *":$install_dir:"*) ;; *) echo "install-rabbit: add $install_dir to PATH" ;; esac
