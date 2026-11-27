#!/bin/sh
set -eu

releases=https://github.com/hardw00t/glitchdeck/releases
base=${GLITCHDECK_BASE_URL:-$releases/download}
version=${GLITCHDECK_VERSION:-latest}
destdir=${GLITCHDECK_INSTALL_DIR:-$HOME/.local/bin}
case $(uname -s) in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) echo "Unsupported OS. Download the Windows zip or another release from $releases" >&2; exit 1 ;;
esac
case $(uname -m) in
    x86_64|amd64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) echo "Unsupported architecture; see $releases" >&2; exit 1 ;;
esac
if command -v curl >/dev/null 2>&1; then
    download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    download() { wget -qO "$2" "$1"; }
else
    echo 'curl or wget is required' >&2; exit 1
fi
if [ "$version" = latest ]; then
    if [ "${GLITCHDECK_BASE_URL+x}" = x ]; then
        echo 'Set GLITCHDECK_VERSION when overriding GLITCHDECK_BASE_URL' >&2; exit 1
    fi
    if command -v curl >/dev/null 2>&1; then
        url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$releases/latest")
    else
        url=$(wget --spider -S "$releases/latest" 2>&1 | sed -n 's/^[[:space:]]*Location: *\([^[:space:]]*\).*/\1/p' | tail -n 1)
    fi
    version=${url##*/}
fi
version=${version#v}
case $version in *[!0-9A-Za-z.-]*) echo "Invalid semantic version: $version" >&2; exit 1 ;; esac
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
if ! printf '%s\n' "$version" | grep -Eq "$semver"; then
    echo "Invalid semantic version: $version" >&2; exit 1
fi
tag=v$version
archive=glitchdeck_${version}_${os}_${arch}.tar.gz
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
download "${base%/}/$tag/$archive" "$tmp/$archive"
download "${base%/}/$tag/SHA256SUMS" "$tmp/SHA256SUMS"
expected=$(awk -v file="$archive" 'length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ && ($2 == file || $2 == "*" file) { hash = $1; count++ } END { if (count == 1) print tolower(hash) }' "$tmp/SHA256SUMS")
if [ -z "$expected" ]; then
    echo "Missing or ambiguous checksum for $archive" >&2; exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$archive")
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$archive")
else
    echo 'sha256sum or shasum is required' >&2; exit 1
fi
actual=${actual%% *}
if [ "$actual" != "$expected" ]; then
    echo "Checksum mismatch for $archive" >&2; exit 1
fi
tar -xzf "$tmp/$archive" -C "$tmp" glitchdeck
mkdir -p "$destdir"
install -m 0755 "$tmp/glitchdeck" "$destdir/glitchdeck"
"$destdir/glitchdeck" --version
case :$PATH: in
    *:"$destdir":*) ;;
    *) echo "Add $destdir to your PATH to run glitchdeck." ;;
esac
