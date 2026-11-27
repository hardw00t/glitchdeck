#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <version without v> <output directory>" >&2
    exit 1
fi
version=$1
case $version in *[!0-9A-Za-z.-]*) echo "Invalid semantic version: $version" >&2; exit 1 ;; esac
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
if ! printf '%s\n' "$version" | grep -Eq "$semver"; then
    echo "Invalid semantic version: $version" >&2
    exit 1
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$2"
out=$(CDPATH='' cd -- "$2" && pwd)
commit=$(git -C "$root" rev-parse --short HEAD)
date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
cd "$root"
cp LICENSE README.md SKILL.md "$tmp/"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
    os=${target%/*}
    arch=${target#*/}
    binary=glitchdeck
    [ "$os" != windows ] || binary=glitchdeck.exe
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=v$version -X main.commit=$commit -X main.buildDate=$date" -o "$tmp/$binary" ./cmd/glitchdeck
    name=glitchdeck_${version}_${os}_${arch}
    if [ "$os" = windows ]; then
        rm -f "$out/$name.zip"
        (cd "$tmp" && python3 -m zipfile -c "$out/$name.zip" "$binary" LICENSE README.md SKILL.md)
    else
        tar -C "$tmp" -czf "$out/$name.tar.gz" "$binary" LICENSE README.md SKILL.md
    fi
    rm "$tmp/$binary"
done
(
    cd "$out"
    for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64 windows_arm64; do
        case $target in windows_*) extension=zip ;; *) extension=tar.gz ;; esac
        file=glitchdeck_${version}_${target}.${extension}
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$file"
        else
            shasum -a 256 "$file"
        fi
    done > SHA256SUMS
)
