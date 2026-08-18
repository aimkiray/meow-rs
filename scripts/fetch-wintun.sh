#!/usr/bin/env bash
# Download the official signed Wintun 0.14.1 zip, verify its SHA-256, and
# extract the matching wintun.dll (+ LICENSE) for a Windows target.
#
# Usage:
#   scripts/fetch-wintun.sh --target x86_64-pc-windows-msvc --outdir dist/wintun
#   scripts/fetch-wintun.sh --arch amd64 --outdir dist/wintun
#
# Official source: https://www.wintun.net/
# The prebuilt signed DLLs are the only supported redistribution form.

set -euo pipefail

WINTUN_VERSION="0.14.1"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

ARCH=""
TARGET=""
OUTDIR=""

usage() {
    cat <<'EOF'
Usage: scripts/fetch-wintun.sh --outdir DIR (--target RUST_TRIPLE | --arch ARCH)

Download the official Wintun zip, verify SHA-256, and write:
  DIR/wintun.dll
  DIR/LICENSE.txt

Architectures: amd64, arm64, x86, arm
Rust triples:  x86_64-*-windows-* → amd64
               aarch64-*-windows-* → arm64
               i686-*-windows-*    → x86
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="${2:-}"
            shift 2
            ;;
        --target)
            TARGET="${2:-}"
            shift 2
            ;;
        --outdir)
            OUTDIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$OUTDIR" ]]; then
    echo "--outdir is required" >&2
    usage >&2
    exit 2
fi

if [[ -n "$TARGET" && -z "$ARCH" ]]; then
    case "$TARGET" in
        x86_64-*) ARCH=amd64 ;;
        aarch64-*) ARCH=arm64 ;;
        i686-*|i586-*) ARCH=x86 ;;
        thumbv7a-*|armv7-*|arm-*) ARCH=arm ;;
        *)
            echo "cannot map Rust target '$TARGET' to a Wintun arch" >&2
            exit 2
            ;;
    esac
fi

if [[ -z "$ARCH" ]]; then
    echo "either --arch or --target is required" >&2
    usage >&2
    exit 2
fi

case "$ARCH" in
    amd64|arm64|x86|arm) ;;
    *)
        echo "unsupported Wintun arch '$ARCH' (want amd64|arm64|x86|arm)" >&2
        exit 2
        ;;
esac

win_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s' "$1"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        # windows-latest Git Bash may lack both; PowerShell is always there.
        local wp
        wp="$(win_path "$1")"
        powershell.exe -NoProfile -Command \
            "(Get-FileHash -Algorithm SHA256 -LiteralPath '${wp}').Hash.ToLower()"
    fi
}

extract_zip() {
    local zip="$1" dest="$2"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "$zip" -d "$dest"
    else
        local wz wd
        wz="$(win_path "$zip")"
        wd="$(win_path "$dest")"
        powershell.exe -NoProfile -Command \
            "Expand-Archive -LiteralPath '${wz}' -DestinationPath '${wd}' -Force"
    fi
}

workdir="$(mktemp -d)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

zip_path="$workdir/wintun-${WINTUN_VERSION}.zip"
echo "fetching $WINTUN_URL"
curl -fsSL --retry 3 --retry-delay 2 -o "$zip_path" "$WINTUN_URL"

got="$(sha256_of "$zip_path" | tr -d '\r')"
if [[ "$got" != "$WINTUN_SHA256" ]]; then
    echo "SHA-256 mismatch for wintun-${WINTUN_VERSION}.zip" >&2
    echo "  expected $WINTUN_SHA256" >&2
    echo "  got      $got" >&2
    exit 1
fi

extract_zip "$zip_path" "$workdir"
src="$workdir/wintun/bin/${ARCH}/wintun.dll"
license="$workdir/wintun/LICENSE.txt"
if [[ ! -f "$src" ]]; then
    echo "zip did not contain wintun/bin/${ARCH}/wintun.dll" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
cp "$src" "$OUTDIR/wintun.dll"
if [[ -f "$license" ]]; then
    cp "$license" "$OUTDIR/LICENSE.txt"
fi
echo "wrote $OUTDIR/wintun.dll ($ARCH)"
