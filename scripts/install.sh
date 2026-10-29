#!/bin/sh
# Installs azhaq from a GitHub release. The archive must match checksums.txt
# and, when cosign is available, checksums.txt must carry a valid signature
# from this repository's release workflow. Nothing is written to DIR before
# both checks pass.
#
# Usage: sh install.sh [-v VERSION] [-d DIR]
set -eu

REPO=trannghiach/azhaq
RELEASES=https://github.com/$REPO/releases
VERSION=
INSTALL_DIR=
TMP=

err() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

info() {
    printf 'install.sh: %s\n' "$*"
}

usage() {
    cat <<EOF
usage: sh install.sh [-v VERSION] [-d DIR]
  -v VERSION  release tag such as v0.8.1 (default: latest)
  -d DIR      install directory (default: \$HOME/.local/bin)
EOF
}

# fetch URL FILE: curl if present, else wget.
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1" || err "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" || err "download failed: $1"
    else
        err "need curl or wget to download files"
    fi
}

while getopts ':v:d:h' opt; do
    case $opt in
        v) VERSION=$OPTARG ;;
        d) INSTALL_DIR=$OPTARG ;;
        h) usage; exit 0 ;;
        \?) err "unknown option -$OPTARG (see: sh install.sh -h)" ;;
        :) err "option -$OPTARG needs a value" ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 0 ] || err "unexpected argument: $1"

case $(uname -s) in
    Linux) OS=linux ;;
    Darwin) OS=darwin ;;
    *) err "unsupported OS $(uname -s); download manually from $RELEASES" ;;
esac

case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported architecture $(uname -m); download manually from $RELEASES" ;;
esac

INSTALL_DIR=${INSTALL_DIR:-$HOME/.local/bin}
case $INSTALL_DIR in
    /*) ;;
    *) INSTALL_DIR=$PWD/$INSTALL_DIR ;;
esac
INSTALL_DIR=${INSTALL_DIR%/}

TMP=$(mktemp -d) || err "cannot create a temp dir"
trap 'if [ -n "$TMP" ]; then rm -rf "$TMP"; fi' EXIT
trap 'exit 1' HUP INT TERM

if [ -z "$VERSION" ]; then
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
    VERSION=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n 1)
    [ -n "$VERSION" ] || err "could not read the latest release tag from the GitHub API"
    info "latest release is $VERSION"
fi

case $VERSION in
    [0-9]*) VERSION=v$VERSION ;;
esac
case $VERSION in
    v[0-9]*) ;;
    *) err "bad version: $VERSION" ;;
esac
case $VERSION in
    *[!A-Za-z0-9._+-]*) err "bad version: $VERSION" ;;
esac

NUM=${VERSION#v}
ARCHIVE=azhaq_${NUM}_${OS}_${ARCH}.tar.gz
BASE=$RELEASES/download/$VERSION

fetch "$BASE/$ARCHIVE" "$TMP/$ARCHIVE"
fetch "$BASE/checksums.txt" "$TMP/checksums.txt"

awk -v f="$ARCHIVE" '$2 == f' "$TMP/checksums.txt" > "$TMP/check.txt"
[ -s "$TMP/check.txt" ] || err "checksums.txt has no entry for $ARCHIVE"

if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256 -c"
else
    err "need sha256sum or shasum to verify the download"
fi
(cd "$TMP" && $SHA_CMD check.txt >/dev/null 2>&1) || err "checksum mismatch for $ARCHIVE; nothing installed"
info "sha256 of $ARCHIVE matches checksums.txt"

COSIGN_BIN=$(command -v "${COSIGN:-cosign}" 2>/dev/null || true)
if [ -n "${COSIGN:-}" ] && [ -z "$COSIGN_BIN" ]; then
    err "COSIGN=$COSIGN is not an executable"
fi

if [ -n "$COSIGN_BIN" ]; then
    fetch "$BASE/checksums.txt.sigstore.json" "$TMP/checksums.txt.sigstore.json"
    "$COSIGN_BIN" verify-blob \
        --bundle "$TMP/checksums.txt.sigstore.json" \
        --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP/checksums.txt" || err "signature check failed for checksums.txt; nothing installed"
    info "signature of checksums.txt verified with cosign"
else
    info "checksum verified, but the signature was NOT verified (cosign not found); to verify, run this in a directory holding the release's checksums.txt and checksums.txt.sigstore.json:"
    printf '%s\n' "cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp '^https://github\.com/trannghiach/azhaq/\.github/workflows/release\.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt"
fi

mkdir "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x" || err "cannot extract $ARCHIVE"
[ -f "$TMP/x/azhaq" ] || err "$ARCHIVE does not contain azhaq"

mkdir -p "$INSTALL_DIR" || err "cannot create $INSTALL_DIR"
cp "$TMP/x/azhaq" "$INSTALL_DIR/azhaq" || err "cannot write $INSTALL_DIR/azhaq"
chmod 755 "$INSTALL_DIR/azhaq"

info "installed $INSTALL_DIR/azhaq"
"$INSTALL_DIR/azhaq" version || err "installed binary did not run"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) info "$INSTALL_DIR is not on PATH; add it with: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
