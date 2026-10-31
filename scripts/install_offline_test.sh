#!/bin/sh
# Runs install.sh against a fake release on disk, with a stand-in curl and
# cosign: no network. Checks the signature options and the tool checks.
# Run: sh scripts/install_offline_test.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL=$HERE/install.sh
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
fails=0

pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

case $(uname -s) in Linux) OS=linux ;; Darwin) OS=darwin ;; *) echo "skip: unsupported OS"; exit 0 ;; esac
case $(uname -m) in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "skip: unsupported architecture"; exit 0 ;; esac

# The fake release v9.9.9: an archive holding an azhaq that prints its
# version, its checksum, and a signature bundle.
REL=$T/release
mkdir -p "$REL" "$T/src"
printf '#!/bin/sh\necho "azhaq 9.9.9"\n' > "$T/src/azhaq"
chmod 755 "$T/src/azhaq"
ARCHIVE=azhaq_9.9.9_${OS}_${ARCH}.tar.gz
(cd "$T/src" && tar -czf "$REL/$ARCHIVE" azhaq)
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$REL" && sha256sum "$ARCHIVE" > checksums.txt)
else
    (cd "$REL" && shasum -a 256 "$ARCHIVE" > checksums.txt)
fi
echo '{}' > "$REL/checksums.txt.sigstore.json"

# Tools: the commands install.sh needs, linked into one directory so that a
# PATH of this directory alone has no cosign, plus a curl that reads the
# release from disk (and records what it was asked) and a cosign that says
# yes or no.
BIN=$T/bin
mkdir -p "$BIN"
for c in sh uname mktemp awk sed head tar gzip cp chmod mkdir rm cat dirname sha256sum shasum basename tr; do
    p=$(command -v "$c" 2>/dev/null) && case $p in /*) ln -s "$p" "$BIN/$c" ;; esac
done
cat > "$BIN/curl" <<CURL
#!/bin/sh
out=; url=
while [ \$# -gt 0 ]; do
    case \$1 in -o) out=\$2; shift ;; -*) ;; *) url=\$1 ;; esac
    shift
done
echo "\$url" >> "$T/curl.log"
f="$REL/\$(basename "\$url")"
[ -f "\$f" ] || exit 22
cp "\$f" "\$out"
CURL
chmod 755 "$BIN/curl"
COS=$T/cosign
cat > "$COS" <<'COSIGN'
#!/bin/sh
echo "cosign $*" >> "$COSIGN_LOG"
[ "${COSIGN_SAYS:-yes}" = yes ]
COSIGN
chmod 755 "$COS"

# run NAME [env…] -- args…: install.sh with only $BIN on PATH.
out=$T/out.log
run() {
    rm -rf "$T/dest" "$T/curl.log"
    : > "$T/cosign.log"
    env -i PATH="$BIN" HOME="$T" COSIGN_LOG="$T/cosign.log" "$@" sh "$INSTALL" -v v9.9.9 -d "$T/dest" >"$out" 2>&1
}
installed() { [ -x "$T/dest/azhaq" ]; }
downloads() { [ -s "$T/curl.log" ]; }

# No cosign: the checksum alone, said plainly.
if run X=1 && installed && grep -q 'NOT verified' "$out"; then
    pass "no cosign: installs on the checksum and says the signature was not verified"
else
    fail "no cosign: installs on the checksum"; cat "$out"
fi

# Required, no cosign: stops before downloading anything.
for how in "--require-signature" "-s"; do
    rm -rf "$T/dest" "$T/curl.log"
    if env -i PATH="$BIN" HOME="$T" sh "$INSTALL" -v v9.9.9 -d "$T/dest" "$how" >"$out" 2>&1; then
        fail "$how without cosign exits non-zero"
    elif installed || downloads; then
        fail "$how without cosign downloads or installs nothing"
    elif grep -q 'cosign was not found' "$out"; then
        pass "$how without cosign: stops before any download, naming cosign"
    else
        fail "$how without cosign names cosign"; cat "$out"
    fi
done
if run AZHAQ_REQUIRE_SIGNATURE=1; then
    fail "AZHAQ_REQUIRE_SIGNATURE=1 without cosign exits non-zero"
elif installed || downloads; then
    fail "AZHAQ_REQUIRE_SIGNATURE=1 without cosign downloads or installs nothing"
else
    pass "AZHAQ_REQUIRE_SIGNATURE=1 without cosign: stops, nothing downloaded or installed"
fi
if run AZHAQ_REQUIRE_SIGNATURE=0 && installed; then
    pass "AZHAQ_REQUIRE_SIGNATURE=0 does not require it"
else
    fail "AZHAQ_REQUIRE_SIGNATURE=0 does not require it"; cat "$out"
fi

# Required, cosign verifies: installs.
if run AZHAQ_REQUIRE_SIGNATURE=1 COSIGN="$COS" && installed && grep -q 'signature of checksums.txt verified' "$out" && grep -q verify-blob "$T/cosign.log"; then
    pass "required, cosign verifies: installs"
else
    fail "required, cosign verifies: installs"; cat "$out"
fi

# cosign says no: nothing installed, required or not.
for req in 1 0; do
    if run AZHAQ_REQUIRE_SIGNATURE=$req COSIGN="$COS" COSIGN_SAYS=no; then
        fail "a failed signature (required=$req) exits non-zero"
    elif installed; then
        fail "a failed signature (required=$req) installs nothing"
    else
        pass "a failed signature (required=$req) installs nothing"
    fi
done

# A tampered archive: nothing installed.
echo tampered >> "$REL/$ARCHIVE"
if run X=1; then
    fail "a checksum mismatch exits non-zero"
elif installed; then
    fail "a checksum mismatch installs nothing"
else
    pass "a checksum mismatch installs nothing"
fi

# A missing tool is named before anything is downloaded.
rm -f "$BIN/gzip"
if run X=1; then
    fail "no gzip exits non-zero"
elif downloads || ! grep -q 'missing commands: gzip' "$out"; then
    fail "no gzip is named before a download"; cat "$out"
else
    pass "no gzip: named before any download"
fi

if [ "$fails" -eq 0 ]; then
    echo "all checks passed"
    exit 0
fi
echo "$fails check(s) failed"
exit 1
