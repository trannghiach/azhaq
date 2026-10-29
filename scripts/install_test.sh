#!/bin/sh
# Installs v0.8.1 into a temp dir with cosign set, then checks the error path.
# Needs network access to github.com and api.github.com.
# Run: sh scripts/install_test.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL=$HERE/install.sh
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
fails=0

pass() {
    echo "ok   $*"
}

fail() {
    echo "FAIL $*"
    fails=$((fails + 1))
}

if COSIGN=/home/nghiattran/azhaq-trial6/bin/cosign sh "$INSTALL" -v v0.8.1 -d "$T/bin" >"$T/install.log" 2>&1; then
    pass "install v0.8.1 exits 0"
else
    fail "install v0.8.1 exits 0"
    cat "$T/install.log"
fi

if grep -q 'NOT verified' "$T/install.log"; then
    fail "signature path ran (cosign was not used)"
else
    pass "signature path ran (cosign was used)"
fi

if [ -x "$T/bin/azhaq" ] && "$T/bin/azhaq" version 2>&1 | grep -q 'azhaq 0\.8\.1'; then
    pass "installed binary reports azhaq 0.8.1"
else
    fail "installed binary reports azhaq 0.8.1"
fi

if sh "$INSTALL" -v v0.0.0-nope -d "$T/bin3" >"$T/bad.log" 2>&1; then
    fail "bogus version exits non-zero"
else
    pass "bogus version exits non-zero"
fi

if grep -q '^install\.sh: ' "$T/bad.log"; then
    pass "bogus version prints an install.sh: message"
else
    fail "bogus version prints an install.sh: message"
    cat "$T/bad.log"
fi

if [ -e "$T/bin3/azhaq" ]; then
    fail "bogus version installs nothing"
else
    pass "bogus version installs nothing"
fi

if [ "$fails" -eq 0 ]; then
    echo "all checks passed"
    exit 0
fi
echo "$fails check(s) failed"
exit 1
