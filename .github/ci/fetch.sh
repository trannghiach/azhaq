#!/bin/bash
# fetch.sh bench|hunt|trial NAME DIR: copies what the CI run KIND-NAME put
# on the ci-results branch into DIR, decrypts and unpacks it, and puts back
# a Codex session the run refreshed, when it is newer than this machine's.
# Then usage.py counts which commands and flags the run used and writes
# DIR/usage.json (skipped without python3 or azhaq); to count every run
# fetched into one folder: usage.py FOLDER <(azhaq help -json).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kind=${1:?usage: fetch.sh bench|hunt|trial NAME DIR}
name=${2:?usage: fetch.sh bench|hunt|trial NAME DIR}
dir=${3:?usage: fetch.sh bench|hunt|trial NAME DIR}
key=${AZHAQ_AGE_KEY:-$HOME/.config/azhaq/age.key}
age=$(command -v age || echo "$HOME/go/bin/age")
repo=trannghiach/azhaq
mkdir -p "$dir"
cd "$dir"
curl -fsS "https://api.github.com/repos/$repo/contents/$kind/$kind-$name?ref=ci-results" |
  python3 -I -c 'import sys, json; [print(f["name"]) for f in json.load(sys.stdin)]' |
  while read -r f; do
    curl -fsSL -o "$f" "https://raw.githubusercontent.com/$repo/ci-results/$kind/$kind-$name/$f"
  done
for f in *.age; do
  [ -e "$f" ] || continue
  case $f in
  *codex-auth.json.age) ;;
  *) "$age" -d -i "$key" -o "${f%.age}" "$f" && tar -xzf "${f%.age}" ;;
  esac
done
# The newest session any job refreshed replaces this machine's older one.
local_auth=${CODEX_HOME:-$HOME/.codex}/auth.json
for f in *codex-auth.json.age; do
  [ -e "$f" ] || continue
  (umask 077 && "$age" -d -i "$key" -o "$f.json" "$f")
  if python3 -I -c 'import sys, json; a = json.load(open(sys.argv[1])).get("last_refresh", ""); b = json.load(open(sys.argv[2])).get("last_refresh", ""); sys.exit(0 if a > b else 1)' "$f.json" "$local_auth"; then
    cp -p "$local_auth" "$local_auth.before-ci"
    (umask 077 && cp "$f.json" "$local_auth")
    echo "fetch.sh: the run refreshed the Codex session; $local_auth now holds it (the old one is $local_auth.before-ci)"
  fi
  rm -f "$f.json"
done
ls -la
if command -v python3 >/dev/null 2>&1 && command -v azhaq >/dev/null 2>&1; then
  if azhaq help -json >.usage-help.json 2>/dev/null; then
    python3 -I "$here/usage.py" -1 . .usage-help.json || echo "fetch.sh: usage.py failed; the results are fetched" >&2
  fi
  rm -f .usage-help.json
fi
