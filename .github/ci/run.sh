#!/bin/bash
# run.sh bench|hunt|trial NAME [WORDS...]: starts a CI run by pushing the
# annotated tag KIND-NAME on HEAD. WORDS are the tag's first line: the bench
# flags ("-only probe -profile polite"), or "areas=web,net model=…" for a
# hunt. A hunt or a trial also carries this machine's Codex session,
# encrypted to the CI's key (its private half is the secret CODEX_AUTH_KEY).
# fetch.sh brings back what the run wrote.
set -euo pipefail
kind=${1:?usage: run.sh bench|hunt|trial NAME [WORDS...]}
name=${2:?usage: run.sh bench|hunt|trial NAME [WORDS...]}
shift 2
ci_recipient=age1s5k75wkcjwpps44lup59t048lxtsmc48l2lkg42mly922kj6g3ks3flrqj
age=$(command -v age || echo "$HOME/go/bin/age")
msg=$(mktemp)
trap 'rm -f "$msg"' EXIT
case $kind in
bench) printf '%s\n' "${*:--profile both}" > "$msg" ;;
hunt | trial)
  printf '%s\n\n' "${*:-$kind}" > "$msg"
  "$age" -a -r "$ci_recipient" "${CODEX_HOME:-$HOME/.codex}/auth.json" >> "$msg"
  ;;
*)
  echo "run.sh: KIND is bench, hunt or trial" >&2
  exit 2
  ;;
esac
git tag -a "$kind-$name" -F "$msg"
git push --no-verify -q origin "$kind-$name"
echo "$kind-$name: https://github.com/trannghiach/azhaq/actions"
