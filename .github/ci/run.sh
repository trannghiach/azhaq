#!/bin/bash
# run.sh bench|hunt|trial|range-smoke NAME [WORDS...]: starts a CI run by
# pushing the annotated tag KIND-NAME on HEAD. WORDS are the tag's first
# line: the bench flags ("-only probe -profile polite"), "areas=web,net
# model=…" for a hunt, "only=ID,ID" for a range-smoke, and for a trial its
# kind: switch (the default), research or hunter (".github/ci/trial/README.md"),
# optionally with "seed=WORDS". A hunt or a trial also carries this machine's
# Codex session, encrypted to the CI's key (its private half is the secret
# CODEX_AUTH_KEY). fetch.sh brings back what the run wrote.
set -euo pipefail
kind=${1:?usage: run.sh bench|hunt|trial|range-smoke NAME [WORDS...]}
name=${2:?usage: run.sh bench|hunt|trial|range-smoke NAME [WORDS...]}
shift 2
ci_recipient=age1s5k75wkcjwpps44lup59t048lxtsmc48l2lkg42mly922kj6g3ks3flrqj
age=$(command -v age || echo "$HOME/go/bin/age")
msg=$(mktemp)
trap 'rm -f "$msg"' EXIT
case $kind in
bench) printf '%s\n' "${*:--profile both}" > "$msg" ;;
range-smoke) printf '%s\n' "${*:-all}" > "$msg" ;;
hunt | trial)
  if [ "$kind" = trial ]; then
    case "${1:-switch}" in
    switch | research | hunter) ;;
    *)
      echo "run.sh: a trial's kind is switch, research or hunter, not $1" >&2
      exit 2
      ;;
    esac
  fi
  printf '%s\n\n' "${*:-$kind}" > "$msg"
  "$age" -a -r "$ci_recipient" "${CODEX_HOME:-$HOME/.codex}/auth.json" >> "$msg"
  ;;
*)
  echo "run.sh: KIND is bench, hunt, trial or range-smoke" >&2
  exit 2
  ;;
esac
git tag -a "$kind-$name" -F "$msg"
git push --no-verify -q origin "$kind-$name"
echo "$kind-$name: https://github.com/trannghiach/azhaq/actions"
