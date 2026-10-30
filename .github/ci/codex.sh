#!/bin/bash
# Installs the Codex CLI the author runs locally and signs it in. The
# session comes in the tag's message, encrypted to the key in the secret
# CODEX_AUTH_KEY (.github/ci/run.sh puts it there); OPENAI_API_KEY or
# CODEX_AUTH_JSON (base64 of an auth.json) also work.
set -euo pipefail
npm install -g -s @openai/codex@0.164.0
mkdir -p "$HOME/.codex"
if [ -n "${CODEX_AUTH_KEY:-}" ]; then
  tag=${GITHUB_REF_NAME:?}
  git fetch -q --force origin "refs/tags/$tag:refs/tags/$tag"
  git for-each-ref --format='%(contents)' "refs/tags/$tag" |
    sed -n '/-----BEGIN AGE ENCRYPTED FILE-----/,/-----END AGE ENCRYPTED FILE-----/p' > "$RUNNER_TEMP/auth.age"
  if [ -s "$RUNNER_TEMP/auth.age" ]; then
    (umask 077 && age -d -i <(printenv CODEX_AUTH_KEY) -o "$HOME/.codex/auth.json" "$RUNNER_TEMP/auth.age")
  fi
fi
if [ ! -s "$HOME/.codex/auth.json" ]; then
  if [ -n "${OPENAI_API_KEY:-}" ]; then
    printenv OPENAI_API_KEY | codex login --with-api-key
  elif [ -n "${CODEX_AUTH_JSON:-}" ]; then
    (umask 077 && printenv CODEX_AUTH_JSON | base64 -d > "$HOME/.codex/auth.json")
  else
    echo "::error::no Codex session: push the tag with .github/ci/run.sh (secret CODEX_AUTH_KEY), or add OPENAI_API_KEY"
    exit 1
  fi
fi
sha256sum "$HOME/.codex/auth.json" | cut -d' ' -f1 > "$RUNNER_TEMP/auth.sum"
codex --version
