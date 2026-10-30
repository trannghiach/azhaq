#!/bin/bash
# Installs the Codex CLI the author runs locally and signs it in from a
# secret: OPENAI_API_KEY, or CODEX_AUTH_JSON (base64 of ~/.codex/auth.json).
set -euo pipefail
npm install -g -s @openai/codex@0.164.0
mkdir -p "$HOME/.codex"
if [ -n "${OPENAI_API_KEY:-}" ]; then
  printenv OPENAI_API_KEY | codex login --with-api-key
elif [ -n "${CODEX_AUTH_JSON:-}" ]; then
  (umask 077 && printenv CODEX_AUTH_JSON | base64 -d > "$HOME/.codex/auth.json")
else
  echo "::error::no Codex credentials: add the secret CODEX_AUTH_JSON or OPENAI_API_KEY"
  exit 1
fi
codex --version
