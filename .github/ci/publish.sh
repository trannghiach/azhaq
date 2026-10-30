#!/bin/bash
# publish.sh DEST FILE...: commits the files under DEST on the ci-results
# branch, which raw.githubusercontent.com serves without a login.
set -euo pipefail
dest=$1
shift
repo="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
w=$(mktemp -d)
if ! git clone -q --depth 1 --branch ci-results "$repo" "$w" 2>/dev/null; then
  git init -q "$w"
  git -C "$w" checkout -q --orphan ci-results
  git -C "$w" remote add origin "$repo"
fi
mkdir -p "$w/$dest"
cp -r "$@" "$w/$dest/"
cd "$w"
git add -A
git -c user.name=lilsadfoqs -c user.email=lilsadfoqs@gmail.com commit -qm "$dest"
# Matrix jobs publish at once: rebase onto what the others pushed.
for i in 1 2 3 4 5 6; do
  git push -q origin HEAD:ci-results && exit 0
  git pull -q --rebase origin ci-results || true
  sleep $((i * 3))
done
exit 1
