#!/bin/bash
# publish.sh DEST FILE...: commits the files under DEST on the ci-results
# branch, which raw.githubusercontent.com serves without a login.
set -euo pipefail
dest=$1
shift
repo="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
files=()
for f in "$@"; do
  files+=("$(realpath "$f")")
done
# One try: a fresh shallow clone of the branch's tip, the files, a push.
# Matrix jobs publish at once, so a push can lose the race; the next try
# starts from the new tip instead of rebasing a shallow history.
try() {
  local w
  w=$(mktemp -d)
  if ! git clone -q --depth 1 --branch ci-results "$repo" "$w" 2>/dev/null; then
    git init -q "$w"
    git -C "$w" checkout -q --orphan ci-results
    git -C "$w" remote add origin "$repo"
  fi
  mkdir -p "$w/$dest"
  cp -r "${files[@]}" "$w/$dest/"
  git -C "$w" add -A
  git -C "$w" -c user.name=lilsadfoqs -c user.email=lilsadfoqs@gmail.com commit -qm "$dest"
  git -C "$w" push -q origin HEAD:ci-results
}
for i in 1 2 3 4 5 6 7 8; do
  try && exit 0
  sleep $((i * 2 + RANDOM % 5))
done
echo "publish.sh: could not push $dest to ci-results" >&2
exit 1
