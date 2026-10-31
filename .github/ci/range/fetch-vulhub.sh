#!/bin/bash
# fetch-vulhub.sh DIR: checks out the Vulhub commit the catalog is pinned to.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: fetch-vulhub.sh DIR}
commit=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["vulhub"]["commit"])' "$here/catalog.json")
git init -q "$dir"
git -C "$dir" remote add origin https://github.com/vulhub/vulhub.git
git -C "$dir" fetch -q --depth 1 origin "$commit"
git -C "$dir" checkout -q FETCH_HEAD
test "$(git -C "$dir" rev-parse HEAD)" = "$commit"
