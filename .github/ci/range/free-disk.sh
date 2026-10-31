#!/bin/bash
# Frees disk on a runner by deleting toolchains the work does not use.
set -uo pipefail
sudo rm -rf /usr/share/dotnet /opt/ghc /usr/local/lib/android /usr/local/share/boost /opt/hostedtoolcache/CodeQL /usr/local/share/powershell
sudo docker image prune -af >/dev/null 2>&1 || true
df -h / | tail -1
