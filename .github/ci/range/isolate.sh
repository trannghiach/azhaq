#!/bin/bash
# isolate.sh [USER]: the last privileged step before the agent works on an
# estate. Afterwards the user it runs as (default: this one) cannot see the
# estate's processes, cannot use the container runtime and has no sudo. Each
# step is verified; the script exits 1 when any check fails, so the job stops
# before the agent starts.
#
#   1. /proc is remounted with hidepid=2: `ps` and /proc/PID show only the
#      user's own processes, not the containers', the proxy or the resolvers.
#   2. The docker socket becomes root:root 0600 and the user leaves the
#      docker group: no `docker`, no way to read a container.
#   3. The user's sudo rights go (sudoers files naming the user, the sudo
#      and admin groups).
#
# Not hidden: the kernel's table of listening sockets (ss, /proc/net/tcp)
# and the network interfaces; grade.py lists any command in the agent's log
# that reads them.
#
# ISOLATE_DRY_RUN=1 prints the privileged commands and checks nothing.
set -uo pipefail
user=${1:-$(id -un)}
uid=$(id -u "$user" 2>/dev/null || id -u)
dry=${ISOLATE_DRY_RUN:-}
fail=0

priv() {
  if [ -n "$dry" ]; then echo "+ sudo $*"; else sudo -n "$@"; fi
}
check() { # check LABEL COMMAND...: the command must succeed
  local label=$1
  shift
  [ -n "$dry" ] && { echo "check: $label"; return; }
  if "$@" >/dev/null 2>&1; then echo "ok: $label"; else echo "FAILED: $label"; fail=1; fi
}
check_not() { # check_not LABEL COMMAND...: the command must fail
  local label=$1
  shift
  [ -n "$dry" ] && { echo "check: $label"; return; }
  if "$@" >/dev/null 2>&1; then echo "FAILED: $label"; fail=1; else echo "ok: $label"; fi
}

# A process of another user, to see whether hidepid hides it.
canary=0
if [ -z "$dry" ]; then
  sudo -n -u nobody setsid sleep 3000 >/dev/null 2>&1 &
  sleep 1
  canary=$(pgrep -n -u nobody -x sleep || echo 0)
else
  echo "+ sudo -u nobody setsid sleep 3000  # canary"
fi

# 1. hidepid
priv mount -o remount,hidepid=2 /proc
others_visible() { # a process of another user in /proc
  find /proc -maxdepth 1 -name '[0-9]*' -printf '%U\n' 2>/dev/null | sort -u | grep -qv "^${uid}$"
}
check_not "processes of other users are hidden in /proc" others_visible
if [ "$canary" != 0 ]; then
  check_not "a canary process of another user is not visible" test -d "/proc/$canary"
  sudo -n kill "$canary" 2>/dev/null || true
fi

# 2. the container runtime
priv chown root:root /var/run/docker.sock
priv chmod 600 /var/run/docker.sock
priv gpasswd -d "$user" docker
check_not "docker is unusable" docker ps
check_not "the docker socket cannot be opened" python3 -c 'import socket; socket.socket(socket.AF_UNIX).connect("/var/run/docker.sock")'
check_not "the docker daemon is not on TCP 2375/2376" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2375'

# 3. sudo, last: the steps above need it
if [ -n "$dry" ]; then
  echo "+ sudo rm -f <each file in /etc/sudoers.d that names $user, %sudo or %admin>"
else
  # The user cannot list /etc/sudoers.d (0750 root): list it as root.
  sudo -n find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null | while read -r f; do
    if sudo -n grep -qE "^[[:space:]]*(${user}|%sudo|%admin)\b" "$f" 2>/dev/null; then
      sudo -n rm -f "$f"
    fi
  done
fi
priv gpasswd -d "$user" sudo
priv gpasswd -d "$user" admin
priv sed -i -E "/^[[:space:]]*(${user}|%sudo|%admin)[[:space:]]/d" /etc/sudoers
# Last, and last in sudoers' order: whatever grant is left, this denies it.
if [ -n "$dry" ]; then
  echo "+ sudo tee /etc/sudoers.d/zzz-no-$user  # $user ALL=(ALL) !ALL"
else
  # One call: once the file is there, sudo is gone.
  printf '%s ALL=(ALL:ALL) !ALL\n' "$user" | sudo -n install -m 0440 /dev/stdin "/etc/sudoers.d/zzz-no-$user" || true
fi
if [ -z "$dry" ]; then sudo -k; fi
check_not "sudo is gone" sudo -n true
check_not "su to root is not possible without a password" su -c true root < /dev/null

if [ -n "$dry" ]; then exit 0; fi
if [ "$fail" -ne 0 ]; then
  echo "isolate.sh: a check failed; the agent must not start" >&2
  exit 1
fi
echo "isolate.sh: all checks passed"
