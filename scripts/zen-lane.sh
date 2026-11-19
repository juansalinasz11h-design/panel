#!/bin/bash
# zen lane — launches OpenCode through the local egress proxy.
#
# OpenCode's free-tier limit is applied to the public IP address the server
# sees. On Linux, WARP runs in isolated proxy mode and listens on
# 127.0.0.1:40000. OpenCode's Bun runtime does not understand socks5://
# proxy environment values, so this launcher starts the stdlib HTTP CONNECT
# proxy (zen_proxy.py) on a private localhost port and points the normal
# HTTP(S)_PROXY variables at it.
#
# The proxy handles WARP, Tor, and custom-proxy modes, edge failover, keepalive,
# and fallback reporting. A temporary machine-id is mounted inside a private
# namespace when the kernel allows it; the namespace disappears on exit.
set -u

BRAND="opencode-unlimited"
DEST="${OUC_DEST:-${XDG_DATA_HOME:-$HOME/.local/share}/$BRAND}"
PYPROXY="$DEST/python/zen_proxy.py"

REAL="${OUC_REAL_BIN:-$HOME/.opencode/bin/opencode}"
if [ ! -x "$REAL" ]; then
  for c in "$HOME/.local/bin/opencode" /usr/local/bin/opencode /usr/bin/opencode; do
    [ -x "$c" ] || continue
    # Never treat one of our own shims as the real binary.
    grep -qs "zen-lane" "$c" && continue
    REAL="$c"
    break
  done
fi
[ -x "$REAL" ] || { echo "opencode binary not found — set OUC_REAL_BIN or reinstall" >&2; exit 1; }
[ -f "$PYPROXY" ] || {
  echo "zen-lane: local proxy missing at $PYPROXY — rerun install.sh" >&2
  exit 1
}

TD=$(mktemp -d /tmp/ouc-lane.XXXXXX 2>/dev/null || {
  mkdir -p /tmp/opencode-unlimited
  mktemp -d /tmp/opencode-unlimited/lane.XXXXXX
}) || { echo "zen-lane: could not create a temporary directory" >&2; exit 1; }

PROXY_PID=""
cleanup(){
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  rm -rf "$TD"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- start the local HTTP CONNECT proxy on an ephemeral port
PORT_FILE="$TD/proxy.port"
PROXY_LOG="$TD/proxy.log"
PYTHONPATH="$DEST/python${PYTHONPATH:+:$PYTHONPATH}" \
  python3 "$PYPROXY" 0 --port-file "$PORT_FILE" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

PROXY_PORT=""
for _ in $(seq 1 60); do
  if [ -s "$PORT_FILE" ]; then
    PROXY_PORT=$(cat "$PORT_FILE" 2>/dev/null)
    break
  fi
  kill -0 "$PROXY_PID" 2>/dev/null || break
  sleep 0.2
done

if [ -z "$PROXY_PORT" ]; then
  echo "zen-lane: local egress proxy did not start — refusing to leak the home IP." >&2
  [ -s "$PROXY_LOG" ] && tail -n 6 "$PROXY_LOG" >&2
  echo "Run opencode-unlimited-doctor, then retry." >&2
  exit 1
fi

PROXY_URL="http://127.0.0.1:$PROXY_PORT"
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"
export ALL_PROXY="$PROXY_URL"
export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"
export all_proxy="$PROXY_URL"
export NO_PROXY="127.0.0.1,localhost,::1"
export no_proxy="$NO_PROXY"

# ---- private machine-id (some endpoints sniff it; fresh per launch costs nothing)
if [ -e /etc/machine-id ]; then
  tr -dc 'a-f0-9' < /dev/urandom | head -c 32 > "$TD/machine-id"
fi

CAN_UNSHARE=0
unshare -rm true 2>/dev/null && CAN_UNSHARE=1

run_opencode(){
  if [ "$CAN_UNSHARE" = "1" ]; then
    unshare -rm bash -c '
      if [ -s "$1/machine-id" ] && [ -e /etc/machine-id ]; then
        mount --bind "$1/machine-id" /etc/machine-id 2>/dev/null || true
      fi
      shift
      exec "$@"
    ' _ "$TD" "$REAL" "$@"
  else
    # Container / VPS kernels can block user namespaces. The proxy environment
    # still carries every HTTP(S) request, so isolated egress remains intact.
    "$REAL" "$@"
  fi
}

run_opencode "$@"
RC=$?
exit "$RC"
