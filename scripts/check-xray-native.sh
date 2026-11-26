#!/bin/sh
# Run only on the designated Linux test host. No uplink, routes, firewall or
# existing namespace is modified. Go modules must already be in the cache.
set -eu
: "${RAZVILKA_XRAY_NATIVE:?Set the absolute path to the verified native xray binary}"
GO=${GO:-go}
case "$RAZVILKA_XRAY_NATIVE" in /*) ;; *) echo 'Xray path must be absolute' >&2; exit 2;; esac
[ -x "$RAZVILKA_XRAY_NATIVE" ] || { echo 'Xray binary is not executable' >&2; exit 2; }
[ "$(basename "$RAZVILKA_XRAY_NATIVE")" = xray ] || { echo 'Receipt verification requires a binary named xray' >&2; exit 2; }
"$RAZVILKA_XRAY_NATIVE" version
"$GO" version
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
"$GO" test -c -o "$tmp/xray-native.test" ./internal/dataplane
# Enter a new namespace even if the caller already owns an isolated VM.
# Public-format fixture addresses pass production admission, but cannot reach
# the Internet: this namespace has only loopback, with no external interface.
export RAZVILKA_XRAY_NETNS=1
pattern='^TestNativeXray(ExactNode|StoreConfigSyntax)$'
timeout=4m
case "${RAZVILKA_XHTTP_NATIVE:-0}" in
  0) ;;
  1) pattern='^TestNativeXray(ExactNode|XHTTPExactNode|StoreConfigSyntax)$'; timeout=12m;;
  *) echo 'RAZVILKA_XHTTP_NATIVE must be 0 or 1' >&2; exit 2;;
esac
unshare --net sh -eu -c '
  ip link set lo up
  ip addr add 93.184.216.11/32 dev lo
  ip addr add 93.184.216.12/32 dev lo
  ip addr add 93.184.216.13/32 dev lo
  exec "$1" -test.run "$2" -test.v -test.timeout "$3"
' sh "$tmp/xray-native.test" "$pattern" "$timeout"
