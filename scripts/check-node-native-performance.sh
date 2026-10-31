#!/bin/sh
# Disposable Linux staging fixture: real Xray server/client, DNS/TLS/SOCKS,
# original Check/queue/controllers. No Internet, router or existing /opt writes.
set -eu
: "${RAZVILKA_XRAY_NATIVE:?absolute path to SHA-verified official Xray26.3.27 (production XHTTP contract)}"
: "${RAZVILKA_NODE_PERF_OUTPUT:?absolute artifact output directory}"
GO=${GO:-go}
case "$RAZVILKA_XRAY_NATIVE:$RAZVILKA_NODE_PERF_OUTPUT" in /*:/*) ;; *) echo 'paths must be absolute' >&2; exit 2;; esac
[ "$(basename "$RAZVILKA_XRAY_NATIVE")" = xray ] && [ -x "$RAZVILKA_XRAY_NATIVE" ] || exit 2
mkdir -p "$RAZVILKA_NODE_PERF_OUTPUT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
{
 "$GO" version
 uname -a
 "$RAZVILKA_XRAY_NATIVE" version
 sha256sum "$RAZVILKA_XRAY_NATIVE"
 git rev-parse HEAD
 printf '%s\n' 'staging loopback-only namespace; stable WAN identity modeled; service delay40ms; N12 repeated plus first per scenario' 'reference=current native production path with only per-Check literal observation hidden, not historical release binary' 'App=current original queue only; controlled queue25ms before dispatch; HTTP delivery observed, browser paint unmeasured' 'stage durations overlap; CPU/RSS/router/physical WAN/Internet unavailable'
} > "$RAZVILKA_NODE_PERF_OUTPUT/environment.txt"
"$GO" test -c -o "$tmp/dataplane.test" ./internal/dataplane
"$GO" test -c -o "$tmp/app.test" ./internal/app
export RAZVILKA_XRAY_NETNS=1 RAZVILKA_NODE_NATIVE_PERF=1
if unshare --net --mount sh -eu -c '
 mount --make-rprivate /
 ip link set lo up
 ip addr add 93.184.216.11/32 dev lo
 ip addr add 93.184.216.12/32 dev lo
 ip addr add 93.184.216.13/32 dev lo
 "$1/dataplane.test" -test.run "^TestNativeVLESSCheckPerformance$" -test.v -test.timeout=25m
 # Hide the hosts /opt only inside this private mount namespace. Actual history
 # admission requires SAME installed inode, not a patched admission callback.
 mkdir -p /opt
 mount -t tmpfs -o mode=0755 tmpfs /opt
 mkdir -p /opt/bin
 cp "$1/app.test" /opt/bin/razvilka
 chmod 0755 /opt/bin/razvilka
 exec /opt/bin/razvilka -test.run "^TestNativeVLESSQueueHTTPPerformance$" -test.v -test.timeout=25m
' sh "$tmp" > "$RAZVILKA_NODE_PERF_OUTPUT/native-performance.log" 2>&1; then
 cat "$RAZVILKA_NODE_PERF_OUTPUT/native-performance.log"
else
 code=$?
 cat "$RAZVILKA_NODE_PERF_OUTPUT/native-performance.log"
 exit "$code"
fi
