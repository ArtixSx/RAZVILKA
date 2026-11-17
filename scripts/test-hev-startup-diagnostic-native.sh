#!/bin/sh
set -eu
# Separate diagnostic only: never trace an acceptance process or modify its PID.
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_HEV_NATIVE:?pinned official HEV2.17.1 binary required}"
case "$RAZVILKA_HEV_NATIVE" in /*) ;; *) exit 2;; esac
for tool in go unshare mount ip strace timeout; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d /tmp/razvilka-hev-startup.XXXXXX)
cleanup() { case "$work" in /tmp/razvilka-hev-startup.*) rm -rf -- "$work";; *) return 1;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
go test -tags razvilka_native_fixture -c -o "$work/diagnostic.test" ./internal/dataplane
export RAZVILKA_HEV_STARTUP_DIAGNOSTIC=1 RAZVILKA_HEV_STARTUP_NAMESPACE=1
exec 8</proc/self/ns/net 9</proc/self/ns/mnt
# Private PID namespace: even a failed diagnostic/timeout cannot leave children
# running in the host. Private /dev is never the actual machine's device tree.
timeout --signal=TERM --kill-after=10s 230s unshare --mount --propagation private --net --pid --fork --kill-child --mount-proc sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nosuid tmpfs /dev
 mkdir -m 755 /dev/net
 mknod -m 600 /dev/net/tun c 10 200
 mknod -m 666 /dev/null c 1 3
 ip link set lo up
 exec "$1/diagnostic.test" -test.run="^TestHEVStartupDiagnostic(ClosedTrace|Population)$" -test.v -test.count=1 -test.timeout=210s
' sh "$work"
