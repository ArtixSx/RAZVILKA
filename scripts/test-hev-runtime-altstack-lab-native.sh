#!/bin/sh
set -eu
test "$(id -u)" = 0 && test "$#" = 1 || exit 2
case "$1" in /*) ;; *) exit 2;; esac
test -f "$1" || exit 2
export RAZVILKA_HEV_ALTSTACK_LAB_MANIFEST="$1"
for tool in go unshare mount ip strace timeout; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d /tmp/razvilka-hev-altstack-lab.XXXXXX)
cleanup() { case "$work" in /tmp/razvilka-hev-altstack-lab.*) rm -rf -- "$work";; *) return 1;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
go test -tags razvilka_native_fixture -c -o "$work/lab.test" ./internal/dataplane
exec 8</proc/self/ns/net 9</proc/self/ns/mnt
timeout --signal=TERM --kill-after=10s 290s unshare --mount --propagation private --net --pid --fork --kill-child --mount-proc sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nosuid tmpfs /dev
 mkdir -m 755 /dev/net
 mknod -m 600 /dev/net/tun c 10 200
 mknod -m 666 /dev/null c 1 3
 ip link set lo up
 exec "$1/lab.test" -test.run="^TestHEV(StartupDiagnosticClosedTrace|RuntimeAltstackLabPopulation)$" -test.v -test.count=1 -test.timeout=270s
' sh "$work"
