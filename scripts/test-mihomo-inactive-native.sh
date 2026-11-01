#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned Mihomo archive required}"
case "$RAZVILKA_MIHOMO_ARCHIVE" in /*) ;; *) exit 2;; esac
mihomo_inactive_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mihomo_inactive_work=$(mktemp -d /tmp/razvilka-mihomo-inactive.XXXXXX)
chmod 700 "$mihomo_inactive_work"
trap 'rm -rf -- "$mihomo_inactive_work"' EXIT HUP INT TERM
export TMPDIR="$mihomo_inactive_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$mihomo_inactive_repo"
go test -tags razvilka_native_fixture -c -o "$mihomo_inactive_work/dataplane.test" ./internal/dataplane
chmod 500 "$mihomo_inactive_work/dataplane.test"
# A real PID namespace prevents the external Go/CI supervisor from being
# misclassified as a competing controller. No process is exempted in code.
unshare --mount --net --pid --fork sh -eu -c '
 mount --make-rprivate /
 # Detach the inherited proc tree in this private namespace. The identity
 # observer deliberately rejects hidden, stacked /proc mountpoints.
 umount -l /proc
 mount -t proc proc /proc
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 ip link set lo up
 export RAZVILKA_MIHOMO_INACTIVE_NATIVE=1
 "$1/dataplane.test" -test.run="^TestMihomoProbeInactiveActualProcesses$" -test.v -test.count=1 -test.timeout=90s
' sh "$mihomo_inactive_work"
