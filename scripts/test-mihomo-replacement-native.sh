#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned target1.19.33 archive required}"
: "${RAZVILKA_MIHOMO_PREDECESSOR_ARCHIVE:?official pinned predecessor1.19.32 archive required}"
case "$RAZVILKA_MIHOMO_ARCHIVE:$RAZVILKA_MIHOMO_PREDECESSOR_ARCHIVE" in /*:/*) ;; *) exit 2;; esac
mihomo_replacement_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mihomo_replacement_work=$(mktemp -d /tmp/razvilka-mihomo-replacement.XXXXXX)
chmod 700 "$mihomo_replacement_work"
trap 'rm -rf -- "$mihomo_replacement_work"' EXIT HUP INT TERM
export TMPDIR="$mihomo_replacement_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$mihomo_replacement_repo"
go test -tags razvilka_native_fixture -c -o "$mihomo_replacement_work/app.test" ./internal/app
chmod 500 "$mihomo_replacement_work/app.test"
unshare --mount --net --pid --fork sh -eu -c '
 mount --make-rprivate /
 umount -l /proc
 mount -t proc proc /proc
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 cp "$1/app.test" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 ip link set lo up
 export RAZVILKA_MIHOMO_REPLACEMENT_NATIVE=1
 exec /opt/bin/razvilka -test.run="^TestMihomoOriginalNativeHTTPVersionReplacement$" -test.v -test.count=1 -test.timeout=150s
' sh "$mihomo_replacement_work"
