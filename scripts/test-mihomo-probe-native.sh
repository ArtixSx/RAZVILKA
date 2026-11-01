#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_XRAY_NATIVE:?official pinned peer required}"
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned Mihomo archive required}"
case "$RAZVILKA_XRAY_NATIVE:$RAZVILKA_MIHOMO_ARCHIVE" in /*:/*) ;; *) exit 2;; esac
mihomo_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mihomo_work=$(mktemp -d /tmp/razvilka-mihomo-service.XXXXXX)
chmod 700 "$mihomo_work"
trap 'rm -rf -- "$mihomo_work"' EXIT HUP INT TERM
export TMPDIR="$mihomo_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_MIHOMO_SERVICE_NATIVE=1
cd "$mihomo_repo"
go test -tags razvilka_native_fixture -c -o "$mihomo_work/app.test" ./internal/app
chmod 500 "$mihomo_work/app.test"
unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 touch /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 mount --bind "$1/app.test" /opt/bin/razvilka
 exec /opt/bin/razvilka -test.run="^TestMihomoOriginalNativeServiceAndCommonCleanup$" -test.v -test.count=1 -test.timeout=180s
' sh "$mihomo_work"
