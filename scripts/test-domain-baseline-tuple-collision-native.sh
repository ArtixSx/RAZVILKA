#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
for tool in go ip iptables-legacy unshare mount umount readlink timeout sha256sum; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d /tmp/razvilka-tuple-collision.XXXXXX)
case "$work" in /tmp/razvilka-tuple-collision.??????) ;; *) exit 2 ;; esac
chmod 700 "$work"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
go test -tags razvilka_native_fixture -c ./internal/dataplane -o "$work/dataplane.test"
sha256sum "$work/dataplane.test"
exec 8</proc/self/ns/net
exec 9</proc/self/ns/mnt
status=0
timeout --kill-after=5s 50s unshare --fork --pid --net --mount sh -eu -c '
  test "$$" = 1
  test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/self/fd/8)"
  test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/fd/9)"
  mount --make-rprivate /
  umount -l /proc
  mount -t proc proc /proc
  mount -t tmpfs -o mode=755 tmpfs /run
  mkdir /run/netns
  export RAZVILKA_DOMAIN_TUPLE_COLLISION=1
  exec "$1" -test.v -test.timeout=45s -test.run "^TestDomainBaselineTupleCollisionNative$"
' tuple-collision "$work/dataplane.test" >"$work/native.log" 2>&1 || status=$?
cat "$work/native.log"
if grep -F -- '--- SKIP:' "$work/native.log"; then status=1; fi
for marker in '--- PASS: TestDomainBaselineTupleCollisionNative ' DOMAIN_TUPLE_NO_EFFECT_CONTROL DOMAIN_ROUTER_SOURCE_MECHANISM DOMAIN_TUPLE_SECOND_PORT_CONTROL DOMAIN_TUPLE_COLLISION_CONFIRMED DOMAIN_TUPLE_CLEANUP; do
  if ! grep -F -- "$marker" "$work/native.log" >/dev/null; then status=1; fi
done
exit "$status"
