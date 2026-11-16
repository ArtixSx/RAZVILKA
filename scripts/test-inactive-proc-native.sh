#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo 'root disposable process fixture required' >&2; exit 2; }
for tool in cc go unshare mount umount readlink timeout sha256sum; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d /tmp/razvilka-inactive-proc.XXXXXX)
case "$work" in /tmp/razvilka-inactive-proc.??????) ;; *) exit 2 ;; esac
chmod 700 "$work"
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread "$repo/scripts/fixtures/inactive-proc-threadgroup.c" -o "$work/threadgroup-helper"
cd "$repo"
go test -tags razvilka_native_fixture -c ./internal/dataplane -o "$work/dataplane.test"
sha256sum "$work/threadgroup-helper" "$work/dataplane.test"
export RAZVILKA_INACTIVE_THREADGROUP_HELPER="$work/threadgroup-helper"
exec 8</proc/self/ns/net
exec 9</proc/self/ns/mnt
status=0
timeout --kill-after=5s 60s unshare --fork --pid --net --mount sh -eu -c '
  test "$$" = 1
  test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/self/fd/8)"
  test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/fd/9)"
  mount --make-rprivate /
  umount -l /proc
  mount -t proc proc /proc
  exec "$1" -test.v -test.timeout=45s -test.run "^TestInactiveProcNativeLeaderExitReproduction$"
' inactive-proc "$work/dataplane.test" >"$work/native.log" 2>&1 || status=$?
cat "$work/native.log"
if grep -F -- '--- SKIP:' "$work/native.log"; then status=1; fi
for marker in '--- PASS: TestInactiveProcNativeLeaderExitReproduction ' INACTIVE_PROC_BASELINE_FALSE_PASS INACTIVE_PROC_WORKER_EXEC INACTIVE_PROC_Z1_THEN_GONE; do
  if ! grep -F -- "$marker" "$work/native.log" >/dev/null; then status=1; fi
done
exit "$status"
