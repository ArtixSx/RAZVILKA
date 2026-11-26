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
case "${RAZVILKA_INACTIVE_PROC_TEST_MODE-normal}" in
  normal) set -- ;;
  race) set -- -race ;;
  *) echo 'unknown inactive process test mode' >&2; exit 2 ;;
esac
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread "$repo/scripts/fixtures/inactive-proc-threadgroup.c" -o "$work/threadgroup-helper"
cc -std=c11 -O2 -Wall -Wextra -Werror "$repo/scripts/fixtures/inactive-proc-statx-fallback.c" -o "$work/statx-fallback"
cd "$repo"
go test "$@" -tags razvilka_native_fixture -c ./internal/dataplane -o "$work/dataplane.test"
sha256sum "$work/threadgroup-helper" "$work/statx-fallback" "$work/dataplane.test"
export RAZVILKA_INACTIVE_THREADGROUP_HELPER="$work/threadgroup-helper"
exec 8</proc/self/ns/net
exec 9</proc/self/ns/mnt
status=0
for variant in native forced-fallback; do
  case_status=0
  timeout --kill-after=5s 60s unshare --fork --pid --net --mount sh -eu -c '
    test "$$" = 1
    test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/self/fd/8)"
    test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/fd/9)"
    mount --make-rprivate /
    umount -l /proc
    mount -t proc proc /proc
    if test "$1" = forced-fallback; then
      exec "$2" "$3" -test.v -test.timeout=45s -test.run "^TestInactiveProcNativeThreadGroupClassification$"
    fi
    exec "$3" -test.v -test.timeout=45s -test.run "^TestInactiveProcNativeThreadGroupClassification$"
  ' inactive-proc "$variant" "$work/statx-fallback" "$work/dataplane.test" >"$work/$variant.log" 2>&1 || case_status=$?
  printf 'inactive_proc_variant=%s\n' "$variant"
  cat "$work/$variant.log"
  if grep -F -- '--- SKIP:' "$work/$variant.log"; then case_status=1; fi
  for marker in '--- PASS: TestInactiveProcNativeThreadGroupClassification ' INACTIVE_PROC_LIVE_WORKER_REFUSED INACTIVE_PROC_WORKER_EXEC INACTIVE_PROC_Z1_THEN_GONE INACTIVE_PROC_MOUNT_FENCES; do
    if ! grep -F -- "$marker" "$work/$variant.log" >/dev/null; then case_status=1; fi
  done
  if test "$variant" = forced-fallback && ! grep -Fx 'INACTIVE_PROC_FORCED_STATX_ENOSYS observed=true process_tree_only=true' "$work/$variant.log" >/dev/null; then case_status=1; fi
  if test "$case_status" != 0; then status=$case_status; fi
done
exit "$status"
