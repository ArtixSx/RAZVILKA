#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_HEV_OFFICIAL_NATIVE:?exact official predecessor ELF required}"
: "${RAZVILKA_HEV_NATIVE:?exact separately pinned source-lab ELF required}"
case "$RAZVILKA_HEV_OFFICIAL_NATIVE:$RAZVILKA_HEV_NATIVE" in /*:/*) ;; *) exit 2;; esac
for tool in go unshare mount umount ip timeout readlink wc grep sha256sum git cut; do command -v "$tool" >/dev/null; done
case "${RAZVILKA_NATIVE_RACE:-0}" in 0) race_flag= ;; 1) race_flag=-race ;; *) exit 2;; esac
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d /tmp/razvilka-hev-replacement.XXXXXX)
cleanup() { case "$work" in /tmp/razvilka-hev-replacement.*) rm -rf -- "$work";; *) return 1;; esac; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
# race_flag has only the two literal values above; no caller-supplied Go flags.
if go test $race_flag -count=1 -v -tags razvilka_native_fixture,razvilka_hev_altstack_lab ./internal/components -run '^TestHEV(Replacement|SameVersion|ReleaseChanged|AltstackLabExactPin)' > "$work/components.log" 2>&1; then
 cat "$work/components.log"
else
 status=$?
 cat "$work/components.log"
 exit "$status"
fi
for name in TestHEVReplacementCursorAndCompensation TestHEVReplacementAdmissionAndCancellation TestHEVReplacementReviewOriginalVectorAndIdentity TestHEVReplacementCrashRecoveryAndPendingRefusal TestHEVSameVersionUpdateRequiresDifferentIntegrityOwnedBytes TestHEVReleaseChangedOwnedBinaryRequiresInactivity TestHEVAltstackLabExactPin; do
 grep -F -- "--- PASS: $name (" "$work/components.log" >/dev/null || exit 1
done
if grep -F -- '--- SKIP:' "$work/components.log" >/dev/null; then exit 1; fi
go test $race_flag -tags razvilka_native_fixture,razvilka_hev_altstack_lab -ldflags='-s -w' -c -o "$work/app.test" ./internal/app
# Preserve the same original controller-reader size bound used by sameboot.
size=$(wc -c < "$work/app.test")
test "$size" -gt 0 && test "$size" -le 67108864 || exit 1
revision=$(git -c safe.directory="$repo" rev-parse HEAD)
printf 'HEV_REPLACEMENT_SOURCE_REVISION=%s\n' "$revision"
printf 'HEV_REPLACEMENT_CONTROLLER_SIZE=%s\n' "$size"
printf 'HEV_REPLACEMENT_CONTROLLER_SHA256='
sha256sum "$work/app.test" | cut -d ' ' -f 1
chmod 500 "$work/app.test"
exec 8</proc/self/ns/net 9</proc/self/ns/mnt
timeout --signal=TERM --kill-after=10s 210s unshare --mount --propagation private --net --pid --fork --kill-child sh -eu -c '
 test "$$" = 1
 test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/self/fd/8)"
 test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/fd/9)"
 mount --make-rprivate /
 # Match the existing private-PID native fixture: detach inherited proc and
 # all nested proc mounts, then create one fresh mount for this PID namespace.
 umount -l /proc
 mount -t proc proc /proc
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 cp "$1/app.test" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 ip link set lo up
 export RAZVILKA_HEV_REPLACEMENT_NATIVE=1
 exec /opt/bin/razvilka -test.run="^TestHEVOriginalNativeHTTPSameVersionReplacement$" -test.v -test.count=1 -test.timeout=200s
' sh "$work"
