#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
wg_native_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
wg_native_work=$(mktemp -d /tmp/razvilka-wg-native.XXXXXX)
chmod 700 "$wg_native_work"
trap 'rm -rf -- "$wg_native_work"' EXIT HUP INT TERM
cd "$wg_native_repo"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
go test -c -o "$wg_native_work/dataplane.test" ./internal/dataplane
chmod 500 "$wg_native_work/dataplane.test"
test -d /etc/wireguard || { echo 'wireguard-tools must prepare its standard directory'; exit 2; }
wg_native_status=0
for wg_native_case in TestWGNativeEmptyTables TestWGNativeCandidateIsolation TestWGNativeEndpointLifecycle TestWGNativeNetworkReceipt; do
  # Each case has a fresh network and private named-netns directory. Test
  # children and their peer interfaces have no path to the runner host network.
  unshare --mount --net --pid --fork --kill-child sh -eu -c '
    mount --make-rprivate /
    # The inherited proc mount still identifies the original outer PID1 here.
    test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)"
    test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
    umount -l /proc
    mount -t proc proc /proc
    mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
    mkdir -m 755 /run/netns
    mount -t tmpfs -o mode=0700,nodev,nosuid tmpfs /etc/wireguard
    mkdir -m 700 /etc/wireguard/fixture
    export TMPDIR=/etc/wireguard/fixture
    export RAZVILKA_WG_NATIVE=1 RAZVILKA_WG_NETWORK_NATIVE=1
    # Keep this shell as PID1: when it exits, a failed/timed-out test cannot
    # leave peer processes outside its disposable PID namespace. The actual
    # test owns a visible local process group and waits its original children.
    status=0
    setsid "$1" -test.run="^$2$" -test.count=1 -test.v -test.timeout=240s || status=$?
    exit "$status"
  ' sh "$wg_native_work/dataplane.test" "$wg_native_case" || wg_native_status=1
done
exit "$wg_native_status"
