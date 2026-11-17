#!/bin/sh
set -eu
umask 077

# Dedicated disposable Ubuntu 26.04 acceptance, never a production installer.
# No stock/profile override, package installation, NFQWS download or LAN claim.
test "$(id -u)" = 0 || { echo 'ROOT isolated CI fixture required' >&2; exit 2; }
for classic_tool in python3 dpkg-query dpkg-deb unshare mount ip iptables-legacy ip6tables-legacy go timeout; do
  command -v "$classic_tool" >/dev/null
done
classic_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 "$classic_repo/scripts/check-classic-save-pinned-fixture.py"
classic_work=$(mktemp -d /tmp/razvilka-classic-pinned.XXXXXX)
chmod 700 "$classic_work"
trap 'rm -rf -- "$classic_work"' EXIT HUP INT TERM
export TMPDIR="$classic_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_MANAGED_PROBE_NATIVE=1 RAZVILKA_STARTUP_TOOLS_NATIVE=ubuntu-legacy
export RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW="$classic_work/tools.json"
python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess
review = {
    'XTablesSHA256': hashlib.sha256(pathlib.Path('/usr/sbin/xtables-legacy-multi').read_bytes()).hexdigest(),
    'IPToolSHA256': hashlib.sha256(pathlib.Path('/usr/bin/ip').read_bytes()).hexdigest(),
    'Version': '1.8.11 (legacy)',
    'IPVersion': subprocess.check_output(['/usr/sbin/ip', '-Version'], text=True),
}
pathlib.Path(os.environ['RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW']).write_text(json.dumps(review))
print('Actual pinned classic fixture source:', json.dumps(review, sort_keys=True))
PY
cd "$classic_repo"
classic_mode=${RAZVILKA_MANAGED_PROBE_BUILD_MODE:-production}
printf 'Actual pinned classic native build mode: %s\n' "$classic_mode"
uname -a
go version
case "$classic_mode" in
  production) go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$classic_work/startuptools.test" ./internal/startuptools ;;
  race) go test -race -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$classic_work/startuptools.test" ./internal/startuptools ;;
  *) echo 'Unknown native build mode' >&2; exit 2 ;;
esac
# Retain genuine originals before unshare. Validate both fresh namespaces before
# any mount/rule effects, then make propagation private. /run is private too:
# the actual lock tests must not create or replace a lock in the runner's /run.
exec 3< /proc/self/ns/net 4< /proc/self/ns/mnt
for classic_case in TestProductionStartupToolsNative TestClassicSaveNativeInventoryParity TestClassicSaveNativeLockCustody TestClassicReadBatchNativeMutation; do
  unshare --mount --net sh -c '
    set -eu
    python3 - <<"PY"
import fcntl, os
for descriptor, name, kind in [(3, "net", 0x40000000), (4, "mnt", 0x00020000)]:
    if fcntl.ioctl(descriptor, 0xb703) != kind:
        raise SystemExit("retained descriptor is not the required namespace: " + name)
    outer = os.fstat(descriptor)
    inner = os.stat("/proc/self/ns/" + name)
    if (outer.st_dev, outer.st_ino) == (inner.st_dev, inner.st_ino):
        raise SystemExit("original namespace was not isolated: " + name)
PY
    mount --make-rprivate /
    python3 - <<"PY"
with open("/proc/self/mountinfo", "rb") as mounts:
    data = mounts.read((1 << 20) + 1)
if len(data) > 1 << 20:
    raise SystemExit("mount inventory exceeds fixture bound")
root = False
for line in data.decode().splitlines():
    fields = line.split()
    separator = fields.index("-")
    if separator < 6 or len(fields) < separator + 4:
        raise SystemExit("malformed mount inventory")
    root = root or fields[4] == "/"
    if any(field.startswith(("shared:", "master:", "propagate_from:")) for field in fields[6:separator]):
        raise SystemExit("private mount propagation required")
if not root:
    raise SystemExit("original root mount unavailable")
PY
    mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
    mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
    for family in /usr/sbin/iptables-legacy /usr/sbin/ip6tables-legacy; do
      for table in filter mangle nat raw security; do
        "$family" -t "$table" -S >/dev/null
      done
    done
    exec "$@"
  ' sh "$classic_work/startuptools.test" -test.run="^${classic_case}\$" -test.count=1 -test.v -test.timeout=100s
done
printf 'ACTUAL_PINNED_CLASSIC_1_8_11_NATIVE_COMPLETE mode=%s\n' "$classic_mode"
