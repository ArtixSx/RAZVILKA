#!/bin/sh
set -eu

# CI-only ROOT fixture. All packet/address/rule effects occur in a new netns.
# Production installer/stock platform approval remains unchanged. The tagged
# fixture models platform classification, NOT artifact bytes, FD ownership,
# compatibility, NFQUEUE packets, TLS/catalogue predicates or cleanup.
test "$(id -u)" = 0 || { echo 'ROOT isolated CI fixture required' >&2; exit 2; }
for probe_tool in curl sha256sum tar python3 unshare mount ip iptables-legacy ip6tables-legacy nft go; do
  command -v "$probe_tool" >/dev/null
done
probe_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
probe_work=$(mktemp -d /tmp/razvilka-managed-probe.XXXXXX)
chmod 700 "$probe_work"
trap 'rm -rf -- "$probe_work"' EXIT HUP INT TERM
export TMPDIR="$probe_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2

# Official release v1.0.6, source tag resolves to
# 221d7dff24bfec0cd5ac0a5070b8acef2008af3d. The archive digest was checked
# against the official release API's sha256 digest; every consumed member is
# additionally pinned below. No unreviewed release, branch or latest lookup.
curl --fail --location --retry 3 --output "$probe_work/release.tar.gz" \
  https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.tar.gz
echo "eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4  $probe_work/release.tar.gz" | sha256sum --check --strict
tar -xzf "$probe_work/release.tar.gz" -C "$probe_work" \
  zapret2-v1.0.6/binaries/linux-x86_64/nfqws2 \
  zapret2-v1.0.6/lua/zapret-lib.lua \
  zapret2-v1.0.6/lua/zapret-antidpi.lua \
  zapret2-v1.0.6/lua/zapret-auto.lua \
  zapret2-v1.0.6/files/fake/quic_initial_www_google_com.bin \
  zapret2-v1.0.6/files/fake/tls_clienthello_www_google_com.bin
export RAZVILKA_MANAGED_PROBE_FIXTURE_WORK="$probe_work"
python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess
work = pathlib.Path(os.environ['RAZVILKA_MANAGED_PROBE_FIXTURE_WORK'])
base = work / 'zapret2-v1.0.6'
members = [
 ('binaries/linux-x86_64/nfqws2', '25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1'),
 ('lua/zapret-lib.lua', '6bf528fef1f0fc3c65e189216fc8a06bb873f6e25d1c29d2bfa4695a09b73440'),
 ('lua/zapret-antidpi.lua', '6d1fa9168e5de1682fef91fd174f68b58c50f6739ef00f42ca7db2b940b6246d'),
 ('lua/zapret-auto.lua', '23a9b99a776d868d92f4cc0ee5110f5c1f12fe746620d9c0337022dbc2f52df0'),
 ('files/fake/quic_initial_www_google_com.bin', 'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a'),
 ('files/fake/tls_clienthello_www_google_com.bin', '936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c'),
]
paths = []
for relative, expected in members:
    path = base / relative
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit('pinned member refused: ' + relative)
    path.chmod(0o500 if not paths else 0o400)
    paths.append({'Path': str(path), 'SHA256': expected})
# Retain PRIVATE ancestors of the actual executable/assets, not just leaves.
for path in base.rglob('*'):
    if path.is_dir(): path.chmod(0o700)
base.chmod(0o700)
arguments = ['--lua-init=@' + p['Path'] for p in paths[1:4]]
arguments += ['--blob=quic_initial:@' + paths[4]['Path'], '--blob=tls_clienthello:@' + paths[5]['Path']]
(work / 'genuine.json').write_text(json.dumps({'BinaryPath': paths[0]['Path'], 'BinarySHA256': paths[0]['SHA256'], 'Assets': paths[1:], 'BaseArguments': arguments}))
xt = pathlib.Path('/usr/sbin/xtables-legacy-multi')
ip = pathlib.Path('/usr/bin/ip')
version = subprocess.check_output(['/usr/sbin/iptables-legacy', '--version'], text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected xtables identity')
version = version.removeprefix('iptables v')
review = {'XTablesSHA256': hashlib.sha256(xt.read_bytes()).hexdigest(), 'IPToolSHA256': hashlib.sha256(ip.read_bytes()).hexdigest(), 'Version': version, 'IPVersion': subprocess.check_output(['/usr/sbin/ip', '-Version'], text=True)}
(work / 'tools.json').write_text(json.dumps(review))
print('CI-only platform classification; actual tool hashes/version:', json.dumps(review))
PY
export RAZVILKA_MANAGED_PROBE_NATIVE=1
export RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW="$probe_work/genuine.json"
export RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW="$probe_work/tools.json"
cd "$probe_repo"
go test -race -tags razvilka_native_fixture -c -o "$probe_work/app.test" ./internal/app
chmod 500 "$probe_work/app.test"
# GitHub's host /opt is writable for its tool cache. The real protected tool
# review correctly refuses it as a preload ancestor. Give this disposable
# mount namespace an actual empty protected /opt; never chmod/change the host.
unshare --mount --net sh -c '
  set -eu
  mount --make-rprivate /
  mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
  # Register actual legacy table/proc inventories before the complete reader.
  # This unreferenced disposable chain loads the NFQUEUE target, sees no
  # packets, and is deleted before original App/Manager admission begins.
  /usr/sbin/iptables-legacy -t mangle -S >/dev/null
  /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
  /usr/sbin/iptables-legacy -t mangle -N RZV_CI_NFQ_BOOTSTRAP
  /usr/sbin/iptables-legacy -t mangle -A RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -D RZV_CI_NFQ_BOOTSTRAP -j NFQUEUE --queue-num 64611
  /usr/sbin/iptables-legacy -t mangle -X RZV_CI_NFQ_BOOTSTRAP
  exec "$@"
' sh "$probe_work/app.test" -test.run='^TestManagedStrategyProbeNativeConsumer$' -test.count=1 -test.v -test.timeout=100s
