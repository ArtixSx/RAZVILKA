#!/bin/sh
set -eu
# Lab outputs only. Never installs/replaces an official asset or router binary.
test "$#" = 1 || { echo 'usage: build-hev-runtime-altstack-lab.sh NEW_ABSOLUTE_OUTPUT'; exit 2; }
out=$1
case "$out" in /*) ;; *) exit 2;; esac
test ! -e "$out" && test ! -L "$out" || exit 2
for tool in curl python3 sha256sum make patch; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
umask 077
mkdir "$out"
out=$(CDPATH= cd -- "$out" && pwd -P)
source_name=hev-socks5-tunnel-2.17.1.tar.xz
tool_name=x86_64-unknown-linux-musl.tar.xz
source_sha=a7b86050091c5a268d81de70b95d3bb0871ba4136160662b6496596761c2f9a7
tool_sha=5f20e367608d6e547c04534d37d00ecedbaa0c2e82730df12957b3332fa36a2d
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 2 \
 "https://github.com/heiher/hev-socks5-tunnel/releases/download/2.17.1/$source_name" -o "$out/$source_name"
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 2 \
 "https://github.com/cross-tools/musl-cross/releases/download/20260515/$tool_name" -o "$out/$tool_name"
printf '%s  %s\n%s  %s\n' "$source_sha" "$out/$source_name" "$tool_sha" "$out/$tool_name" | sha256sum -c -
python3 - "$out" "$repo" <<'PY'
import hashlib,json,pathlib,shutil,sys,tarfile
out=pathlib.Path(sys.argv[1]);repo=pathlib.Path(sys.argv[2])
for archive,destination,prefix in [('hev-socks5-tunnel-2.17.1.tar.xz','original','hev-socks5-tunnel-2.17.1'),('x86_64-unknown-linux-musl.tar.xz','toolchain','x86_64-unknown-linux-musl')]:
    target=out/destination;target.mkdir()
    with tarfile.open(out/archive,'r:xz') as tar:
        members=tar.getmembers()
        assert len(members)<=25000 and sum(m.size for m in members)<=2<<30
        for member in members:
            path=pathlib.PurePosixPath(member.name)
            assert not path.is_absolute() and '..' not in path.parts and path.parts[0]==prefix
        tar.extractall(target,filter='data')
source=out/'original/hev-socks5-tunnel-2.17.1'
detector=source/'third-part/hev-task-system/src/lib/misc/hev-task-stack-detector.c'
assert hashlib.sha256(detector.read_bytes()).hexdigest()=='b2f494d342f0ee3cb5d96bd8c96fe1e3b454e96c9a458c76b926d88f44c24367'
assert (source/'.rev-id').read_text().strip()=='9a06bc6'
shutil.copytree(source,out/'patched',symlinks=True)
for name in ['hev-runtime-altstack.patch','hev-runtime-altstack-fault-test.c']:
    shutil.copyfile(repo/'scripts/fixtures'/name,out/name)
PY
patch --fuzz=0 --batch --forward --dry-run -p1 -d "$out/patched" < "$out/hev-runtime-altstack.patch"
patch --fuzz=0 --batch --forward -p1 -d "$out/patched" < "$out/hev-runtime-altstack.patch"
printf '%s  %s\n' 500bd669dbeb6e125ff21c48877f42d80b378a7c3f09b2d12bee0d784a702733 "$out/patched/third-part/hev-task-system/src/lib/misc/hev-task-stack-detector.c" | sha256sum -c -
prefix="$out/toolchain/x86_64-unknown-linux-musl/bin/x86_64-unknown-linux-musl-"
"${prefix}gcc" --version > "$out/compiler.txt"
mkdir "$out/bin"
for side in original patched; do
 source="$out/$side"
 if test "$side" = original; then source="$source/hev-socks5-tunnel-2.17.1"; fi
 make -C "$source" CROSS_PREFIX="$prefix" ENABLE_STATIC=1 -j2 > "$out/build-$side.log" 2>&1
 cp "$source/bin/hev-socks5-tunnel" "$out/bin/hev-$side"
 chmod 0500 "$out/bin/hev-$side"
done
task="$out/patched/third-part/hev-task-system"
"${prefix}gcc" -static -O2 -Wall -Werror -pthread \
 -I"$task/src" -I"$task/include" \
 "-DHEV_STACK_SOURCE=\"$task/src/lib/misc/hev-task-stack-detector.c\"" \
 "$out/hev-runtime-altstack-fault-test.c" "$task/bin/libhev-task-system.a" \
 -o "$out/bin/altstack-fault.test"
ulimit -c 0
"$out/bin/altstack-fault.test" > "$out/fault-tests.txt" 2>&1
grep -qx HEV_RUNTIME_ALTSTACK_FAULT_CONTRACT_PASS "$out/fault-tests.txt"
python3 - "$out" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=out/'original/hev-socks5-tunnel-2.17.1';patched=out/'patched'
files=['hev-socks5-tunnel-2.17.1.tar.xz','x86_64-unknown-linux-musl.tar.xz','hev-runtime-altstack.patch','hev-runtime-altstack-fault-test.c','bin/hev-original','bin/hev-patched','bin/altstack-fault.test']
licenses=[]
for root in [source,patched,out/'toolchain']:
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink() and path.name.lower().startswith(('license','copying','copyright')):
            licenses.append({'path':str(path.relative_to(out)),'sha256':sha(path)})
record={'schema':1,'purpose':'separate lab qualification only; original official asset unchanged','hev_commit':'9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a','task_commit':'328f35d903221b51811b3d02b277d665dfbdc75f','official_binary_sha256':'a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03','toolchain_release':'20260515','compiler':(out/'compiler.txt').read_text(),'build_flags':['ENABLE_STATIC=1','-j2'],'artifacts':{name:sha(out/name) for name in files},'licenses':licenses,'fault_tests':'PASS','route_or_router_acceptance':False}
(out/'build-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
print('HEV_RUNTIME_ALTSTACK_LAB_BUILD_PASS')
PY
