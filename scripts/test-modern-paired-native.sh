#!/bin/sh
set -eu
umask 077
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 && test "$(id -u)" = 0 || exit 2
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d /root/razvilka-modern-pair.XXXXXX)
chmod 700 "$work"
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
source_sha=$(git rev-parse HEAD)
# Complete main binaries, fixture platform classification, same source and
# supported linker-version knobs. No release/tag/provenance is manufactured.
go build -tags razvilka_native_fixture -ldflags="-s -w -X github.com/ArtixSx/razvilka/internal/app.Version=0.20.0 -X github.com/ArtixSx/razvilka/internal/app.BuildCommit=$source_sha" -o "$work/source" ./cmd/razvilka
go build -tags razvilka_native_fixture -ldflags="-s -w -X github.com/ArtixSx/razvilka/internal/app.Version=0.20.1 -X github.com/ArtixSx/razvilka/internal/app.BuildCommit=$source_sha" -o "$work/candidate" ./cmd/razvilka
go test -tags razvilka_native_fixture -ldflags='-s -w' -c -o "$work/cmd.test" ./cmd/razvilka
hook_status=0
go test -tags razvilka_native_fixture ./internal/updatecheck -run '^TestNativeModern' -count=1 -v >"$work/hooks.log" 2>&1 || hook_status=$?
cat "$work/hooks.log"
test "$hook_status" -eq 0
for name in TestNativeModernPublishedHandoff TestNativeModernAbsentAndInvalidMarker TestNativeModernClosedCommandList; do
 grep -F -- "--- PASS: $name " "$work/hooks.log"
done
if grep -E '^[[:space:]]*--- SKIP:' "$work/hooks.log"; then exit 1; fi
test "$("$work/source" -version)" = 0.20.0
test "$("$work/candidate" -version)" = 0.20.1
for binary in source candidate; do
 test "$("$work/$binary" -strategy-lab-read-version)" = 7
 test "$("$work/$binary" -self-update-private-snapshot-read-version)" = 4
done
chmod 500 "$work/source" "$work/candidate" "$work/cmd.test"
cp scripts/fixtures/modern-pair-daemon.py "$work/modern-daemon.py"
chmod 500 "$work/modern-daemon.py"
mkdir -p "$work/package/RAZVILKA-0.20.1/dist"
cp -R configs scripts "$work/package/RAZVILKA-0.20.1/"
cp "$work/candidate" "$work/package/RAZVILKA-0.20.1/dist/razvilka-linux-amd64"
(cd "$work/package/RAZVILKA-0.20.1" && sha256sum dist/razvilka-linux-amd64 >dist/SHA256SUMS)
tar -czf "$work/release.tar.gz" -C "$work/package" RAZVILKA-0.20.1
sh scripts/fetch-native-fixture.sh zapret2-1.0.6 "$work/nfqws-source.tar.gz"
tar -xzf "$work/nfqws-source.tar.gz" -C "$work" zapret2-v1.0.6/binaries/linux-x86_64/nfqws2
echo "25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1  $work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2" | sha256sum --check --strict
chmod 500 "$work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2"
python3 - "$work/runtime-native-tool-review.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys
xt=pathlib.Path('/usr/sbin/xtables-legacy-multi'); ip=pathlib.Path('/usr/bin/ip').resolve()
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True)
assert version in ('iptables v1.8.10 (legacy)\n','iptables v1.8.11 (legacy)\n')
review={'XTablesSHA256':hashlib.sha256(xt.read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(ip.read_bytes()).hexdigest(),'Version':version.removesuffix('\n').removeprefix('iptables v'),'IPVersion':subprocess.check_output([str(ip),'-Version'],text=True)}
p=pathlib.Path(sys.argv[1]);p.write_text(json.dumps(review));p.chmod(0o600)
PY
export RAZVILKA_MODERN_PAIR_NATIVE=1 RAZVILKA_PAIRED_NATIVE_SCOPE=1
export RAZVILKA_RUNTIME_NATIVE_REVIEW="$work/runtime-native-tool-review.json" RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
exec 3</proc/self/ns/net 4</proc/self/ns/mnt 5</proc/self/ns/pid
status=0
unshare --mount --net /bin/sh "$repo/scripts/fixtures/modern-pair-session.sh" "$work" "$repo" outer >"$work/native.log" 2>&1 || status=$?
cat "$work/native.log"
test "$status" -eq 0
grep -F 'actual_modern_public_pair rollback=true source_live_restored=true candidate_live_observed=true original_post_live_fault=true original_receipt=true draft_bytes_preserved=true all_panels_joined=true same_source_lab_versions=true official_release_provenance=false router_ready=false' "$work/native.log"
grep -F -- '--- PASS: TestNativeModernPublicRollback ' "$work/native.log"
if grep -E '^[[:space:]]*--- SKIP:' "$work/native.log"; then exit 1; fi
printf 'PASS actual main/public updater/known rollback with tagged platform classification and synthetic release transport; same-source schema compatibility only.\n'
case "$work" in /root/razvilka-modern-pair.*) rm -rf -- "$work" ;; *) exit 2 ;; esac
