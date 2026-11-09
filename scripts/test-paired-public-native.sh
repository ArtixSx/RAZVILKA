#!/bin/sh
set -eu
umask 077
case "${RAZVILKA_PAIRED_NATIVE_HISTORY:-}" in ""|draft) ;; *) exit 2 ;; esac
export RAZVILKA_PAIRED_NATIVE_HISTORY
test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64 && test "$(id -u)" = 0 || exit 2
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d /root/razvilka-paired-public.XXXXXX)
chmod 700 "$work"
export TMPDIR="$work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$repo"
# No clone, release or publication: an isolated exact historical source tree.
old=817783493f0c2784ccc70aa73868cd64e9437634
test "$(git rev-parse v0.19.3^{commit})" = "$old"
mkdir "$work/old-source"
git archive "$old" | tar -xf - -C "$work/old-source"
(cd "$work/old-source" && go build -ldflags='-s -w' -o "$work/old-controller" ./cmd/razvilka)
go build -ldflags='-s -w' -tags razvilka_native_fixture -o "$work/candidate" ./cmd/razvilka
go test -ldflags='-s -w' -tags razvilka_native_fixture -c -o "$work/cmd.test" ./cmd/razvilka
"$work/cmd.test" -test.run '^TestExternalBootstrapDiagnostic|^TestNativePairedRestoreOutput' -test.count=1 -test.v -test.timeout=30s
go test -tags razvilka_native_fixture ./internal/updatecheck -run '^TestNativeRuntimeCommandForwarding|^TestExternalBootstrapFileDiagnostic|^TestBootstrapOfflineStrategy|^TestBootstrapImage|^TestOrdinaryImage' -count=1 -v
test "$("$work/old-controller" -version)" = 0.19.3
test "$("$work/candidate" -version)" = 0.20.0
chmod 500 "$work/old-controller" "$work/candidate" "$work/cmd.test"
# Reuse the existing independently pinned no-hook queue initializer. It runs
# and joins before the PID namespace, so its /proc/1 isolation check stays real.
sh "$repo/scripts/fetch-native-fixture.sh" zapret2-1.0.6 "$work/nfqws-source.tar.gz"
tar -xzf "$work/nfqws-source.tar.gz" -C "$work" zapret2-v1.0.6/binaries/linux-x86_64/nfqws2
echo "25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1  $work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2" | sha256sum --check --strict
chmod 500 "$work/zapret2-v1.0.6/binaries/linux-x86_64/nfqws2"
mkdir -p "$work/package/RAZVILKA-0.20.0/dist"
cp -R configs scripts "$work/package/RAZVILKA-0.20.0/"
cp "$work/candidate" "$work/package/RAZVILKA-0.20.0/dist/razvilka-linux-amd64"
(cd "$work/package/RAZVILKA-0.20.0" && sha256sum dist/razvilka-linux-amd64 >dist/SHA256SUMS)
tar -czf "$work/release.tar.gz" -C "$work/package" RAZVILKA-0.20.0
export RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ID=0123456789abcdef0123456789abcdef
export RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_CANDIDATE="$work/candidate"
export RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ARCHIVE="$work/release.tar.gz"
export RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ARCHIVE_SHA=$(sha256sum "$work/release.tar.gz" | cut -d ' ' -f 1)
export RAZVILKA_NATIVE_PAIRED_RESTORE_ID="$RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ID"
export RAZVILKA_NATIVE_PAIRED_RESTORE_CANDIDATE="$work/candidate"
export RAZVILKA_PAIRED_NATIVE_SOURCE_SHA=$(sha256sum "$work/old-controller" | cut -d ' ' -f 1)
export RAZVILKA_PAIRED_NATIVE_INIT_SHA=$(sha256sum "$work/old-source/scripts/S99razvilka" | cut -d ' ' -f 1)
export RAZVILKA_PAIRED_NATIVE_SCOPE=1
python3 - "$work/runtime-native-tool-review.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys
xt=pathlib.Path('/usr/sbin/xtables-legacy-multi'); ip=pathlib.Path('/usr/bin/ip').resolve()
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True)
assert version in ('iptables v1.8.10 (legacy)\n','iptables v1.8.11 (legacy)\n')
version=version.removesuffix('\n')
review={'XTablesSHA256':hashlib.sha256(xt.read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(ip.read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output([str(ip),'-Version'],text=True)}
path=pathlib.Path(sys.argv[1]);path.write_text(json.dumps(review));path.chmod(0o600)
PY
export RAZVILKA_RUNTIME_NATIVE_REVIEW="$work/runtime-native-tool-review.json" RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
# Original namespace identities are retained before ANY isolation/mount action.
exec 3</proc/self/ns/net 4</proc/self/ns/mnt 5</proc/self/ns/pid
status=0
unshare --mount --net /bin/sh "$repo/scripts/fixtures/paired-public-session.sh" "$work" "$repo" outer >"$work/native.log" 2>&1 || status=$?
cat "$work/native.log"
if test "$status" -ne 0; then
  printf 'Paired public fixture failed (%s); private artifacts retained only at %s\n' "$status" "$work" >&2
  exit "$status"
fi
grep -F 'actual_configured_old193_public_pair complete=true source_restored_offline=true original_stop_retained=true guards_preserved=true tagged_platform_classification=true' "$work/native.log"
grep -F -- '--- PASS: TestNativeConfiguredOld193PairLifecycle ' "$work/native.log"
if grep -E '^[[:space:]]*--- SKIP:' "$work/native.log"; then exit 1; fi
if test "${RAZVILKA_PAIRED_NATIVE_HISTORY:-}" = draft; then
 grep -F 'actual_public_pair_retained_draft preserved=true original_old_http_writer=true current_reader=true old_live_compatibility=false manual_selection=false' "$work/native.log"
else
 printf 'PASS baseline empty configured pair; nonempty draft/history/selection are separate scenarios.\n'
fi
printf 'PASS configured source0.19.3 -> genuine public bootstrap -> current durable Stop -> public offline restore. Tagged Ubuntu classification; no router/default legacy-layout or old live-reader claim.\n'
# Only this exact private fixture directory is removed after all assertions.
case "$work" in /root/razvilka-paired-public.*) rm -rf -- "$work" ;; *) exit 2 ;; esac
