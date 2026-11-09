#!/bin/sh
set -eu
# CI-only physical topology + original protected tool lease. Public ordinary
# domain Apply remains blocked; no router or existing namespace is changed.
test "$(id -u)" = 0 || { echo 'root isolated native fixture required' >&2; exit 2; }
: "${RAZVILKA_XRAY_NATIVE:?absolute SHA-verified official Xray binary required}"
case "$RAZVILKA_XRAY_NATIVE" in /*) ;; *) exit 2;; esac
for domain_tool in python3 unshare mount ip iptables-legacy ip6tables-legacy go timeout; do command -v "$domain_tool" >/dev/null; done
domain_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
domain_work=$(mktemp -d /tmp/razvilka-domain-original.XXXXXX)
chmod 700 "$domain_work"
trap 'rm -rf -- "$domain_work"' EXIT HUP INT TERM
export TMPDIR="$domain_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_DOMAIN_FIXTURE_WORK="$domain_work"
export RAZVILKA_DOMAIN_CPU_PROFILE="$domain_work"
python3 - <<'PY'
import hashlib,json,os,pathlib,subprocess
work=pathlib.Path(os.environ['RAZVILKA_DOMAIN_FIXTURE_WORK'])
xt=pathlib.Path('/usr/sbin/xtables-legacy-multi')
ip=pathlib.Path('/usr/bin/ip')
version=subprocess.check_output(['/usr/sbin/iptables-legacy','--version'],text=True).strip()
if not version.startswith('iptables v'): raise SystemExit('unexpected legacy tool identity')
review={'XTablesSHA256':hashlib.sha256(xt.read_bytes()).hexdigest(),'IPToolSHA256':hashlib.sha256(ip.read_bytes()).hexdigest(),'Version':version.removeprefix('iptables v'),'IPVersion':subprocess.check_output(['/usr/sbin/ip','-Version'],text=True)}
(work/'tools.json').write_text(json.dumps(review));(work/'tools.json').chmod(0o600)
print('CI-only platform classification; actual protected tool bytes:',json.dumps(review))
PY
export RAZVILKA_DOMAIN_ORIGINAL_NATIVE=1
export RAZVILKA_DOMAIN_TOOLS_REVIEW="$domain_work/tools.json"
cd "$domain_repo"
go test -tags razvilka_native_fixture -c -o "$domain_work/app.test" ./internal/app
chmod 500 "$domain_work/app.test"
# Go 1.26 may build pprof lazily; exclude that bounded parent preparation from
# both the namespace run and its CPU sample, retaining diagnostics on failure.
timeout 50s go tool pprof -h > "$domain_work/pprof-prewarm.log" 2>&1 || true
domain_status=0
domain_case=TestDomainTCPOriginalNativeAcceptedFlows
domain_test_timeout=180s
case "${RAZVILKA_DOMAIN_UNPUBLISHED_NATIVE:-0}" in
 0) ;;
 1) domain_case=TestDomainTCPOriginalNativeUnpublishedRetirement ;;
 *) exit 2 ;;
esac
case "${RAZVILKA_DOMAIN_DNS_ONLY_NATIVE:-0}" in
 0) ;;
 1)
  test "${RAZVILKA_DOMAIN_UNPUBLISHED_NATIVE:-0}" = 0 || exit 2
  domain_case=TestDomainTCPOriginalNativePublishedDNSStandby
  case "${RAZVILKA_DOMAIN_DNS_DETACH:-0}" in
   0) ;;
   1) domain_case=TestDomainTCPOriginalNativeDNSDetachment ;;
   *) exit 2 ;;
  esac ;;
 *) exit 2 ;;
esac
case "${RAZVILKA_DOMAIN_DNS_COEXISTENCE:-0}" in
 0) ;;
 1)
  test "${RAZVILKA_DOMAIN_DNS_ONLY_NATIVE:-0}" = 1 || exit 2
  test "${RAZVILKA_DOMAIN_DNS_DETACH:-0}" = 1 || exit 2
  test "${RAZVILKA_DOMAIN_UNPUBLISHED_NATIVE:-0}" = 0 || exit 2
  test -z "${RAZVILKA_DOMAIN_DNS_DETACH_ACK:-}" || exit 2
  test -z "${RAZVILKA_DOMAIN_DNS_DETACH_FOREIGN_HISTORY:-}" || exit 2
  domain_case=TestDomainTCPOriginalNativeDNSCoexistence
  case "${RAZVILKA_DOMAIN_INITIAL_ACK:-}" in
   '') ;;
   transaction|global) domain_case=TestDomainTCPOriginalNativeUnstartedKeeper ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR:-0}" in
   0) ;;
   1) test -z "${RAZVILKA_DOMAIN_INITIAL_ACK:-}" || exit 2; domain_case=TestDomainTCPOriginalNativeNeverIssuedKeeper ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_JOINED_FAILURE:-0}" in
   0) ;;
   1) test "${RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR:-0}" = 1 || exit 2; domain_case=TestDomainTCPOriginalNativeJoinedFailureKeeper ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_CANCELED_CHILD:-0}" in
   0) ;;
   1) test -z "${RAZVILKA_DOMAIN_INITIAL_ACK:-}" || exit 2; test "${RAZVILKA_DOMAIN_JOINED_FAILURE:-0}" = 0 || exit 2; test "${RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR:-0}" = 0 || exit 2; domain_case=TestDomainTCPOriginalNativeCanceledChildCleanup ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_CANCELED_READY:-0}" in
   0) ;;
   1) test "${RAZVILKA_DOMAIN_CANCELED_CHILD:-0}" = 1 || exit 2; domain_case=TestDomainTCPOriginalNativeCanceledReadyRetirement ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_CANCELED_PUBLISHED:-0}" in
   0) ;;
   1) test "${RAZVILKA_DOMAIN_CANCELED_READY:-0}" = 1 || exit 2; domain_case=TestDomainTCPOriginalNativeCanceledPublishedStandby ;;
   *) exit 2 ;;
  esac
  case "${RAZVILKA_DOMAIN_PREPARATION_CUT:-0}" in
   0) ;;
   1) test "${RAZVILKA_DOMAIN_CANCELED_CHILD:-0}" = 0 || exit 2; test "${RAZVILKA_DOMAIN_NEVER_ISSUED_SUCCESSOR:-0}" = 0 || exit 2; test "${RAZVILKA_DOMAIN_JOINED_FAILURE:-0}" = 0 || exit 2; test -z "${RAZVILKA_DOMAIN_INITIAL_ACK:-}" || exit 2; domain_case=TestDomainTCPOriginalNativeFailedPreparationRetirement ;;
   *) exit 2 ;;
  esac
  domain_test_timeout=240s ;;
 *) exit 2 ;;
esac
unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 # Original tool/preload review must observe protected ancestors, not the
 # unrelated hosted runners writable /opt cache. This mount is private.
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 touch /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 mount --bind "$1/app.test" /opt/bin/razvilka
 /usr/sbin/iptables-legacy -t mangle -S >/dev/null
 /usr/sbin/iptables-legacy -t raw -S >/dev/null
 /usr/sbin/iptables-legacy -t nat -S >/dev/null
 /usr/sbin/iptables-legacy -t filter -S >/dev/null
 /usr/sbin/ip6tables-legacy -t mangle -S >/dev/null
 exec /opt/bin/razvilka -test.run="^$2$" -test.v -test.count=1 -test.timeout="$3"
' sh "$domain_work" "$domain_case" "$domain_test_timeout" || domain_status=$?
# Keep the child's result. CPU symbols and bounded top output contain no
# profile/config credentials and are analyzed by the parent outside /opt.
if test -n "${RAZVILKA_DOMAIN_PROFILE_OUTPUT:-}"; then
 case "$RAZVILKA_DOMAIN_PROFILE_OUTPUT" in /*) ;; *) exit 2;; esac
 mkdir -p "$RAZVILKA_DOMAIN_PROFILE_OUTPUT"
 if test -s "$domain_work/original-run.cpu.pprof"; then
  cp "$domain_work/original-run.cpu.pprof" "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/"
  timeout 50s go tool pprof -top -nodecount=35 "$domain_work/app.test" "$domain_work/original-run.cpu.pprof" 2>&1 | head -c 65536 > "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/cpu-top.txt" || true
 fi
 domain_publication_budget=${RAZVILKA_DOMAIN_DIAGNOSTIC_PUBLICATION:-12}
 domain_diagnostic=${RAZVILKA_DOMAIN_DIAGNOSTIC_PUBLICATION:-false}
 if test "$domain_case" = TestDomainTCPOriginalNativeUnpublishedRetirement; then
  domain_publication_budget=not-sent
  domain_diagnostic=unpublished-readiness30-retirement-only
 fi
 printf 'child_exit_status=%s\npublication_budget_seconds=%s\nprofile_span=original_Run_through_join\ndiagnostic_only=%s\nnative_case=%s\n' "$domain_status" "$domain_publication_budget" "$domain_diagnostic" "$domain_case" > "$RAZVILKA_DOMAIN_PROFILE_OUTPUT/status.txt"
fi
exit "$domain_status"
