#!/bin/sh
set -eu
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_MIHOMO_ARCHIVE:?official pinned archive required}"
: "${RAZVILKA_EXECUTION_READER4_BINARY:?actual pinned d36 reader4 required}"
: "${RAZVILKA_XRAY_NATIVE:?official pinned 26.3.27 VLESS peer required}"
case "$RAZVILKA_MIHOMO_ARCHIVE" in /*) ;; *) exit 2;; esac
cold_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cold_work=$(mktemp -d /tmp/razvilka-mihomo-cold.XXXXXX)
chmod 700 "$cold_work"
trap 'rm -rf -- "$cold_work"' EXIT HUP INT TERM
export TMPDIR="$cold_work" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
cd "$cold_repo"
go test -tags razvilka_native_fixture -c -o "$cold_work/app.test" ./internal/app
go build -o "$cold_work/controller" ./cmd/razvilka
chmod 500 "$cold_work/app.test" "$cold_work/controller"
# A separate fresh process/namespace prevents cached CA pools and retained
# reader4 history from contaminating the subsequent reader5 crash scenario.
RAZVILKA_DOMAIN_ORIGINAL_NATIVE=1 RAZVILKA_MIHOMO_SERVICE_NATIVE=1 unshare --mount --net sh -eu -c '
 mount --make-rprivate /
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 cp "$1/app.test" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 exec /opt/bin/razvilka -test.run="^TestMihomoOriginalNativeHTTPReader4Fallback$" -test.v -test.count=1 -test.timeout=180s
' sh "$cold_work"
unshare --mount --net --pid --fork sh -eu -c '
 mount --make-rprivate /
 # The original identity parser refuses overmounts, including hidden /proc
 # roots. Retire the outer proc mount in this private mount namespace first.
 umount -l /proc
 mount -t proc proc /proc
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 ip link set lo up
 work=$1
 cp "$work/app.test" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 producer= copy= panel=
 trap '\''for child in "$producer" "$copy" "$panel"; do if test -n "$child"; then kill -KILL "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; done'\'' EXIT HUP INT TERM
 export RAZVILKA_MIHOMO_COLD_READY="$work/ready.json"
 /opt/bin/razvilka -test.run="^TestMihomoColdOriginalProducer$" -test.v -test.timeout=100s > "$work/producer.log" 2>&1 &
 producer=$!
 python3 - "$work/ready.json" "$producer" <<'\''PY'\''
import pathlib,sys,time
p=pathlib.Path(sys.argv[1]); proc=pathlib.Path("/proc")/sys.argv[2]; deadline=time.monotonic()+40
while time.monotonic()<deadline:
 if p.exists(): break
 try:
  if proc.joinpath("stat").read_text().rsplit(") ",1)[1].split()[0] in ("Z","X","x"): raise SystemExit("actual original producer exited before readiness")
 except FileNotFoundError: raise SystemExit("actual original producer exited before readiness")
 time.sleep(.05)
else: raise SystemExit("actual native producer did not publish listener-ready COMMON")
PY
 cp /opt/razvilka/state/dataplane/latest-execution.json "$work/original.json"
 plan=$(python3 -c '\''import json,sys;print(json.load(open(sys.argv[1]))["plan_id"])'\'' "$work/ready.json")
 digest=$(python3 -c '\''import json,sys;print(json.load(open(sys.argv[1]))["digest"])'\'' "$work/ready.json")
 # The installed producer owns five real lifetime leases. A concurrent
 # public maintenance command must refuse without changing either record.
 if "$work/controller" -retire-mihomo-probe-after-parent-plan "$plan" -retire-mihomo-probe-after-parent-digest "$digest" > "$work/live-parent.log" 2>&1; then echo "live parent/lease admission accepted" >&2; exit 1; fi
 cmp "$work/original.json" /opt/razvilka/state/dataplane/latest-execution.json
 kill -KILL "$producer"
 wait "$producer" 2>/dev/null || true
 producer=
 # Install the actual reviewed test controller for the new ordinary boot.
 # This is fixture setup only, inside private /opt, after the old parent died.
 cp "$work/controller" /opt/bin/razvilka
 chmod 555 /opt/bin/razvilka
 python3 - "$work/ready.json" <<'\''PY'\''
import hashlib,json,os,pathlib,sys,time
d=json.load(open(sys.argv[1]))["resources"][0]["mihomo_probe"]["source"]
deadline=time.monotonic()+5
while time.monotonic()<deadline:
 found=False
 for p in pathlib.Path("/proc").iterdir():
  if not p.name.isdigit(): continue
  try:
   exe=p/"exe"
   if exe.stat().st_size==d["binary_size"] and hashlib.sha256(exe.read_bytes()).hexdigest()==d["binary_sha256"]: found=True
  except (FileNotFoundError,ProcessLookupError): pass
 if not found: break
 time.sleep(.02)
else: raise SystemExit("original actual Mihomo child outlived killed parent")
PY
 # Same boot/net namespace is insufficient when /proc uses another PID ns.
 if unshare --mount --pid --fork sh -eu -c '\''
  mount --make-rprivate /
  umount -l /proc
  mount -t proc proc /proc
  "$1/app.test" -test.run="^TestMihomoColdActualNetworkIdentity$" -test.v -test.count=1
  shift
  exec /opt/bin/razvilka "$@"
 '\'' sh "$work" -retire-mihomo-probe-after-parent-plan "$plan" -retire-mihomo-probe-after-parent-digest "$digest" > "$work/foreign-pidns.log" 2>&1; then echo "foreign PID namespace admitted" >&2; exit 1; fi
 grep -q "PASS: TestMihomoColdActualNetworkIdentity" "$work/foreign-pidns.log"
 cmp "$work/original.json" /opt/razvilka/state/dataplane/latest-execution.json
 cp "$work/app.test" "$work/opaque-copy"
 chmod 500 "$work/opaque-copy"
 RAZVILKA_MIHOMO_COPY_READY="$work/copy-ready" "$work/opaque-copy" -test.run="^TestMihomoColdForeignCopy$" > "$work/copy.log" 2>&1 &
 copy=$!
 python3 - "$work/copy-ready" <<'\''PY'\''
import pathlib,sys,time
p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+5
while time.monotonic()<deadline:
 if p.exists(): break
 time.sleep(.02)
else: raise SystemExit("copied original controller did not start")
PY
 if /opt/bin/razvilka -retire-mihomo-probe-after-parent-plan "$plan" -retire-mihomo-probe-after-parent-digest "$digest" > "$work/copied-process.log" 2>&1; then echo "copied controller admitted" >&2; exit 1; fi
 cmp "$work/original.json" /opt/razvilka/state/dataplane/latest-execution.json
 kill -KILL "$copy"
 wait "$copy" 2>/dev/null || true
 copy=
 /opt/bin/razvilka -retire-mihomo-probe-after-parent-plan "$plan" -retire-mihomo-probe-after-parent-digest "$digest" > "$work/result.json"
 python3 - "$work/original.json" "$work/result.json" <<'\''PY'\''
import base64,json,pathlib,sys
before=pathlib.Path(sys.argv[1]).read_bytes();after=json.load(open(sys.argv[2]))
assert after["state"]=="temporary-complete" and after["steps"][0]["state"]=="failed"
assert not after.get("rollback_verified",False)
assert after["resources"][0]["phase"]=="removed"
root=pathlib.Path("/opt/razvilka/state/dataplane")
manifest=json.loads((root/"mihomo-probe-retirements"/after["plan_id"]/"retirement.json").read_bytes())
assert manifest["same_boot"] is True and base64.b64decode(manifest["before"])==before
assert (root/"latest-execution.json").read_bytes()==(root/"transactions"/after["plan_id"]/"execution.json").read_bytes()
print("PASS actual parent/Pdeath exit, foreign PID namespace/copy/lease refusal, public cold CLI exact archive/CAS; no service or original cleanup proof")
PY
 # Ordinary Main now has to pass the very same retained recovery admission.
 /opt/bin/razvilka -listen 127.0.0.1:28787 > "$work/panel.log" 2>&1 &
 panel=$!
 python3 - <<'\''PY'\''
import json,time,urllib.request
deadline=time.monotonic()+25
while time.monotonic()<deadline:
 try:
  token=open("/opt/etc/razvilka/admin.token").read().strip()
  req=urllib.request.Request("http://127.0.0.1:28787/api/v1/panel/availability",headers={"Authorization":"Bearer "+token})
  with urllib.request.urlopen(req,timeout=1) as r:
   result=json.load(r)
   assert r.status==200
   print("PASS actual ordinary panel HTTP recovery admission after cold retirement",result)
   break
 except (OSError,ValueError): time.sleep(.1)
else: raise SystemExit("ordinary panel did not recover HTTP readiness")
PY
 kill -TERM "$panel"
 wait "$panel" || true
 panel=
' sh "$cold_work" || {
 code=$?
 for cold_log in producer live-parent foreign-pidns copied-process panel; do
  if test -f "$cold_work/$cold_log.log"; then printf '\n%s\n' "$cold_log"; tail -c 16384 "$cold_work/$cold_log.log"; fi
 done
 exit "$code"
}
