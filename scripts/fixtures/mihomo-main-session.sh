#!/bin/sh
set -eu
 mount --make-rprivate /
 umount -l /proc
 mount -t proc proc /proc
 mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /opt
 mkdir -m 755 /opt/bin
 ip link set lo up
 work=$1
 cp "$work/app.test" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 RAZVILKA_MIHOMO_MAIN_SETUP=1 /opt/bin/razvilka -test.run="^TestMihomoReplacementOriginalMainSetup$" -test.v -test.count=1 -test.timeout=60s
 cp /opt/bin/mihomo "$work/binary-before"
 cp /opt/bin/.mihomo.razvilka.json "$work/receipt-before"
 cp /opt/razvilka/state/components/receipts/mihomo.json "$work/lifecycle-before"
 cp "$work/controller" /opt/bin/razvilka
 chmod 500 /opt/bin/razvilka
 proxy= panel=
 trap 'for child in "$panel" "$proxy"; do if test -n "$child"; then kill -KILL "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; done' EXIT HUP INT TERM
 python3 "$2/scripts/fixtures/mihomo-release-proxy.py" "$RAZVILKA_MIHOMO_ARCHIVE" "$work/ca.pem" "$work/key.pem" "$work/proxy-ready" > "$work/proxy.log" 2>&1 &
 proxy=$!
 python3 - "$work/proxy-ready" "$proxy" <<'PY'
import pathlib,sys,time
ready=pathlib.Path(sys.argv[1]);proc=pathlib.Path("/proc")/sys.argv[2];deadline=time.monotonic()+5
while time.monotonic()<deadline:
 if ready.exists():break
 try:
  if proc.joinpath("stat").read_text().rsplit(") ",1)[1].split()[0] in ("Z","X","x"):raise SystemExit("exact release peer exited before listen")
 except FileNotFoundError:raise SystemExit("exact release peer exited before listen")
 time.sleep(.02)
else:raise SystemExit("exact release peer did not listen")
PY
 export HTTPS_PROXY=http://127.0.0.1:29499 HTTP_PROXY=http://127.0.0.1:29499 NO_PROXY=127.0.0.1,localhost SSL_CERT_FILE="$work/ca.pem"
 setsid /opt/bin/razvilka -listen 127.0.0.1:28891 > "$work/main.log" 2>&1 &
 panel=$!
 python3 - "$work" <<'PY'
import json,os,pathlib,sys,time,urllib.request,urllib.error
work=pathlib.Path(sys.argv[1]);deadline=time.monotonic()+45;base="http://127.0.0.1:28891"
def request(method,path):
 token=pathlib.Path("/opt/etc/razvilka/admin.token").read_text().strip()
 q=urllib.request.Request(base+path,data=b"{}" if method=="POST" else None,method=method,headers={"Authorization":"Bearer "+token,"Origin":base,"Content-Type":"application/json"})
 try:
  with urllib.request.urlopen(q,timeout=90) as r:return r.status,r.read(1024*1024)
 except urllib.error.HTTPError as e:return e.code,e.read(1024*1024)
while time.monotonic()<deadline:
 try:
  status,body=request("GET","/api/v1/panel/availability")
  if status==200:break
 except (OSError,ValueError):pass
 time.sleep(.1)
else:raise SystemExit("actual ordinary Main did not serve authenticated HTTP")
status,body=request("GET","/api/v1/components/mihomo/plan?action=update&refresh=true")
plan=json.loads(body)
assert status==200 and plan["ready"] is True and plan["installed_version"]=="1.19.32" and plan["available_version"]=="1.19.33",(status,body)
status,body=request("POST","/api/v1/components/mihomo/update")
if status!=200:
 print('Actual full-factory update refusal HTTP',status,'bounded body:',body[:4096].decode('utf-8','replace'),flush=True)
assert int(work.joinpath("proxy-transfer-complete").read_text())==pathlib.Path(os.environ["RAZVILKA_MIHOMO_ARCHIVE"]).stat().st_size,"default client did not fetch the full exact release asset"
if os.environ.get('RAZVILKA_MIHOMO_MAIN_NATIVE_BINDING')=='1':
 import hashlib
 assert status==200,(status,body[:4096])
 result=json.loads(body);assert result['ok'] is True and result['installed_idle_accepted'] is True,(status,body)
 data=pathlib.Path('/opt/bin/mihomo').read_bytes();digest=hashlib.sha256(data).hexdigest()
 assert len(data)==62017662 and digest=='09c2cb429cf45fb56884ceb91a0e5b17cc8b2c866c07811bcf75dfb59fef7662'
 receipt=json.loads(pathlib.Path('/opt/bin/.mihomo.razvilka.json').read_bytes());assert receipt=={'version':'1.19.33','sha256':digest},receipt
 life=json.loads(pathlib.Path('/opt/razvilka/state/components/receipts/mihomo.json').read_bytes());assert life['before_version']=='1.19.32' and life['after_version']=='1.19.33',life
 status,body=request('GET','/api/v1/extension-lab/mihomo/probe');view=json.loads(body);assert status==200 and view['lifecycle']['operations']['package_update']['registration']=='registered' and view['lifecycle']['operations']['package_update'].get('available') is None
 assert view['lifecycle']['operations']['live_apply']['registration']=='absent'
 assert 'Runtime ownership observation unavailable' not in work.joinpath('main.log').read_text()
 print('PASS actual Main complete factory registry, original held ELF tools/provider/full inventories, verified HTTPS default-client asset and exact1.19.32→1.19.33 package replacement. Platform classification is tagged/modelled; no router, service or live-apply claim.')
else:
 assert status!=200 and b"fresh owned runtime inactivity proof is unavailable" in body,(status,body)
 for before,path in [("binary-before","/opt/bin/mihomo"),("receipt-before","/opt/bin/.mihomo.razvilka.json"),("lifecycle-before","/opt/razvilka/state/components/receipts/mihomo.json")]:assert work.joinpath(before).read_bytes()==pathlib.Path(path).read_bytes(),path
 assert "manager-platform" in work.joinpath("main.log").read_text()
 print("PASS actual ordinary Main auth/plan/update transport and unchanged original pair: unsupported platform source correctly refuses global inactivity. This is a negative prerequisite test; no ordinary-Main replacement success, runtime, service or router-readiness claim.")
PY
