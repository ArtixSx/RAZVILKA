#!/usr/bin/env bash
set -euo pipefail
umask 077
export GIT_OPTIONAL_LOCKS=0
# Disposable CI only. Each sample uses the unchanged original harness, which
# creates a fresh process and private topology and joins its owned children.
test "$(id -u)" = 0 || { echo 'root isolated CI fixture required' >&2; exit 2; }
test "$#" = 1 || exit 2
case "$1" in
  selected) expected=TestDomainTCPOriginalNativeAcceptedFlows ;;
  canceled-ready) expected=TestDomainTCPOriginalNativeCanceledReadyRetirement ;;
  *) exit 2 ;;
esac
scenario=$1
: "${RAZVILKA_DOMAIN_IMAGE_OUTPUT:?new absolute comparison output directory required}"
: "${RAZVILKA_XRAY_NATIVE:?same installed pinned Xray required}"
case "$RAZVILKA_DOMAIN_IMAGE_OUTPUT" in /*) ;; *) exit 2 ;; esac
case "$RAZVILKA_XRAY_NATIVE" in /*) ;; *) exit 2 ;; esac
for tool in git python3 timeout go sha256sum tar setsid sleep; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
baseline=344912c11f285a4c2dc0ac0eadd8ab64e6110160
candidate=$(git -c safe.directory="$repo" -C "$repo" rev-parse HEAD)
case "$candidate" in *[!0-9a-f]*) exit 2 ;; esac
test "${#candidate}" = 40 || exit 2
git -c safe.directory="$repo" -C "$repo" diff --quiet
git -c safe.directory="$repo" -C "$repo" diff --cached --quiet
git -c safe.directory="$repo" -C "$repo" cat-file -e "$baseline^{commit}"
mkdir -m 700 "$RAZVILKA_DOMAIN_IMAGE_OUTPUT"
output=$(CDPATH= cd -- "$RAZVILKA_DOMAIN_IMAGE_OUTPUT" && pwd -P)
work=$(mktemp -d /tmp/razvilka-domain-image.XXXXXX)
cleanup() {
  case "$work" in /tmp/razvilka-domain-image.*) rm -rf -- "$work" ;; *) return 1 ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
# Reject fixture/budget/dependency drift rather than silently compare different
# acceptance rules. Neither archived source tree is patched.
for path in scripts/test-domain-original-native.sh scripts/fetch-native-fixture.sh \
  internal/app/domain_tcp_original_native_linux_test.go \
  internal/app/domain_tcp_original_native_peers_linux_test.go go.mod go.sum; do
  old=$(git -c safe.directory="$repo" -C "$repo" rev-parse "$baseline:$path")
  new=$(git -c safe.directory="$repo" -C "$repo" rev-parse "$candidate:$path")
  test "$old" = "$new" || { printf 'comparison fixture drift: %s\n' "$path" >&2; exit 2; }
  printf '%s %s\n' "$old" "$path" >> "$output/unchanged-fixtures.txt"
done
for side in baseline candidate; do
  sha=$baseline
  if test "$side" = candidate; then sha=$candidate; fi
  mkdir -m 700 "$work/$side"
  git -c safe.directory="$repo" -C "$repo" archive "$sha" | tar -x -C "$work/$side"
done
export DOMAIN_IMAGE_BASELINE=$baseline DOMAIN_IMAGE_CANDIDATE=$candidate
export DOMAIN_IMAGE_SCENARIO=$scenario DOMAIN_IMAGE_EXPECTED=$expected DOMAIN_IMAGE_OUTPUT=$output
python3 - <<'PY'
import hashlib,json,os,pathlib,platform,subprocess
out=pathlib.Path(os.environ['DOMAIN_IMAGE_OUTPUT'])
cpu=next((x.split(':',1)[1].strip() for x in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')), 'unknown')
files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in map(pathlib.Path,[os.environ['RAZVILKA_XRAY_NATIVE'],'/usr/sbin/xtables-legacy-multi','/usr/bin/ip'])}
meta={'baseline':os.environ['DOMAIN_IMAGE_BASELINE'],'candidate':os.environ['DOMAIN_IMAGE_CANDIDATE'],'scenario':os.environ['DOMAIN_IMAGE_SCENARIO'],'order':['baseline','candidate','candidate','baseline'],'cpu_model':cpu,'kernel':platform.release(),'go':subprocess.check_output(['go','version'],text=True).strip(),'assets_sha256':files,'native_GOMAXPROCS':2,'limits':['Unchanged publication12s/client4s; no diagnostic deadline override','Fresh process/namespace each sample; warm host page cache, not cold IO','Original profile span label is Run-through-join; failed cleanup error is not retained, so counter/profile markers do not prove joined cleanup','Retained image bytes are not process RSS or router memory proof','Two samples per side do not establish statistical significance; compare identical completed stages only']}
cg=pathlib.Path('/sys/fs/cgroup/cpu.max')
meta['cgroup_cpu_max']=cg.read_text().strip() if cg.exists() else 'unavailable'
(out/'provenance.json').write_text(json.dumps(meta,indent=2)+'\n')
PY
# Remove every inherited fixture selector. Only the two explicit unchanged
# scenario configurations below are allowed; a longer diagnostic clock is not.
while IFS= read -r name; do unset "$name"; done < <(compgen -v | grep '^RAZVILKA_DOMAIN_' || true)
if test "$scenario" = canceled-ready; then
  export RAZVILKA_DOMAIN_DNS_ONLY_NATIVE=1 RAZVILKA_DOMAIN_DNS_DETACH=1
  export RAZVILKA_DOMAIN_DNS_COEXISTENCE=1 RAZVILKA_DOMAIN_CANCELED_CHILD=1 RAZVILKA_DOMAIN_CANCELED_READY=1
fi
cat > "$work/supervise.py" <<'PY'
# Sole waiter for one original harness subtree; no namespace/profile changes.
# Linux man-pages6.19: https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
# https://man7.org/linux/man-pages/man2/waitpid.2.html
import ctypes,errno,hashlib,json,os,pathlib,selectors,signal,subprocess,sys,time
out=pathlib.Path(sys.argv[2]); libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.restype=ctypes.c_int
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
signal.signal(signal.SIGCHLD,signal.SIG_DFL)
state=ctypes.c_int()
if libc.prctl(36,1,0,0,0)!=0 or libc.prctl(37,ctypes.addressof(state),0,0,0)!=0 or state.value!=1:
    (out/'supervisor.json').write_text(json.dumps({'subreaper':False,'boundary':'refused_before_start'})+'\n')
    (out/'exit-status.txt').write_text('125\n');(out/'log-status.txt').write_text('1\n');(out/'native.log').write_text('subreaper setup refused before native start\n');sys.exit(125)
proc=None; sel=selectors.DefaultSelector(); total=0; kept=0; digest=hashlib.sha256(); log_error=False; forced=False; reaped=0; initial=None; absent=False
log=(out/'native.log').open('xb')
def drain(wait):
    global total,kept,log_error
    if not sel.get_map():time.sleep(wait);return
    for key,_ in sel.select(wait):
        try:data=os.read(key.fd,65536)
        except BlockingIOError:continue
        if not data:sel.unregister(key.fd);continue
        total+=len(data);digest.update(data);part=data[:max(0,(2<<20)-kept)];kept+=len(part)
        try:log.write(part);log.flush();sys.stdout.buffer.write(part);sys.stdout.buffer.flush()
        except (OSError,BrokenPipeError):log_error=True

def reap():
    global reaped
    while True:
        try:pid,_=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError:return True
        if pid==0:return False
        reaped+=1

def kill_owned_children():
    # No concurrent waiter, SIGCHLD is default, and nothing else forks here.
    # An actual unreaped child PID cannot be reused before our own waitpid.
    with open(f'/proc/self/task/{os.getpid()}/children','rb') as f:raw=f.read(65537)
    if len(raw)>65536:raise RuntimeError('child inventory bound')
    for value in raw.split():
        pid=int(value)
        if pid<=0 or pid==os.getpid():raise RuntimeError('child inventory identity')
        os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) # prove still our child, never reap here
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass # an unreaped exited child, never another owner

def interrupted(signum,frame):raise KeyboardInterrupt()
signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
try:
    proc=subprocess.Popen(['timeout','--signal=TERM','--kill-after=20s','480s','sh',sys.argv[1]],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True)
    os.set_blocking(proc.stdout.fileno(),False);sel.register(proc.stdout,selectors.EVENT_READ)
    deadline=time.monotonic()+510
    while initial is None:
        drain(0.05);initial=proc.poll() # sole initial-child waiter
        if time.monotonic()>deadline and initial is None:raise TimeoutError()
    # Popen has reaped only its own initial child. No further Popen polling or
    # asynchronous waiter runs during the adopted-child ownership checks below.
    deadline=time.monotonic()+2
    while not (absent:=reap()) and time.monotonic()<deadline:drain(0.05)
    if not absent:
        forced=True;deadline=time.monotonic()+5
        while not absent and time.monotonic()<deadline:
            kill_owned_children();drain(0.05);absent=reap()
except BaseException:
    forced=True
    if proc is not None and initial is None:
        try:proc.kill();initial=proc.wait(timeout=5)
        except BaseException:pass
    try:
        deadline=time.monotonic()+5
        while not (absent:=reap()) and time.monotonic()<deadline:kill_owned_children();drain(0.05)
    except BaseException:absent=False
finally:
    # Bounded drain: an unjoined descendant must not keep the outer logger open.
    deadline=time.monotonic()+1
    while sel.get_map() and time.monotonic()<deadline:
        try:drain(0.02)
        except BaseException:log_error=True;break
    eof_complete=not bool(sel.get_map())
    if not eof_complete:log_error=True
    sel.close()
    if proc is not None and proc.stdout is not None:proc.stdout.close()
    log.close()
rc=125 if initial is None else initial if initial>=0 else 128-initial
(out/'exit-status.txt').write_text(str(rc)+'\n')
(out/'log-status.txt').write_text(str(int(log_error or total>2<<20))+'\n')
(out/'log-capture.json').write_text(json.dumps({'total_bytes':total,'retained_bytes':kept,'full_stream_sha256':digest.hexdigest() if eof_complete else None,'observed_stream_sha256':digest.hexdigest(),'eof_complete':eof_complete,'truncated':total>2<<20,'io_error':log_error})+'\n')
boundary=absent and not forced
(out/'supervisor.json').write_text(json.dumps({'subreaper':True,'initial_exit_status':rc,'adopted_children_reaped':reaped,'descendants_absent':absent,'forced_cleanup':forced,'no_overlap_boundary':boundary,'original_cleanup_success':'not inferred from descendant absence'})+'\n')
sys.exit(rc if boundary and not log_error and total<=2<<20 else 125)
PY
# Validate this actual host's adoption/reaping boundary with harmless processes,
# before any native sample. An orphan in a separate session must be contained;
# this forced-cleanup control is deliberately NOT a successful native sample.
printf 'exit 0\n' > "$work/control-clean.sh"
printf 'exit 1\n' > "$work/control-failure.sh"
printf '(trap "" TERM; exec setsid sleep 30) &\nexit 0\n' > "$work/control-orphan.sh"
for control in clean failure orphan; do
  mkdir -m 700 "$output/control-$control"
  set +e
  python3 "$work/supervise.py" "$work/control-$control.sh" "$output/control-$control"
  control_status=$?
  set -e
  expected_status=0
  if test "$control" = failure; then expected_status=1; fi
  if test "$control" = orphan; then expected_status=125; fi
  test "$control_status" = "$expected_status" || exit 2
done
python3 - "$output" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);clean=json.loads((root/'control-clean/supervisor.json').read_text());failure=json.loads((root/'control-failure/supervisor.json').read_text());orphan=json.loads((root/'control-orphan/supervisor.json').read_text())
if not (clean.get('subreaper') and clean.get('no_overlap_boundary') and clean.get('initial_exit_status')==0):raise SystemExit('clean subreaper control refused')
if not (failure.get('subreaper') and failure.get('no_overlap_boundary') and failure.get('initial_exit_status')==1):raise SystemExit('failed child status hidden')
if not (orphan.get('subreaper') and orphan.get('forced_cleanup') and orphan.get('descendants_absent') and orphan.get('initial_exit_status')==0 and not orphan.get('no_overlap_boundary') and orphan.get('adopted_children_reaped',0)>0):raise SystemExit('orphan containment control refused')
print('ACTUAL_SUBREAPER_CONTROLS_COMPLETE: exit0/exit1 preserved, separate-session orphan killed/reaped; forced cleanup cannot mint native success')
PY
index=0
unsafe=0
for side in baseline candidate candidate baseline; do
  index=$((index+1))
  sample=$(printf '%02d-%s' "$index" "$side")
  dir="$output/$sample"
  mkdir -m 700 "$dir"
  if test "$unsafe" != 0; then
    printf 'not_run_after_unjoined_or_incomplete_sample\n' > "$dir/not-run.txt"
    continue
  fi
  # Original harness writes only status and bounded CPU diagnostics here;
  # its binaries, private keys/configs and workspace are removed by its trap.
  export RAZVILKA_DOMAIN_PROFILE_OUTPUT=$dir
  set +e
  python3 "$work/supervise.py" "$work/$side/scripts/test-domain-original-native.sh" "$dir"
  supervisor_status=$?
  set -e
  printf '%s\n' "$supervisor_status" > "$dir/supervisor-status.txt"
  # An ordinary failed assertion still runs original cleanup and is retained.
  # A timeout/panic/missing joined evidence must not overlap another sample.
  if test "$supervisor_status" -gt 1 || \
     ! test -s "$dir/status.txt" || \
     ! grep -Fq 'actual Run through join observation counts:' "$dir/native.log" || \
     grep -Eq 'original runtime did not join|original Run cleanup did not join|capture listener remains|fresh cleanup original child join/row publication|child survived cleanup join|same actual terminal ACK retry|same original native terminal ACK retry|physical server did not join|owned namespace cleanup|private trust mount cleanup|child survived cleanup join|native child still exists' "$dir/native.log"; then
    unsafe=1
    printf 'incomplete_or_unjoined_observation\n' > "$dir/incomplete.txt"
  fi
done
python3 - <<'PY'
import hashlib,json,os,pathlib,re,sys
out=pathlib.Path(os.environ['DOMAIN_IMAGE_OUTPUT']); expected=os.environ['DOMAIN_IMAGE_EXPECTED']
rows=[]; failed=False; wanted={'capture-prepare','standby-prepare','process-current','whole-executable-hash','executable-image-capture','executable-image-compare','executable-image-storage','kernel-observe','mapping-compare'}
for index,side in enumerate(['baseline','candidate','candidate','baseline'],1):
    p=out/f'{index:02d}-{side}'; row={'sample':index,'side':side}; rows.append(row)
    if (p/'not-run.txt').exists():
        row['status']='not_run_after_unjoined_or_incomplete_sample';failed=True;continue
    rc=int((p/'exit-status.txt').read_text()); row['exit_status']=rc
    log=(p/'native.log').read_text(errors='strict'); status=(p/'status.txt').read_text() if (p/'status.txt').exists() else ''
    valid=all(x in status.splitlines() for x in ['publication_budget_seconds=12','diagnostic_only=false',f'native_case={expected}',f'child_exit_status={rc}'])
    native_pass=rc==0 and f'--- PASS: {expected} (' in log and '--- SKIP:' not in log
    complete=not (p/'incomplete.txt').exists(); log_ok=int((p/'log-status.txt').read_text())==0
    boundary=json.loads((p/'supervisor.json').read_text()) if (p/'supervisor.json').exists() else {}
    passed=native_pass and valid and complete and log_ok and boundary.get('no_overlap_boundary',False)
    row.update(status='pass' if passed else 'fail',native_test_pass=native_pass,original_status_valid=valid)
    row['diagnostic_evidence_complete']=complete
    row['descendant_boundary']=boundary
    if not boundary.get('no_overlap_boundary',False):failed=True
    if not row['diagnostic_evidence_complete']:failed=True
    if not valid or int((p/'log-status.txt').read_text())!=0 or rc>1 or side=='candidate' and not passed:failed=True
    for line in log.splitlines():
        stage='first_answer' if 'actual first DNS answer completed-counter snapshot' in line else 'before_stop' if 'actual before stopRun completed-counter snapshot' in line else 'joined' if 'actual Run through join observation counts:' in line else None
        if stage:
            row[stage]={name:{'calls':int(calls),'bytes':int(size),'elapsed':elapsed} for name,calls,size,elapsed in re.findall(r'([\w/-]+):\{Calls:(\d+) Bytes:(\d+) Elapsed:([^}]+)\}',line) if name in wanted}
            keys=['whole-executable-hash','executable-image-capture','executable-image-compare']
            row[stage]['observed_executable_io']={field:sum(row[stage].get(key,{}).get(field,0) for key in keys) for field in ['calls','bytes']}
    row['first_dns_answer_observed']='first_answer' in row
    row['selected_tls_timeout']='Client.Timeout exceeded while awaiting headers' in log
    row['gen1_publication_failure']='actual DNS publication did not become available' in log
    row['native_outcomes']=[line.strip() for line in log.splitlines() if line.startswith(('--- PASS:','--- FAIL:'))]
# Artifacts are bounded public fixture evidence only. Never copy native binaries
# or the private namespace workspaces into this output directory.
entries=list(out.rglob('*'))
if any(p.is_symlink() or not (p.is_dir() or p.is_file()) for p in entries):raise SystemExit('nonregular comparison evidence refused')
files=[p for p in entries if p.is_file()]
if len(files)>80 or sum(p.stat().st_size for p in files)>16<<20:raise SystemExit('bounded comparison evidence limit exceeded')
report={'baseline':os.environ['DOMAIN_IMAGE_BASELINE'],'candidate':os.environ['DOMAIN_IMAGE_CANDIDATE'],'scenario':os.environ['DOMAIN_IMAGE_SCENARIO'],'samples':rows,'all_candidate_samples_pass':all(r.get('status')=='pass' for r in rows if r['side']=='candidate'),'evidence':{str(p.relative_to(out)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files}}
(out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'scenario':report['scenario'],'samples':[{k:r[k] for k in ['sample','side','status']} for r in rows],'all_candidate_samples_pass':report['all_candidate_samples_pass']}))
sys.exit(1 if failed else 0)
PY
