#!/usr/bin/env bash
set -euo pipefail
umask 077
export GIT_OPTIONAL_LOCKS=0 GIT_NO_LAZY_FETCH=1
test "$(id -u)" = 0 || { echo 'root isolated CI fixture required' >&2; exit 2; }
test "$#" = 1 || exit 2
case "$1" in production|race) mode=$1 ;; *) exit 2 ;; esac
: "${RAZVILKA_NFQ_RUNTIME_READ_OUTPUT:?new absolute output outside source tree required}"
for tool in git python3 timeout go sha256sum tar setsid sleep; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
candidate=$(git --no-lazy-fetch -c safe.directory="$repo" -C "$repo" rev-parse HEAD)
case "$candidate" in *[!0-9a-f]*) exit 2 ;; esac
test "${#candidate}" = 40
git -c safe.directory="$repo" -C "$repo" diff --quiet
git -c safe.directory="$repo" -C "$repo" diff --cached --quiet
export NFQ_READ_OUTPUT=$RAZVILKA_NFQ_RUNTIME_READ_OUTPUT NFQ_READ_MODE=$mode NFQ_READ_SHA=$candidate NFQ_READ_REPO=$repo
python3 - <<'PY'
import os,pathlib
p=pathlib.Path(os.environ['NFQ_READ_OUTPUT']); repo=pathlib.Path(os.environ['NFQ_READ_REPO'])
if not p.is_absolute() or p!=p.resolve() or not p.parent.is_dir() or p.exists() or p.is_symlink() or p==repo or p in repo.parents or repo in p.parents:
    raise SystemExit('new canonical disjoint output required')
p.mkdir(mode=0o700)
PY
output=$NFQ_READ_OUTPUT
work=$(mktemp -d /tmp/razvilka-nfq-read.XXXXXX)
work_safe=1
cleanup() {
  if test "$work_safe" != 1; then
    printf '%s\n' "$work" > "$output/retained-source-workspace.txt"
    return
  fi
  case "$work" in /tmp/razvilka-nfq-read.??????) rm -rf -- "$work" ;; *) return 1 ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
for side in baseline candidate; do
  mkdir -m 700 "$work/$side"
  git --no-lazy-fetch -c safe.directory="$repo" -C "$repo" archive "$candidate" | tar -x -C "$work/$side"
done
export NFQ_READ_WORK=$work
# Only the reviewed wrapper changes; the actor and all budgets stay identical.
cat > "$output/prepare-source.py" <<'PY'
import difflib,hashlib,json,os,pathlib,stat
REL='internal/strategylab/selected_candidate_runtime_observation.go'
PIN='b7e102c647bbf7bd664f4353e92ab6ad111d03209029382d9b4b30ef7f291c45'
def digest(data): return hashlib.sha256(data).hexdigest()
def inventory(root):
    result={}; total=0
    for p in sorted(root.rglob('*')):
        s=p.lstat()
        if stat.S_ISDIR(s.st_mode): continue
        if not stat.S_ISREG(s.st_mode) or s.st_size>128<<20 or len(result)>=20000: raise ValueError('source member refused')
        data=p.read_bytes(); total+=len(data)
        if len(data)!=s.st_size or total>1<<30: raise ValueError('source bound')
        result[p.relative_to(root).as_posix()]={'bytes':len(data),'mode':stat.S_IMODE(s.st_mode),'sha256':digest(data)}
    return result
def prepare(candidate,baseline,out):
    roots=[candidate,baseline,out]
    if any(not p.is_absolute() or p!=p.resolve() or not p.is_dir() for p in roots): raise ValueError('canonical existing roots required')
    if any(a==b or a in b.parents or b in a.parents for i,a in enumerate(roots) for b in roots[i+1:]): raise ValueError('overlapping roots')
    before=inventory(candidate)
    if before!=inventory(baseline): raise ValueError('initial tree drift')
    actor=(candidate/'internal/app/strategy_managed_probe_native_linux_test.go').read_bytes()
    if actor.count(b'probeCtx, probeCancel := context.WithTimeout(original, 14*time.Second)')!=1:
        raise ValueError('original consumer budget drift')
    original=(candidate/REL).read_bytes()
    if digest(original)!=PIN: raise ValueError('reviewed wrapper source drift')
    start=original.index(b'func (r *SelectedCandidateReview) materialReadCurrentLocked(')
    end=original.index(b'func (r *SelectedCandidateReview) materialRuntimeCompare(',start)
    replacement=b'func (r *SelectedCandidateReview) materialReadCurrentLocked(ctx context.Context) error {\n\treturn r.materialCurrentWithRuntimeReadLocked(ctx, nil)\n}\n\n'
    altered=original[:start]+replacement+original[end:]
    if altered.count(b'\t"errors"\n')!=1: raise ValueError('reviewed import drift')
    altered=altered.replace(b'\t"errors"\n',b'',1)
    (baseline/REL).write_bytes(altered)
    after=inventory(baseline)
    changed=[name for name in sorted(before.keys()|after.keys()) if before.get(name)!=after.get(name)]
    if changed!=[REL] or before[REL]['mode']!=after[REL]['mode'] or inventory(candidate)!=before: raise ValueError('unexpected source mutation')
    patch=''.join(difflib.unified_diff(original.decode().splitlines(True),altered.decode().splitlines(True),fromfile='candidate/'+REL,tofile='baseline/'+REL))
    (out/'baseline.patch').write_text(patch,encoding='utf-8',newline='\n')
    (out/'candidate-wrapper.go.txt').write_bytes(original); (out/'baseline-wrapper.go.txt').write_bytes(altered)
    for name,data in [('candidate-source.json',before),('baseline-source.json',after)]:
        (out/name).write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')
    report={'candidate_commit':os.environ['NFQ_READ_SHA'],'baseline':'synthetic-same-current-source-full-runtime-Check','changed_files':changed,'candidate_wrapper_sha256':PIN,'baseline_wrapper_sha256':digest(altered),'patch_sha256':digest(patch.encode()),'helper_sha256':digest(pathlib.Path(__file__).read_bytes()),'original_budget_seconds':14,'order':['baseline','candidate','candidate','baseline'],'limits':['Baseline is not an older whole repository commit.','Only the private wrapper and its now-unused import differ; other source bytes and modes are exact.','Native platform classification remains modeled; real service/packet/cleanup assertions unchanged.']}
    (out/'source-comparison.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':
    work=pathlib.Path(os.environ['NFQ_READ_WORK']);prepare(work/'candidate',work/'baseline',pathlib.Path(os.environ['NFQ_READ_OUTPUT']))
PY
python3 "$output/prepare-source.py"
python3 - <<'PY'
import hashlib,json,os,pathlib,platform,subprocess
p=pathlib.Path(os.environ['NFQ_READ_OUTPUT']);repo=pathlib.Path(os.environ['NFQ_READ_REPO'])
paths=['/usr/sbin/xtables-legacy-multi','/usr/bin/ip']
cpu=next((x.split(':',1)[1].strip() for x in pathlib.Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),'unknown')
cg=pathlib.Path('/sys/fs/cgroup/cpu.max')
d={'candidate_commit':os.environ['NFQ_READ_SHA'],'mode':os.environ['NFQ_READ_MODE'],'cpu_model':cpu,'kernel':platform.release(),'go':subprocess.check_output(['go','version'],text=True).strip(),'cgroup_cpu_max':cg.read_text().strip() if cg.exists() else 'unavailable','tools_sha256':{x:hashlib.sha256(pathlib.Path(x).read_bytes()).hexdigest() for x in paths},'harness_sha256':{x:hashlib.sha256((repo/x).read_bytes()).hexdigest() for x in ['scripts/compare-nfq-runtime-read.sh','scripts/test-managed-probe-native.sh','scripts/fetch-native-fixture.sh']},'native_GOMAXPROCS':2,'limits':['Same host per mode, fresh namespace/process per sample; host page cache is warm.','Production and race jobs run on distinct hosts; do not pool latency.','Compilation/setup and supervisor wall time are not Execute latency.','Baseline assertion failures remain censored failures, never PASS or successful timings.','Only candidate complete original service and cleanup PASS qualifies.','Two samples per arm are a bounded diagnostic, not statistical significance or router acceptance.']}
(p/'provenance.json').write_text(json.dumps(d,indent=2)+'\n')
PY
# Closed original actor; inherited experiment knobs cannot alter either arm.
while IFS= read -r name; do unset "$name"; done < <(compgen -v | grep '^RAZVILKA_' || true)
unset GORACE
export RAZVILKA_MANAGED_PROBE_BUILD_MODE=$mode RAZVILKA_MANAGED_PROBE_CASE_SET=original-consumer
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
  work_safe=0
  set +e
  python3 "$work/supervise.py" "$work/control-$control.sh" "$output/control-$control"
  control_status=$?
  set -e
  if python3 - "$output/control-$control/supervisor.json" <<'PY'
import json,sys
sys.exit(0 if json.load(open(sys.argv[1])).get('descendants_absent') is True else 1)
PY
  then work_safe=1; fi
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
  dir="$output/$(printf '%02d-%s' "$index" "$side")"
  mkdir -m 700 "$dir"
  if test "$unsafe" != 0; then
    printf 'not_run_after_unjoined_or_incomplete_sample\n' > "$dir/not-run.txt"
    continue
  fi
  work_safe=0
  set +e
  python3 "$work/supervise.py" "$work/$side/scripts/test-managed-probe-native.sh" "$dir"
  status=$?
  set -e
  printf '%s\n' "$status" > "$dir/supervisor-status.txt"
  if python3 - "$dir/supervisor.json" <<'PY'
import json,sys
sys.exit(0 if json.load(open(sys.argv[1])).get('descendants_absent') is True else 1)
PY
  then work_safe=1; fi
  if test "$work_safe" != 1; then printf '%s\n' "$work" > "$output/retained-source-workspace.txt"; fi
  if test "$work_safe" != 1 || test "$status" -gt 1 || ! grep -Fq '=== RUN   TestManagedStrategyProbeNativeConsumer' "$dir/native.log" || grep -Fq -- '--- SKIP:' "$dir/native.log"; then
    unsafe=1
    printf 'incomplete_or_unjoined_sample\n' > "$dir/incomplete.txt"
  fi
done
python3 - <<'PY'
import hashlib,importlib.util,json,os,pathlib,re,sys
out=pathlib.Path(os.environ['NFQ_READ_OUTPUT']); work=pathlib.Path(os.environ['NFQ_READ_WORK'])
spec=importlib.util.spec_from_file_location('prepare',out/'prepare-source.py'); prep=importlib.util.module_from_spec(spec)
sys.dont_write_bytecode=True;spec.loader.exec_module(prep)
source_current=all(prep.inventory(work/side)==json.loads((out/f'{side}-source.json').read_text()) for side in ['baseline','candidate'])
rows=[]; failed=not source_current
expected='TestManagedStrategyProbeNativeConsumer'
service='actual isolated consumer: managed native validation + held source socket + queue200 + wrong-source negative + exact counters + TLS/catalogue predicates + soleWait/ACK + COMMON cleanup; platform/WAN classification modeled; no router/LAN acceptance'
def duration(text):
    parts=re.findall(r'(\d+(?:\.\d+)?)(ns|µs|us|ms|s|m|h)',text)
    if ''.join(a+b for a,b in parts)!=text: raise ValueError('unknown duration')
    scales={'ns':1,'µs':1000,'us':1000,'ms':1000000,'s':1000000000,'m':60000000000,'h':3600000000000}
    return round(sum(float(a)*scales[b] for a,b in parts))
for index,side in enumerate(['baseline','candidate','candidate','baseline'],1):
    p=out/f'{index:02d}-{side}';row={'sample':index,'side':side};rows.append(row)
    if (p/'not-run.txt').exists():row['status']='not_run';failed=True;continue
    log=(p/'native.log').read_text();rc=int((p/'exit-status.txt').read_text());supervisor=json.loads((p/'supervisor.json').read_text())
    native_pass=rc==0 and re.search(r'^--- PASS: '+expected+r' \(',log,re.M) is not None and service in log and '--- SKIP:' not in log
    native_failure=rc==1 and re.search(r'^--- FAIL: '+expected+r' \(',log,re.M) is not None and '--- SKIP:' not in log
    counts=re.findall(r'native measured runtime read frames \[begun completed error\] \[(\d+) (\d+) (\d+)\]',log)
    valid=len(counts)==1
    values=list(map(int,counts[0])) if valid else None
    valid=valid and (values==[0,0,0] if side=='baseline' else values[0]==values[1] and values[0]>0 and values[2]==0)
    boundary=supervisor.get('no_overlap_boundary') is True and not (p/'incomplete.txt').exists() and int((p/'log-status.txt').read_text())==0
    admissible=boundary and valid and (native_pass if side=='candidate' else native_pass or native_failure)
    row.update(status='pass' if native_pass else 'fail',native_exit=rc,native_complete_service_cleanup_pass=native_pass,frames_begun_completed_error=values,variant_path_valid=valid,descendant_boundary=supervisor,sample_evidence_admissible=admissible)
    timings=re.findall(r'native measured Execute (\S+) actual inventory ToolCheck calls (\d+) ToolCheck wall (\S+)',log)
    if len(timings)==1:
        elapsed,calls,toolwall=timings[0];row['execute_elapsed_ns']=duration(elapsed);row['tool_check_calls']=int(calls);row['tool_check_inclusive_ns']=duration(toolwall)
    else:admissible=False;row['sample_evidence_admissible']=False
    row['elapsed_is_censored']=not native_pass
    row['native_outcomes']=[line.strip() for line in log.splitlines() if line.startswith(('--- PASS:','--- FAIL:','--- SKIP:'))]
    row['payload_measurements']=re.findall(r'native measured Execute member-read attempts/returned-bytes (\d+) (\d+)',log)
    if not admissible:failed=True
entries=list(out.rglob('*'))
if any(p.is_symlink() or not (p.is_dir() or p.is_file()) for p in entries):raise SystemExit('nonregular evidence')
files=[p for p in entries if p.is_file()]
if len(files)>80 or sum(p.stat().st_size for p in files)>24<<20:raise SystemExit('evidence bound')
report={'candidate_commit':os.environ['NFQ_READ_SHA'],'mode':os.environ['NFQ_READ_MODE'],'source_trees_unchanged_after_population':source_current,'source_comparison':json.loads((out/'source-comparison.json').read_text()),'samples':rows,'all_candidate_samples_pass':all(r.get('native_complete_service_cleanup_pass') and r.get('sample_evidence_admissible') for r in rows if r['side']=='candidate'),'all_samples_pass':all(r.get('native_complete_service_cleanup_pass') for r in rows),'comparison_valid':not failed,'baseline_failure_policy':'Preserved as censored FAIL; no success or latency-gain claim from failed samples.','evidence':{str(p.relative_to(out)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files}}
(out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['comparison_valid','all_candidate_samples_pass','all_samples_pass']}))
sys.exit(1 if failed else 0)
PY
