#!/usr/bin/env bash
set -euo pipefail
umask 077
export GIT_OPTIONAL_LOCKS=0 GIT_NO_LAZY_FETCH=1
test "$(id -u)" = 0 || exit 2
: "${RAZVILKA_DOMAIN_BUILD_OUTPUT:?new absolute output directory required}"
: "${RAZVILKA_XRAY_NATIVE:?same pinned Xray required}"
case "$RAZVILKA_DOMAIN_BUILD_OUTPUT" in /*) ;; *) exit 2 ;; esac
for tool in git python3 timeout go tar setsid sleep; do command -v "$tool" >/dev/null; done
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
revision=$(git -c safe.directory="$repo" -C "$repo" rev-parse HEAD)
git -c safe.directory="$repo" -C "$repo" diff --quiet
git -c safe.directory="$repo" -C "$repo" diff --cached --quiet
python3 - "$RAZVILKA_DOMAIN_BUILD_OUTPUT" "$repo" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); repo=pathlib.Path(sys.argv[2]).resolve()
if not p.is_absolute() or p!=p.resolve() or not p.parent.is_dir() or p.exists() or p.is_symlink() or p==repo or p in repo.parents or repo in p.parents:
 raise SystemExit('new canonical disjoint output required')
p.mkdir(mode=0o700)
PY
output=$(CDPATH= cd -- "$RAZVILKA_DOMAIN_BUILD_OUTPUT" && pwd -P)
work=$(mktemp -d /tmp/razvilka-domain-build.XXXXXX)
work_safe=1
cleanup() {
 if test "$work_safe" != 1; then
  printf '%s\n' "$work" > "$output/retained-source-workspace.txt"
  return
 fi
 case "$work" in /tmp/razvilka-domain-build.??????) rm -rf -- "$work" ;; *) return 1 ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
mkdir -m 700 "$work/source"
git --no-lazy-fetch -c safe.directory="$repo" -C "$repo" archive "$revision" | tar -x -C "$work/source"
# One SAME source tree/path, no source mutation between either build variant.
cat > "$work/source-proof.py" <<'PY'
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); mode=sys.argv[3]
rows={}
for p in sorted(root.rglob('*')):
 s=p.lstat(); rel=str(p.relative_to(root)); row={'mode':stat.S_IMODE(s.st_mode)}
 if p.is_symlink():row['link']=str(p.readlink())
 elif p.is_file():row['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 elif p.is_dir():row['directory']=True
 else:raise SystemExit('nonregular source')
 rows[rel]=row
if mode=='create':out.write_text(json.dumps(rows,sort_keys=True)+'\n')
elif mode!='check' or json.loads(out.read_text())!=rows:raise SystemExit('source changed during build comparison')
PY
python3 "$work/source-proof.py" "$work/source" "$output/source-manifest.json" create
printf '%s\n' "$revision" > "$output/source-revision.txt"
# No inherited scenario, deadline, alternate image, or profile selector.
while IFS= read -r name; do unset "$name"; done < <(compgen -v | grep '^RAZVILKA_DOMAIN_' || true)
export RAZVILKA_DOMAIN_PROFILE_ENABLED=1
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
  test "$work_safe" = 1 || exit 2
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
for mode in debug production-strip production-strip debug; do
 index=$((index+1)); dir="$output/$(printf '%02d' "$index")-$mode"
 mkdir -m 700 "$dir"
 if test "$unsafe" != 0; then printf 'not_run_after_unjoined_sample\n' > "$dir/not-run.txt"; continue; fi
 python3 "$work/source-proof.py" "$work/source" "$output/source-manifest.json" check
 export RAZVILKA_DOMAIN_BUILD_MODE="$mode" RAZVILKA_DOMAIN_PROFILE_OUTPUT="$dir"
 work_safe=0
 set +e
 python3 "$work/supervise.py" "$work/source/scripts/test-domain-original-native.sh" "$dir"
 status=$?
 set -e
 if python3 - "$dir/supervisor.json" <<'PY'
import json,sys
sys.exit(0 if json.load(open(sys.argv[1])).get('descendants_absent') is True else 1)
PY
 then work_safe=1; fi
 if test "$work_safe" != 1; then printf '%s\n' "$work" > "$output/retained-source-workspace.txt"; fi
 printf '%s\n' "$status" > "$dir/supervisor-status.txt"
 python3 "$work/source-proof.py" "$work/source" "$output/source-manifest.json" check
 if test "$work_safe" != 1 || test "$status" -gt 1 || ! test -s "$dir/status.txt" ||
    ! grep -Fq 'actual Run through join observation counts:' "$dir/native.log" ||
    grep -Eq 'original runtime did not join|original Run cleanup did not join|capture listener remains|fresh cleanup original child join/row publication|child survived cleanup join|same actual terminal ACK retry|same original native terminal ACK retry|physical server did not join|owned namespace cleanup|private trust mount cleanup|native child still exists' "$dir/native.log"; then
  unsafe=1; printf 'unjoined_or_incomplete\n' > "$dir/incomplete.txt"
 fi
done
python3 - "$output" <<'PY'
import hashlib,json,pathlib,re,sys
out=pathlib.Path(sys.argv[1]); rows=[]; expected='TestDomainTCPOriginalNativeAcceptedFlows'
for i,mode in enumerate(['debug','production-strip','production-strip','debug'],1):
 p=out/f'{i:02d}-{mode}'; row={'sample':i,'mode':mode,'pass':False}; rows.append(row)
 if (p/'not-run.txt').exists():row['not_run']='previous sample not joined';continue
 log=(p/'native.log').read_text(); status=(p/'status.txt').read_text().splitlines() if (p/'status.txt').exists() else []
 binary=json.loads((p/'binary.json').read_text()) if (p/'binary.json').exists() else {}
 supervisor=json.loads((p/'supervisor.json').read_text()); rc=int((p/'exit-status.txt').read_text())
 profile=(p/'original-run.cpu.pprof'); top=(p/'cpu-cumulative.txt')
 profile_symbols=profile.is_file() and profile.stat().st_size>0 and top.is_file() and 'github.com/ArtixSx/razvilka/internal/' in top.read_text()
 valid=binary.get('build_mode')==mode and 0<binary.get('bytes',0)<=64<<20 and bool(re.fullmatch('[a-f0-9]{64}',binary.get('sha256','')))
 flags=binary.get('go_build_info',''); valid=valid and (('-ldflags="-s -w"' in flags) if mode=='production-strip' else '-ldflags=' not in flags)
 valid=valid and all(v in status for v in ['publication_budget_seconds=12','diagnostic_only=false',f'child_exit_status={rc}',f'native_case={expected}'])
 row.update(exit_status=rc,binary=binary,profile_symbols=profile_symbols,status_valid=valid,supervisor=supervisor)
 row['pass']=rc==0 and valid and profile_symbols and supervisor.get('no_overlap_boundary') and not (p/'incomplete.txt').exists() and int((p/'log-status.txt').read_text())==0 and f'--- PASS: {expected} (' in log and '--- SKIP:' not in log
 row['counter_snapshots']=[x.strip() for x in log.splitlines() if 'completed-counter snapshot' in x or 'Run through join observation counts:' in x]
 row['native_outcomes']=[x for x in log.splitlines() if x.startswith(('--- PASS:','--- FAIL:'))]
identities={mode:{(r.get('binary',{}).get('sha256'),r.get('binary',{}).get('bytes')) for r in rows if r['mode']==mode} for mode in ['debug','production-strip']}
binary_pair_valid=all(len(v)==1 and next(iter(v))[0] is not None for v in identities.values())
if binary_pair_valid:
 binary_pair_valid=next(iter(identities['production-strip']))[1]<next(iter(identities['debug']))[1]
files=[p for p in out.rglob('*') if p.is_file()]
if any(p.is_symlink() for p in out.rglob('*')) or len(files)>80 or sum(p.stat().st_size for p in files)>16<<20:raise SystemExit('evidence bound')
report={'revision':(out/'source-revision.txt').read_text().strip(),'comparison':'same-source linker debug versus production-strip fidelity only','samples':rows,'binary_pair_valid':binary_pair_valid,'all_samples_pass':binary_pair_valid and all(r['pass'] for r in rows),'all_strip_samples_pass':all(r['pass'] for r in rows if r['mode']=='production-strip'),'limits':['No failure is censored; debug failure remains comparison failure.','Original12s publication and4s client unchanged.','Test ELF is not shipped cmd/razvilka; only -s -w fidelity is isolated.','Two samples per side do not establish statistical speedup; compare completed stages separately.','Fresh process/topology per sample; host pagecache warm.'],'raw':{str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
(out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'all_samples_pass':report['all_samples_pass'],'all_strip_samples_pass':report['all_strip_samples_pass']}))
sys.exit(0 if report['all_samples_pass'] else 1)
PY
