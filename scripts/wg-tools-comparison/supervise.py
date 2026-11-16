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