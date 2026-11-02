#!/usr/bin/python3
"""Hand the supervisor this ORIGINAL process's pidfd, then exec the peer."""
import array
import ctypes
import os
import pathlib
import signal
import socket
import stat

root = pathlib.Path(os.environ['TMPDIR'])
channel = root / 'same-boot-custody.sock'
peer = root / 'physical-peer-original'
if os.geteuid() != 0 or not root.is_absolute():
    raise SystemExit('private root fixture required')
for path, kind, mode in ((root, stat.S_ISDIR, 0o700), (channel, stat.S_ISSOCK, 0o600), (peer, stat.S_ISREG, 0o500)):
    info = path.lstat()
    if info.st_uid != os.geteuid() or not kind(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
        raise SystemExit('original private peer custody path required')
parent = os.getppid()
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'original peer parent-death binding')
if os.getppid() != parent:
    os.kill(os.getpid(), signal.SIGKILL)
descriptor = os.pidfd_open(os.getpid())
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
        sender.settimeout(3)
        count = sender.sendmsg([b'original-physical-peer-v1'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor]))], 0, str(channel))
        if count != len(b'original-physical-peer-v1'):
            raise RuntimeError('original peer custody transfer incomplete')
finally:
    os.close(descriptor)
# The same PID/birth and PDEATHSIG survive this non-privileged exec. The peer
# already gives its own actual Xray child a parent-death SIGKILL binding.
os.execv('/usr/bin/python3', ['/usr/bin/python3', str(peer)])
