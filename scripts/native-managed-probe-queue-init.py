#!/usr/bin/env python3
"""CI-only real queue-handler initialization, never controller authority."""
import hashlib
import os
import pathlib
import select
import signal
import subprocess
import time

if (os.geteuid() != 0 or
        os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net') or
        os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt')):
    raise SystemExit('ROOT private mount+network namespace required')

binary = pathlib.Path(os.environ['RAZVILKA_MANAGED_PROBE_FIXTURE_WORK']) / 'zapret2-v1.0.6/binaries/linux-x86_64/nfqws2'
if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != '25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1':
    raise SystemExit('actual pinned initialization binary changed')
if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
    raise SystemExit('original child custody requires default SIGCHLD, no auto-reaper')
capability = os.pidfd_open(os.getpid(), 0)
signal.pidfd_send_signal(capability, 0)  # Check the signal API with no signal sent.
os.close(capability)  # Refuse unsupported pidfd kernels BEFORE creating a child.

# No hook references this queue; no socket is connected and no packet is sent.
# xt_NFQUEUE alone does not initialize the NFNETLINK_QUEUE per-net inventory.
process = subprocess.Popen([str(binary), '--qnum=64611', '--intercept=1', '--filter-tcp=443'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, start_new_session=True)
try:
    pidfd = os.pidfd_open(process.pid, 0)  # BEFORE any poll/Wait.
except BaseException:
    # Exceptional FD exhaustion: this single-threaded parent has NOT polled or
    # waited, and SIGCHLD cannot auto-reap. The SAME original child (or zombie)
    # still occupies this PID until our sole Wait, so it cannot target reuse.
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    raise
queue = pathlib.Path('/proc/net/netfilter/nfnetlink_queue')
observed = False
forced = False
try:
    expires = time.monotonic() + 5
    while time.monotonic() < expires:
        if select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError('pinned queue initializer exited before real registration')
        try:
            rows = queue.read_text().splitlines()
        except FileNotFoundError:
            rows = []
        if any(row.split() and row.split()[0] == '64611' for row in rows):
            observed = True
            break
        time.sleep(0.05)
    if not observed:
        raise RuntimeError('real NFNETLINK_QUEUE registration unavailable')
finally:
    try:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            pass  # SAME already exited original child still belongs to our Wait.
        try:
            process.wait(timeout=5)  # This parent is the sole waiter.
        except subprocess.TimeoutExpired:
            forced = True
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            process.wait(timeout=5)
    finally:
        os.close(pidfd)

if forced or not observed or queue.read_text().strip():
    raise SystemExit('queue initializer did not leave positively observed empty kernel inventory')
print('Actual pinned no-hook queue64611 registration, pidfd TERM+sole Wait, empty real NFNETLINK_QUEUE inventory confirmed')
