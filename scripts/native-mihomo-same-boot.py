#!/usr/bin/env python3
"""Original process/pidfd custody in an already isolated mount+net namespace."""
import array
import errno
import json
import os
import pathlib
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


def image_mount(image):
    """Identify the one original private bind; never retain a busy open FD."""
    target = pathlib.Path('/opt/bin/razvilka')
    source, mounted = image.lstat(), target.lstat()
    if not all(stat.S_ISREG(s.st_mode) and s.st_uid == 0 for s in (source, mounted)) or (source.st_dev, source.st_ino) != (mounted.st_dev, mounted.st_ino):
        raise RuntimeError('original fixture image changed')
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise RuntimeError('fixture mount inventory bound')
    matches = [line for line in raw.splitlines() if len(line.split()) >= 10 and line.split()[4] == b'/opt/bin/razvilka']
    if len(matches) != 1:
        raise RuntimeError('one original fixture image mount required')
    fields = matches[0].split()
    separator = fields.index(b'-')
    if any(field.startswith((b'shared:', b'master:', b'propagate_from:')) for field in fields[6:separator]):
        raise RuntimeError('private fixture image mount required')
    return source.st_dev, source.st_ino, matches[0]


def unmount_original_image(image, original):
    # The original parent is already killed and joined. A transient busy mount
    # remains a refusal until ordinary umount succeeds within the SAME 5s cap.
    # No force/lazy flags, new image, foreign process signal or relaxed current.
    # Linux man-pages 6.19: https://man7.org/linux/man-pages/man2/umount.2.html
    # Keep the former original-child timeout/kill/Wait boundary even if the
    # kernel syscall stalls. The helper has no caller-selected path or flags.
    helper = '''import ctypes,sys
libc=ctypes.CDLL(None,use_errno=True)
libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
libc.umount2.restype=ctypes.c_int
result=libc.umount2(b'/opt/bin/razvilka',0)
error=ctypes.get_errno() if result else 0
print(error,flush=True)
sys.exit(1 if result else 0)
'''
    deadline = time.monotonic() + 5
    attempts = 0
    while True:
        if image_mount(image) != original:
            raise RuntimeError('original fixture image mount replaced')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('original fixture image remained busy within 5s')
        attempts += 1
        try:
            result = subprocess.run([sys.executable, '-I', '-c', helper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError('original fixture ordinary unmount exceeded original 5s') from error
        if len(result.stdout) > 8 or result.stderr or result.returncode not in (0, 1):
            raise RuntimeError('original fixture unmount helper failed')
        try:
            error = int(result.stdout)
        except ValueError as invalid:
            raise RuntimeError('original fixture unmount result malformed') from invalid
        if result.stdout != f'{error}\n'.encode() or not 0 <= error <= 4095 or (result.returncode == 0) != (error == 0):
            raise RuntimeError('original fixture unmount result inconsistent')
        if error == 0:
            print(f'original fixture ordinary unmount confirmed attempts={attempts}', flush=True)
            return
        if error != errno.EBUSY:
            raise OSError(error, 'original fixture ordinary unmount failed')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('original fixture image remained busy within 5s')
        time.sleep(min(0.05, remaining))


def interrupted(signum, _):
    raise InterruptedError(f'original fixture interrupted by signal {signum}')


def signal_original(descriptor):
    try:
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except ProcessLookupError:
        pass


class Custody:
    def __init__(self, work):
        self.children = []
        self.peer = None
        self.channel = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.channel.bind(str(work / 'same-boot-custody.sock'))
        os.chmod(work / 'same-boot-custody.sock', 0o600)
        self.channel.settimeout(0.1)

    def start(self, arguments, **options):
        child = subprocess.Popen(arguments, pass_fds=(3,), **options)
        try:
            # MUST precede poll/Wait, for this exact original Popen child.
            descriptor = os.pidfd_open(child.pid)
        except BaseException as original:
            # Sole original waiter + SIGCHLD_DFL; no numeric-PID adoption.
            try:
                child.kill()
                child.wait(timeout=10)
            except BaseException as cleanup:
                raise BaseExceptionGroup('pidfd acquisition and original child cleanup failed', [original, cleanup])
            raise
        self.children.append((child, descriptor))
        return child, descriptor

    def receive_peer(self):
        raw, ancillary, flags, _ = self.channel.recvmsg(64, socket.CMSG_SPACE(4 * 4) + socket.CMSG_SPACE(12))
        descriptors = []
        credentials = None
        try:
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i')
                    values.frombytes(data[:len(data) - len(data) % values.itemsize])
                    descriptors.extend(values)
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                    credentials = struct.unpack('3i', data)
            for descriptor in descriptors:
                os.set_inheritable(descriptor, False)
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or raw != b'original-physical-peer-v1' or len(descriptors) != 1 or credentials is None or credentials[0] < 1 or credentials[1] != os.geteuid() or self.peer is not None:
                raise RuntimeError('one bounded original peer pidfd message required')
            # Validation only, never a signal by sender-supplied numeric PID.
            signal.pidfd_send_signal(descriptors[0], 0)
            self.peer = descriptors.pop()
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def close(self):
        # Further TERM cannot interrupt finite original-handle cleanup. The
        # external timeout still has its independent hard backstop.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        failures = []
        for child, descriptor in reversed(self.children):
            try:
                if child.returncode is None:
                    signal_original(descriptor)
                    child.wait(timeout=10)
            except BaseException as error:
                failures.append(error)
            finally:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    failures.append(error)
        if self.peer is not None:
            try:
                signal_original(self.peer)
                if not select.select([self.peer], [], [], 10)[0]:
                    raise RuntimeError('original physical peer did not terminate')
                print('original physical peer pidfd terminal observation confirmed', flush=True)
            except BaseException as error:
                failures.append(error)
            finally:
                try:
                    os.close(self.peer)
                except BaseException as error:
                    failures.append(error)
        self.channel.close()
        if failures:
            raise BaseExceptionGroup('original fixture cleanup failed', failures)


def run(work, custody):
    original_image = image_mount(work / 'app.test')
    ready = pathlib.Path('/opt/razvilka/state/dataplane/.same-boot-native-ready.json')
    env = os.environ.copy()
    env['RAZVILKA_MIHOMO_SAME_BOOT_PRODUCER'] = '1'
    with (work / 'original-parent.log').open('xb') as output:
        parent, descriptor = custody.start([
            '/opt/bin/razvilka', '-test.run=^TestMihomoLiveOriginalApplyStopAndFreshApply$',
            '-test.v', '-test.count=1', '-test.timeout=150s',
        ], env=env, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 125
        while not ready.exists():
            try:
                custody.receive_peer()
            except socket.timeout:
                pass
            if parent.poll() is not None:
                raise RuntimeError('original producer exited before actual policy ACK')
            if time.monotonic() >= deadline:
                raise RuntimeError('original producer policy ACK deadline')
            time.sleep(0.05)
        if custody.peer is None:
            custody.receive_peer()
        info = ready.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise RuntimeError('bounded original witness required')
        document = json.loads(ready.read_bytes())
        if set(document) != {'PlanID', 'Digest'} or not all(document.values()):
            raise RuntimeError('original policy ACK witness malformed')
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        if parent.wait(timeout=10) != -signal.SIGKILL:
            raise RuntimeError('original parent death not confirmed')
        print('actual original parent SIGKILL and sole Wait confirmed', flush=True)
    # Only after original Wait replace the private mounted test image.
    unmount_original_image(work / 'app.test', original_image)
    subprocess.run(['mount', '--bind', str(work / 'cmd.test'), '/opt/bin/razvilka'], check=True, timeout=5)
    env['RAZVILKA_MIHOMO_SAME_BOOT_PRODUCER'] = '0'
    env['RAZVILKA_MIHOMO_SAME_BOOT_CONSUMER'] = '1'
    consumer_command = [
        '/opt/bin/razvilka', '-test.run=^TestMihomoSameBootCLINativeOriginalParent$',
        '-test.v', '-test.count=1', '-test.timeout=140s',
    ]
    profile = os.environ.get('RAZVILKA_MIHOMO_SAME_BOOT_CPU_PROFILE', '0')
    if profile not in ('0', '1'):
        raise RuntimeError('closed native profiling mode required')
    if profile == '1':
        consumer_command.append('-test.cpuprofile=' + str(work / 'sameboot-consumer.cpu.pprof'))
    consumer, _ = custody.start(consumer_command, env=env)
    return consumer.wait(timeout=150)


def main():
    work = pathlib.Path(sys.argv[1])
    if os.geteuid() != 0 or not work.is_absolute() or work.lstat().st_uid != 0 or stat.S_IMODE(work.lstat().st_mode) != 0o700:
        raise RuntimeError('private root fixture required')
    for kind in ('net', 'mnt'):
        if os.readlink(f'/proc/self/ns/{kind}') == os.readlink(f'/proc/1/ns/{kind}'):
            raise RuntimeError('distinct actual namespaces required')
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    probe = os.pidfd_open(os.getpid())
    os.close(probe)
    if not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('actual pidfd signalling required')
    custody = Custody(work)  # Bind private channel BEFORE original launch.
    try:
        result = run(work, custody)
    except BaseException as original:
        try:
            custody.close()
        except BaseException as cleanup:
            raise BaseExceptionGroup('original fixture and cleanup failed', [original, cleanup])
        raise
    custody.close()
    return result


if __name__ == '__main__':
    try:
        sys.exit(main())
    finally:
        if len(sys.argv) == 2:
            log = pathlib.Path(sys.argv[1]) / 'original-parent.log'
            if log.is_file():
                with log.open('rb') as stream:
                    sys.stdout.buffer.write(stream.read(65536))
