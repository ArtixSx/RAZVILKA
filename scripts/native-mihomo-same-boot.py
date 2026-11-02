#!/usr/bin/env python3
"""Original process/pidfd custody in an already isolated mount+net namespace."""
import array
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
    subprocess.run(['umount', '/opt/bin/razvilka'], check=True, timeout=5)
    subprocess.run(['mount', '--bind', str(work / 'cmd.test'), '/opt/bin/razvilka'], check=True, timeout=5)
    env['RAZVILKA_MIHOMO_SAME_BOOT_PRODUCER'] = '0'
    env['RAZVILKA_MIHOMO_SAME_BOOT_CONSUMER'] = '1'
    consumer, _ = custody.start([
        '/opt/bin/razvilka', '-test.run=^TestMihomoSameBootCLINativeOriginalParent$',
        '-test.v', '-test.count=1', '-test.timeout=140s',
    ], env=env)
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
