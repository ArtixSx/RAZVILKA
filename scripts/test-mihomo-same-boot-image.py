#!/usr/bin/env python3
"""Ordinary fixture-image unmount: finite EBUSY, exact identity, no force."""
import errno
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('sameboot', pathlib.Path(__file__).with_name('native-mihomo-same-boot.py'))
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class ImageRetryContracts(unittest.TestCase):
    def invoke(self, errors, identities=None):
        now = [0.0]
        calls = []
        def unmount(arguments, **options):
            calls.append((arguments, options))
            value = errors[min(len(calls) - 1, len(errors) - 1)]
            if value == 'stall':
                raise subprocess.TimeoutExpired(arguments, options['timeout'])
            return subprocess.CompletedProcess(arguments, 1 if value else 0, f'{value}\n'.encode(), b'')
        def sleep(seconds):
            now[0] += seconds
        identity = mock.Mock(return_value='original', side_effect=identities)
        with mock.patch.object(subject.subprocess, 'run', side_effect=unmount), mock.patch.object(subject, 'image_mount', identity), mock.patch.object(subject.time, 'monotonic', side_effect=lambda: now[0]), mock.patch.object(subject.time, 'sleep', side_effect=sleep):
            try:
                subject.unmount_original_image(pathlib.Path('/private/app.test'), 'original')
            finally:
                self.assertTrue(all(a[:3] == [sys.executable, '-I', '-c'] and "umount2(b'/opt/bin/razvilka',0)" in a[3] and 0 < o['timeout'] <= 5 for a, o in calls))
                self.calls, self.elapsed = calls, now[0]

    def test_transient_busy_then_ordinary_success(self):
        self.invoke([errno.EBUSY, errno.EBUSY, 0])
        self.assertEqual(len(self.calls), 3)
        self.assertAlmostEqual(self.elapsed, 0.1)

    def test_persistent_busy_keeps_original_five_seconds(self):
        with self.assertRaises(TimeoutError):
            self.invoke([errno.EBUSY])
        self.assertAlmostEqual(self.elapsed, 5)
        self.assertLessEqual(len(self.calls), 102)

    def test_nonbusy_error_is_never_retried(self):
        with self.assertRaises(OSError) as result:
            self.invoke([errno.EPERM])
        self.assertEqual(result.exception.errno, errno.EPERM)
        self.assertEqual(len(self.calls), 1)

    def test_replaced_mount_refuses_before_next_unmount(self):
        with self.assertRaisesRegex(RuntimeError, 'replaced'):
            self.invoke([errno.EBUSY, 0], ['original', 'foreign'])
        self.assertEqual(len(self.calls), 1)

    def test_foreign_initial_mount_never_unmounted(self):
        with self.assertRaisesRegex(RuntimeError, 'replaced'):
            self.invoke([0], ['foreign'])
        self.assertEqual(self.calls, [])

    def test_stalled_helper_preserves_original_subprocess_timeout(self):
        with self.assertRaisesRegex(TimeoutError, 'exceeded original 5s'):
            self.invoke([errno.EBUSY, 'stall'])
        self.assertEqual(len(self.calls), 2)
        self.assertAlmostEqual(self.calls[1][1]['timeout'], 4.95)


class ActualPrivateMount(unittest.TestCase):
    def test_actual_busy_mount_only_succeeds_after_original_fd_close(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/mnt'), os.readlink('/proc/1/ns/mnt'))
        subprocess.run(['mount', '--make-rprivate', '/'], check=True, timeout=5)
        # All fixture paths live on this new private /opt, never the host tree.
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755,nodev,nosuid', 'tmpfs', '/opt'], check=True, timeout=5)
        root = pathlib.Path(tempfile.mkdtemp(prefix='sameboot-image-', dir='/opt'))
        source = root / 'app.test'
        source.write_bytes(b'original private image\n')
        source.chmod(0o500)
        pathlib.Path('/opt/bin').mkdir()
        target = pathlib.Path('/opt/bin/razvilka')
        target.touch(mode=0o500)
        subprocess.run(['mount', '--bind', str(source), str(target)], check=True, timeout=5)
        mounted = True
        held = target.open('rb')
        worker = None
        try:
            identity = subject.image_mount(source)
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                subject.unmount_original_image(source, identity)
            self.assertGreaterEqual(time.monotonic() - started, 5)
            self.assertEqual(held.read(), b'original private image\n')
            self.assertEqual(subject.image_mount(source), identity)
            def release():
                time.sleep(0.15)
                held.close()
            worker = threading.Thread(target=release)
            worker.start()
            subject.unmount_original_image(source, identity)
            mounted = False
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(target.read_bytes(), b'')
        finally:
            if worker is not None:
                worker.join(timeout=2)
                if worker.is_alive():
                    raise RuntimeError('original FD closer not joined')
            held.close()
            if mounted:
                subprocess.run(['umount', str(target)], check=True, timeout=5)
            subprocess.run(['umount', '/opt'], check=True, timeout=5)


if __name__ == '__main__':
    native = sys.argv[1:] == ['--native']
    if sys.argv[1:] and not native:
        raise SystemExit('only --native in a private Linux mount namespace is accepted')
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ImageRetryContracts)
    if native:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ActualPrivateMount))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
