#!/usr/bin/env python3
"""Portable packaging contracts; synthetic inputs never qualify an ELF."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vendor', Path(__file__).with_name('prepare-hev-vendor-assets.py'))
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:xz') as tar:
        for name, content in entries:
            item = tarfile.TarInfo(name)
            if isinstance(content, tuple):
                item.type, item.linkname = tarfile.SYMTYPE, content[0]
                tar.addfile(item)
            else:
                item.size = len(content)
                tar.addfile(item, io.BytesIO(content))
    return stream.getvalue()


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.build, self.repo = self.root / 'build', self.root / 'repo'
        self.build.mkdir()
        self.repo.mkdir()
        (self.repo / 'LICENSE').write_bytes(b'project license fixture')
        self.blobs = {name: ('fixture ' + name).encode() for name in vendor.PINS}
        self.blobs[vendor.SOURCE] = archive([('hev-socks5-tunnel-2.17.1/LICENSE', b'MIT fixture')])
        self.blobs[vendor.COMPILER] = archive([
            ('x86_64-unknown-linux-musl/share/licenses/libc/COPYRIGHT', b'libc fixture'),
            ('x86_64-unknown-linux-musl/share/licenses/libc/alias', ('COPYRIGHT',)),
        ])
        self.pins = {n: vendor.sha(d) for n, d in self.blobs.items()}
        self.addCleanup(patch.stopall)
        patch.object(vendor, 'PINS', self.pins).start()
        for name, data in self.blobs.items():
            p = self.build / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        for name in ('hev-runtime-altstack.patch', 'hev-runtime-altstack-fault-test.c'):
            p = self.repo / 'scripts/fixtures' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(self.blobs[name])
        for name in ('build-hev-runtime-altstack-lab.sh', 'prepare-hev-vendor-assets.py'):
            (self.repo / 'scripts' / name).write_bytes(b'fixture script')
        self.manifest = dict(schema=1, artifacts=self.pins, hev_commit='9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a',
                             task_commit='328f35d903221b51811b3d02b277d665dfbdc75f', toolchain_release='20260515',
                             fault_tests='PASS', route_or_router_acceptance=False,
                             build_flags=['ENABLE_STATIC=1', '-j2'], official_binary_sha256=self.pins['bin/hev-original'],
                             compiler='fixture compiler', licenses=[])
        for prefix in ('original/hev-socks5-tunnel-2.17.1/', 'patched/'):
            self.manifest['licenses'].append(dict(path=prefix + 'LICENSE', sha256=vendor.sha(b'MIT fixture')))
        for name, alias in [('COPYRIGHT', None), ('alias', 'COPYRIGHT')]:
            entry = dict(path='toolchain/x86_64-unknown-linux-musl/share/licenses/libc/' + name,
                         sha256=vendor.sha(b'libc fixture'))
            if alias:
                entry['symlink_target'] = alias
            self.manifest['licenses'].append(entry)
        self.write_manifest()
        for name, data in [('compiler.txt', b'fixture compiler'), ('fault-tests.txt', b'HEV_RUNTIME_ALTSTACK_FAULT_CONTRACT_PASS\n'),
                           ('build-original.log', b'original'), ('build-patched.log', b'patched')]:
            (self.build / name).write_bytes(data)

    def write_manifest(self):
        (self.build / 'build-manifest.json').write_bytes(vendor.encoded(self.manifest))

    def prepare(self, name='output'):
        return vendor.prepare(self.build, self.repo, self.root / name)

    def test_deterministic_roundtrip_and_materialized_notices(self):
        first, second = self.prepare('one'), self.prepare('two')
        self.assertEqual(first, second)
        source = self.root / 'one' / (vendor.NAME + '-sources-notices.tar.xz')
        with tarfile.open(source) as tar:
            self.assertTrue(all(m.isfile() and m.mtime == 0 and m.uid == m.gid == 0 for m in tar))
            names = tar.getnames()
            self.assertFalse(any(n.endswith(vendor.COMPILER) for n in names))
            self.assertEqual(tar.extractfile(vendor.NAME + '/licenses/toolchain/x86_64-unknown-linux-musl/share/licenses/libc/alias').read(), b'libc fixture')
            manifest = json.load(tar.extractfile(vendor.NAME + '/vendor-manifest.json'))
            self.assertEqual(tar.extractfile(vendor.NAME + '/LICENSE').read(), b'project license fixture')
            for name, digest in manifest['payload_sha256'].items():
                self.assertEqual(vendor.sha(tar.extractfile(vendor.NAME + '/' + name).read()), digest)

    def test_drift_refuses_before_output(self):
        (self.build / 'bin/hev-patched').write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.prepare()
        self.assertFalse((self.root / 'output').exists())

    def test_incomplete_or_duplicate_licenses(self):
        for duplicate in (False, True):
            saved = list(self.manifest['licenses'])
            if duplicate:
                self.manifest['licenses'].append(saved[0])
            else:
                self.manifest['licenses'].pop()
            self.write_manifest()
            with self.assertRaises(ValueError):
                self.prepare()
            self.manifest['licenses'] = saved

    def test_provenance_and_fault_refusal(self):
        for key, value in [('fault_tests', 'FAIL'), ('route_or_router_acceptance', True), ('build_flags', [])]:
            prior = self.manifest[key]
            self.manifest[key] = value
            self.write_manifest()
            with self.assertRaises(ValueError):
                self.prepare()
            self.manifest[key] = prior
        self.write_manifest()
        (self.build / 'fault-tests.txt').write_bytes(b'not the exact marker')
        with self.assertRaisesRegex(ValueError, 'fault marker'):
            self.prepare()

    def test_output_confinement(self):
        for path in (self.build / 'out', self.repo / 'out', self.root):
            with self.assertRaises(ValueError):
                vendor.prepare(self.build, self.repo, path)

    def test_repository_patch_drift(self):
        (self.repo / 'scripts/fixtures/hev-runtime-altstack.patch').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'patch drift'):
            self.prepare()

    def test_archive_refusals(self):
        for entries in [
            [('root/../LICENSE', b'a')], [('root/LICENSE', b'a'), ('root/LICENSE', b'b')],
            [('root/LICENSE', ('../../foreign',))], [('root/LICENSE', ('LICENSE',))],
            [('root/LICENSE', ('missing',))],
        ]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                vendor.archive_notices(archive(entries), 'root')

    def test_symlink_input_refuses(self):
        target = self.build / 'bin/hev-patched'
        target.unlink()
        try:
            target.symlink_to(self.build / 'bin/hev-original')
        except OSError:
            self.skipTest('host does not permit symbolic links')
        with self.assertRaises(ValueError):
            self.prepare()


if __name__ == '__main__':
    unittest.main()
