#!/usr/bin/env python3
"""Prepare reviewed AMD64 HEV assets locally; never publish or change a catalog."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import tarfile

NAME = 'razvilka-hev-2.17.1-runtime-altstack1'
PINS = {
    'hev-socks5-tunnel-2.17.1.tar.xz': 'a7b86050091c5a268d81de70b95d3bb0871ba4136160662b6496596761c2f9a7',
    'x86_64-unknown-linux-musl.tar.xz': '5f20e367608d6e547c04534d37d00ecedbaa0c2e82730df12957b3332fa36a2d',
    'hev-runtime-altstack.patch': '30dcee28f54a82305dd2da9b0b640a0dc54550d865bc2cf86cdafb404b7e7984',
    'hev-runtime-altstack-fault-test.c': '12d333a6eef43b1fa8f50f08c7a27e3a621ee051b8d92e2ca107db38028a4143',
    'bin/hev-original': 'a98763f18b0ad1f72a903221008488275f2bf60be00028886f9fa41622df6a03',
    'bin/hev-patched': '1170182f821cec62b03c1443747e52b45f48baa7d7595f45e95c2ccf958972d9',
    'bin/altstack-fault.test': 'c3cc99c25995f5691255fbf6aeeb86c472f68cba864e7b704596b2cf2c3d6b64',
}
SOURCE = 'hev-socks5-tunnel-2.17.1.tar.xz'
COMPILER = 'x86_64-unknown-linux-musl.tar.xz'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def canonical(path, exists=True):
    path = Path(path).absolute()
    require(path == path.resolve(strict=exists), 'aliased path refused')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'symlink path refused')
    return path


def read(root, name, limit=128 << 20):
    p = root / name
    canonical(p)
    before = p.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'nonregular or oversized input')
    with p.open('rb') as f:
        opened = os.fstat(f.fileno())
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
    def identity(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode
    require(identity(before) == identity(opened) == identity(after) == identity(p.stat()), 'input changed')
    require(len(data) == before.st_size <= limit, 'input length changed')
    return data


def archive_notices(data, prefix):
    """Read fixed archives without extraction; materialize confined notice aliases."""
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
        members = archive.getmembers()
        require(len(members) <= 25000 and sum(m.size for m in members) <= 2 << 30, 'archive bounds')
        indexed = {}
        for item in members:
            name = item.name.rstrip('/')
            p = PurePosixPath(name)
            require(name == p.as_posix() and not p.is_absolute() and '..' not in p.parts and
                    p.parts and p.parts[0] == prefix and '\\' not in name and name not in indexed,
                    'unsafe or duplicate archive path')
            require(item.isfile() or item.isdir() or item.issym() or item.islnk(), 'special archive member')
            indexed[name] = item
        for name, item in indexed.items():
            p = PurePosixPath(name)
            notice = p.name.lower().startswith(('license', 'copying', 'copyright', 'notice'))
            notice |= p.parts[:3] == (prefix, 'share', 'licenses')
            if not notice or item.isdir():
                continue
            target, visited = name, set()
            while True:
                require(target in indexed and target not in visited, 'missing or cyclic notice alias')
                visited.add(target)
                current = indexed[target]
                if current.isfile():
                    break
                require(current.issym() or current.islnk(), 'notice target not regular')
                link = current.linkname
                require(not PurePosixPath(link).is_absolute() and '\\' not in link, 'absolute notice alias')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(target), link) if current.issym() else link)
                require(target.startswith(prefix + '/'), 'escaping notice alias')
            require(current.size <= 4 << 20, 'oversized notice')
            content = archive.extractfile(current).read((4 << 20) + 1)
            require(len(content) == current.size, 'truncated notice')
            result[name] = (content, item.linkname if item.issym() or item.islnk() else None)
    require(result, 'missing notices')
    return result


def prepare(build, repo, output):
    build, repo = canonical(build), canonical(repo)
    output = canonical(output, False)
    require(output.parent.is_dir() and not output.exists(), 'output must be new with existing parent')
    for source in (build, repo):
        require(not output.is_relative_to(source) and not source.is_relative_to(output), 'output overlaps source')
    blobs = {name: read(build, name) for name in PINS}
    require(all(sha(blobs[n]) == digest for n, digest in PINS.items()), 'fixed artifact hash mismatch')
    manifest_bytes = read(build, 'build-manifest.json', 2 << 20)
    manifest = json.loads(manifest_bytes)
    require(manifest['schema'] == 1 and manifest['artifacts'] == PINS and
            manifest['hev_commit'] == '9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a' and
            manifest['task_commit'] == '328f35d903221b51811b3d02b277d665dfbdc75f' and
            manifest['toolchain_release'] == '20260515' and manifest['fault_tests'] == 'PASS' and
            manifest['route_or_router_acceptance'] is False and
            manifest['build_flags'] == ['ENABLE_STATIC=1', '-j2'] and
            manifest['official_binary_sha256'] == PINS['bin/hev-original'], 'build provenance mismatch')
    payload = {'source/' + SOURCE: blobs[SOURCE], 'provenance/build-manifest.json': manifest_bytes}
    notices, expected = [], {}
    for archive, prefix, origins in [
        (SOURCE, 'hev-socks5-tunnel-2.17.1', ['original/', 'patched/']),
        (COMPILER, 'x86_64-unknown-linux-musl', ['toolchain/']),
    ]:
        for name, (data, alias) in archive_notices(blobs[archive], prefix).items():
            dest = 'licenses/' + ('source/' if archive == SOURCE else 'toolchain/') + name
            payload[dest] = data
            entry = {'archive': archive, 'original_path': name, 'bundle_path': dest, 'sha256': sha(data)}
            if alias:
                entry['original_alias_target'] = alias
            notices.append(entry)
            for origin in origins:
                key = origin + (name[len(prefix) + 1:] if origin == 'patched/' else name)
                expected[key] = (sha(data), alias)
    actual = {}
    for entry in manifest['licenses']:
        require(entry['path'] not in actual, 'duplicate manifest notice')
        actual[entry['path']] = (entry['sha256'], entry.get('symlink_target'))
    require(actual == expected, 'incomplete or changed notice inventory')
    for name in ('compiler.txt', 'fault-tests.txt', 'build-original.log', 'build-patched.log'):
        payload['provenance/' + name] = read(build, name, 8 << 20)
    require(payload['provenance/compiler.txt'].decode() == manifest['compiler'], 'compiler metadata mismatch')
    require(b'HEV_RUNTIME_ALTSTACK_FAULT_CONTRACT_PASS' in payload['provenance/fault-tests.txt'].splitlines(), 'fault marker missing')
    for name in ('hev-runtime-altstack.patch', 'hev-runtime-altstack-fault-test.c'):
        require(read(repo, 'scripts/fixtures/' + name) == blobs[name], 'repository patch drift')
        payload['scripts/fixtures/' + name] = blobs[name]
    for name in ('build-hev-runtime-altstack-lab.sh', 'prepare-hev-vendor-assets.py'):
        payload['scripts/' + name] = read(repo, 'scripts/' + name, 1 << 20)
    # The build scripts, patch and fault tests are also redistributed source.
    payload['LICENSE'] = read(repo, 'LICENSE', 1 << 20)
    record = {'schema': 1, 'architecture': 'linux-amd64', 'upstream_version': '2.17.1',
              'vendor_revision': 'runtime-altstack1', 'binary_sha256': PINS['bin/hev-patched'],
              'status': 'prepared only; publication, default pin and router qualification separate',
              'compiler_archive': {'url': 'https://github.com/cross-tools/musl-cross/releases/download/20260515/' + COMPILER,
                                   'sha256': PINS[COMPILER], 'included': False},
              'licenses': notices, 'payload_sha256': {n: sha(d) for n, d in sorted(payload.items())}}
    payload['vendor-manifest.json'] = encoded(record)
    payload['README.txt'] = (NAME + '\nAMD64 vendor build, not an official upstream asset.\n'
                            'Source, exact patch, tests, build commands and notices are included.\n'
                            'Compiler archive is pinned in vendor-manifest.json and is not redistributed.\n'
                            'Use only the managed component replacement workflow; never overwrite receipts.\n'
                            'Publication/default catalog promotion and ARM64/router qualification are separate.\n').encode()
    payload['SHA256SUMS'] = ''.join(f'{sha(d)}  {n}\n' for n, d in sorted(payload.items())).encode()
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode='w:xz', format=tarfile.USTAR_FORMAT, preset=9) as tar:
        for name, data in sorted(payload.items()):
            info = tarfile.TarInfo(NAME + '/' + name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    assets = {NAME + '-linux-amd64': blobs['bin/hev-patched'], NAME + '-sources-notices.tar.xz': packed.getvalue()}
    assets[NAME + '.SHA256SUMS'] = ''.join(f'{sha(d)}  {n}\n' for n, d in sorted(assets.items())).encode()
    output.mkdir(mode=0o700)
    for name, data in assets.items():
        with (output / name).open('xb') as f:
            f.write(data)
    require(all(read(output, n) == d for n, d in assets.items()), 'output verification failed')
    return {n: sha(d) for n, d in assets.items()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.build_dir, args.repo, args.output), sort_keys=True))
