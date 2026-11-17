#!/usr/bin/env python3
"""One exact-source diagnostic population; never a performance comparison."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

import importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('comparison', HERE / 'compare-wg-tools.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)
DRIVER = 'scripts/test-managed-probe-native.sh'
DRIVER_SHA = '38e8b847104e6a80328d5e4fbd5221e19b2d016726e244a26cdfcd5e468856ad'
POPULATIONS = {
    'old-checkptr': ('go1.26.5', 'production', True),
    'old-race-checkptr': ('go1.26.5', 'race', True),
    'patch-production': ('go1.26.11', 'production', False),
}


def diagnostic_driver(original, checkptr):
    if comparison.sha(original) != DRIVER_SHA:
        raise RuntimeError('original driver drift')
    flags = b'GOMAXPROCS=2 GOFLAGS=-p=2\n'
    marker = b"PY\nprintf '127.0.0.1 localhost\\n8.8.8.8 managed-probe.example\\n'"
    if original.count(flags) != 1 or original.count(marker) != 1:
        raise RuntimeError('diagnostic insertion boundary drift')
    result = original
    if checkptr:
        result = result.replace(flags, b"GOMAXPROCS=2 GOFLAGS='-p=2 -gcflags=all=-d=checkptr=2'\n")
    # After the original 64 MiB admission check, before any network actor.
    # The evidence directory is newly created, private, and disjoint from source.
    evidence = b'''PY
printf 'Diagnostic app ELF: '
sha256sum "$probe_work/app.test"
go version -m "$probe_work/app.test"
cp "$probe_work/app.test" "$RAZVILKA_DIAGNOSTIC_ELF/app.test"
chmod 400 "$RAZVILKA_DIAGNOSTIC_ELF/app.test"
printf '127.0.0.1 localhost\\n8.8.8.8 managed-probe.example\\n' '''.rstrip()
    return result.replace(marker, evidence)


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 4 or sys.argv[3] not in POPULATIONS:
        raise SystemExit('Linux root: diagnose-memory.py CHECKOUT NEW_OUTPUT POPULATION')
    repo = pathlib.Path(sys.argv[1]).resolve(strict=True)
    out = pathlib.Path(sys.argv[2])
    if not out.is_absolute() or out != out.resolve() or not out.parent.is_dir() or out.exists() or out.is_symlink() or out == repo or out in repo.parents or repo in out.parents:
        raise SystemExit('new canonical disjoint output required')
    version, mode, checkptr = POPULATIONS[sys.argv[3]]
    env = {k: v for k, v in os.environ.items() if not k.startswith('RAZVILKA_') and k not in ('GOFLAGS', 'GOEXPERIMENT', 'GODEBUG')}
    env.update(GOTOOLCHAIN='local', GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1')
    actual = subprocess.check_output(['go', 'version'], env=env, text=True).strip()
    if actual != 'go version ' + version + ' linux/amd64':
        raise RuntimeError('toolchain does not match named diagnostic population: ' + actual)
    supervisor = HERE / 'supervise.py'
    if comparison.sha(supervisor.read_bytes()) != comparison.SUPERVISOR_SHA:
        raise RuntimeError('supervisor drift')
    git = ['git', '--no-lazy-fetch', '-c', 'safe.directory=' + str(repo), '-C', str(repo)]
    for suffix in (['diff', '--quiet'], ['diff', '--cached', '--quiet']):
        subprocess.run(git + suffix, env=env, check=True)
    out.mkdir(mode=0o700)
    elf = out / 'elf'
    elf.mkdir(mode=0o700)
    work = pathlib.Path(tempfile.mkdtemp(prefix='razvilka-memory-', dir='/tmp')).resolve()
    safe = True
    try:
        archive = work / 'source.tar'
        with archive.open('xb') as f:
            subprocess.run(git + ['archive', comparison.REVISION], env=env, stdout=f, check=True)
        source = work / 'source'
        source.mkdir(mode=0o700)
        with tarfile.open(archive) as tf:
            tf.extractall(source, filter='data')
        before = comparison.files(source)
        candidate = (source / comparison.TARGET).read_bytes()
        baseline = comparison.baseline(candidate)
        if comparison.sha(candidate) != comparison.CANDIDATE_SHA or comparison.sha(baseline) != comparison.BASELINE_SHA:
            raise RuntimeError('exact baseline source drift')
        (source / comparison.TARGET).write_bytes(baseline)
        (source / DRIVER).write_bytes(diagnostic_driver((source / DRIVER).read_bytes(), checkptr))
        after = comparison.files(source)
        if set(k for k in before if before[k] != after[k]) != {comparison.TARGET, DRIVER}:
            raise RuntimeError('unexpected source delta')
        (out / 'source-manifest.json').write_text(json.dumps(after, sort_keys=True) + '\n')
        proof = {'revision': comparison.REVISION, 'archive_sha256': comparison.sha(archive.read_bytes()),
                 'population': sys.argv[3], 'go_version': actual, 'mode': mode, 'checkptr_2': checkptr,
                 'deltas': {k: {'before': before[k], 'after': after[k]} for k in (comparison.TARGET, DRIVER)},
                 'original_test_timeout_seconds': 240, 'internal_budgets_and_profiling': 'unchanged',
                 'purpose': 'Investigate failed baseline memory corruption; not release or speed evidence.'}
        (out / 'source-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        env.update(RAZVILKA_MANAGED_PROBE_LAN_NATIVE='1', RAZVILKA_MANAGED_PROBE_LAN_CASE='manual',
                   RAZVILKA_MANAGED_PROBE_CASE_SET='all', RAZVILKA_MANAGED_PROBE_BUILD_MODE=mode,
                   RAZVILKA_DIAGNOSTIC_ELF=str(elf))
        folder = out / 'actor'
        folder.mkdir(mode=0o700)
        safe = False
        result = subprocess.run([sys.executable, str(supervisor), str(source / 'scripts/test-managed-probe-lan-native.sh'), str(folder)], env=env, cwd=source, stdout=subprocess.DEVNULL)
        state = json.loads((folder / 'supervisor.json').read_text())
        safe = state.get('descendants_absent') is True
        classified = comparison.classify(folder, result.returncode)
        if comparison.files(source) != after:
            raise RuntimeError('source changed during diagnostic')
        log = (folder / 'native.log').read_text()
        saved = elf / 'app.test'
        logged = re.findall(r'^Diagnostic app ELF: ([0-9a-f]{64})  .*/app[.]test$', log, re.M)
        binary_ok = False
        classified['binary_sha256_limit'] = 'Saved ELF is hashed after the joined actor and compared with the pre-actor log.'
        if saved.is_file() and not saved.is_symlink():
            info = saved.stat()
            if info.st_nlink == 1 and 0 < info.st_size <= 64 << 20:
                digest = comparison.sha(saved.read_bytes())
                binary_ok = logged == [digest] and classified['binary_bytes'] == info.st_size
                classified['binary_sha256'] = digest
        classified['saved_elf_matches_pre_actor'] = binary_ok
        classified['pass'] = classified['pass'] and binary_ok
        report = {'source': proof, 'exit': result.returncode, 'outcome': classified,
                  'fatal_memory': 'fatal error: found pointer to free object' in log,
                  'race_report': 'WARNING: DATA RACE' in log,
                  'checkptr_report': 'fatal error: checkptr:' in log,
                  'limits': ['A nonreproduction does not establish the crash cause or a toolchain fix.',
                             'Separate hosts/toolchains/instrumentation are not comparable performance samples.',
                             'No candidate arm or actual router runs in this diagnostic.']}
        report['raw'] = {p.relative_to(out).as_posix(): comparison.sha(p.read_bytes()) for p in out.rglob('*') if p.is_file()}
        (out / 'diagnostic.json').write_text(json.dumps(report, indent=2) + '\n')
        return 0 if classified['pass'] else 1
    finally:
        if safe:
            if work.parent != pathlib.Path('/tmp') or not work.name.startswith('razvilka-memory-'):
                raise RuntimeError('cleanup boundary')
            shutil.rmtree(work)
        else:
            (out / 'retained-source-workspace.txt').write_text(str(work) + '\n')


if __name__ == '__main__':
    sys.exit(main())
