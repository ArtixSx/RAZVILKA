#!/bin/sh
# Lab source comparison only. Neither source variant changes the checkout.
set -eu
test "$(id -u)" = 0 || exit 2
test "$(uname -s)" = Linux || exit 2
test "$#" = 1 || exit 2
case "$1" in /*) ;; *) exit 2 ;; esac
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export GOTOOLCHAIN=local
python3 - "$repo" "$1" <<'PY'
import hashlib, io, json, os, pathlib, re, subprocess, sys, tarfile, tempfile, time

repo, output = map(pathlib.Path, sys.argv[1:])
repo = repo.resolve(strict=True)
output = output.resolve()
output.mkdir(parents=True, exist_ok=False)
git = ['git', '-c', 'safe.directory='+str(repo), '-C', str(repo)]
revision = subprocess.check_output(git+['rev-parse', 'HEAD'], text=True).strip()
if not re.fullmatch('[0-9a-f]{40}', revision):
    raise SystemExit('exact source revision required')
archive = subprocess.check_output(git+['archive', '--format=tar', revision])
target = 'internal/dataplane/mihomo_live_cold_process_linux.go'
before = b'borrowMihomoColdSelfImage(held, "/proc/self/exe", &domainTCPImageScratch)'
after = b'borrowMihomoColdSelfImage(held, "/proc/self/exe", nil)'
def digest(data):
    return hashlib.sha256(data).hexdigest()
def manifest(root):
    result = {}
    for p in sorted(root.rglob('*')):
        name = p.relative_to(root).as_posix()
        if p.is_symlink():
            result[name] = {'kind':'symlink', 'target':os.readlink(p)}
        elif p.is_file():
            result[name] = {'kind':'file', 'size':p.stat().st_size,
                            'sha256':digest(p.read_bytes()), 'mode':p.stat().st_mode & 0o777}
    return result
def tree_digest(value):
    return digest(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
rows = []
failed = False
with tempfile.TemporaryDirectory(prefix='razvilka-sameboot-image-', dir='/tmp') as scratch:
    scratch = pathlib.Path(scratch)
    sources = {'image':scratch/'variant-a', 'two-sha':scratch/'variant-b'}
    for root in sources.values():
        root.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as bundle:
            bundle.extractall(root,filter='data')
    original = (sources['image']/target).read_bytes()
    if original.count(before) != 1 or after in original:
        raise SystemExit('exact single original call required')
    changed = original.replace(before,after,1)
    (sources['two-sha']/target).write_bytes(changed)
    manifests = {name:manifest(root) for name,root in sources.items()}
    left,right = manifests['image'],manifests['two-sha']
    delta = [name for name in sorted(set(left)|set(right)) if left.get(name)!=right.get(name)]
    if delta != [target]:
        raise SystemExit('source delta exceeds exact scratch argument')
    proof = {'revision':revision,'archive_sha256':digest(archive),'only_changed_file':target,
             'original_file_sha256':digest(original),'comparison_file_sha256':digest(changed),
             'replacement_before':before.decode(),'replacement_after':after.decode(),
             'tree_sha256':{name:tree_digest(value) for name,value in manifests.items()},
             'sequence':['image','two-sha','two-sha','image'],
             'consumer_deadline_seconds':120,'profile_enabled':False,
             'scope':'cold process self image only; other shared scratch consumers unchanged'}
    (output/'source-provenance.json').write_text(json.dumps(proof,indent=2)+'\n')
    for name,value in manifests.items():
        (output/(name+'.files.json')).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    for build in ('normal','race'):
        for sample,variant in enumerate(proof['sequence']):
            source = sources[variant]
            if manifest(source) != manifests[variant]:
                raise SystemExit('source changed between samples')
            env = os.environ.copy()
            env['RAZVILKA_NATIVE_RACE'] = '1' if build=='race' else '0'
            env['RAZVILKA_HEV_ALTSTACK_LAB'] = '1'
            env['RAZVILKA_MIHOMO_SAME_BOOT_CPU_PROFILE'] = '0'
            env.pop('RAZVILKA_MIHOMO_SAME_BOOT_ACK_CUT',None)
            env.pop('RAZVILKA_MIHOMO_SAME_BOOT_PROFILE_OUTPUT',None)
            log = output/(f'{build}-{sample}-{variant}.log')
            started = time.monotonic_ns()
            with log.open('xb') as stream:
                # This unchanged driver builds app/cmd/startup from THIS
                # variant, owns all namespace cleanup and original timeouts.
                result = subprocess.run(['sh',str(source/'scripts/test-mihomo-same-boot-native.sh')],
                                        cwd=source,env=env,stdout=stream,stderr=subprocess.STDOUT)
            wall_ms = (time.monotonic_ns()-started)/1e6
            text = log.read_text(errors='replace')
            matches = re.findall(r'^--- (PASS|FAIL|SKIP): TestMihomoSameBootCLINativeOriginalParent \(([0-9.]+)s\)$',text,re.M)
            outcome,seconds = matches[0] if len(matches)==1 else ('unavailable',None)
            row = {'build':build,'sample':sample,'variant':variant,'exit_code':result.returncode,
                   'consumer_outcome':outcome,'consumer_seconds':float(seconds) if seconds else None,
                   'driver_wall_including_build_ms':wall_ms,'log_sha256':digest(log.read_bytes())}
            rows.append(row)
            print(json.dumps(row),flush=True)
            (output/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
            if result.returncode != 0 or outcome!='PASS' or '--- SKIP:' in text:
                failed = True
    if any(manifest(root)!=manifests[name] for name,root in sources.items()):
        raise SystemExit('source changed during comparison')
if len(rows)!=8:
    raise SystemExit('incomplete fixed population')
(output/'result.json').write_text(json.dumps({'revision':revision,'samples':8,
    'conclusion':'failure' if failed else 'success','failed_samples_preserved':True,
    'same_host_normal_and_race':True,'source_variants_not_production_commits':True},indent=2)+'\n')
raise SystemExit(1 if failed else 0)
PY
