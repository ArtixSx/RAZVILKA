#!/bin/sh
# Same-host source comparison; no changes to the checkout or route budgets.
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
    raise SystemExit('exact current revision required')
baseline = 'aab413ebf6f16567434fd0f2569331708c9b0b71'
blob = '9310a512731b18d9badb34d87b4f19e6144cd2ca'
target = 'internal/dataplane/wg_empty_table_read.go'
actual_blob = subprocess.check_output(git+['rev-parse',baseline+':'+target],text=True).strip()
if actual_blob != blob:
    raise SystemExit('historical exact blob refused')
old = subprocess.check_output(git+['cat-file','blob',blob])
archive = subprocess.check_output(git+['archive','--format=tar',revision])

def digest(data):
    return hashlib.sha256(data).hexdigest()

def manifest(root):
    rows = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows[name] = {'kind':'link','target':os.readlink(path)}
        elif path.is_file():
            rows[name] = {'kind':'file','sha256':digest(path.read_bytes()),
                          'bytes':path.stat().st_size,'mode':path.stat().st_mode & 0o777}
    return rows

rows, failed = [], False
sequence = ['cli','kernel','kernel','cli'] * 2
with tempfile.TemporaryDirectory(prefix='razvilka-wg-pair-',dir='/tmp') as scratch:
    sources = {name:pathlib.Path(scratch)/name for name in ('cli','kernel')}
    for source in sources.values():
        source.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as bundle:
            bundle.extractall(source,filter='data')
    new = (sources['kernel']/target).read_bytes()
    if new == old:
        raise SystemExit('candidate has no source change')
    (sources['cli']/target).write_bytes(old)
    manifests = {name:manifest(source) for name,source in sources.items()}
    delta = [name for name in sorted(set(manifests['cli'])|set(manifests['kernel']))
             if manifests['cli'].get(name)!=manifests['kernel'].get(name)]
    if delta != [target]:
        raise SystemExit('comparison differs outside exact old table reader')
    proof = {'revision':revision,'historical_revision':baseline,'historical_blob':blob,
             'archive_sha256':digest(archive),'only_changed_file':target,
             'baseline_sha256':digest(old),'candidate_sha256':digest(new),
             'sequence_per_mode':sequence,'modes':['production','race'],
             'original_body_budget_seconds':8,'full_apply':False,
             'scope':'complete original WG inactivity calls, two engines, same fresh namespace per sample'}
    (output/'source-provenance.json').write_text(json.dumps(proof,indent=2)+'\n')
    for name,value in manifests.items():
        (output/(name+'.files.json')).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    for mode in proof['modes']:
        for sample,variant in enumerate(sequence):
            source = sources[variant]
            if manifest(source) != manifests[variant]:
                raise SystemExit('source changed before sample')
            env = os.environ.copy()
            # Closed fixture population, independent of caller acceptance flags.
            for name in list(env):
                if name.startswith(('RAZVILKA_MANAGED_PROBE_', 'RAZVILKA_NFQWS_NEVER_ISSUED_',
                                    'RAZVILKA_MIHOMO_COLD_SOURCE_', 'RAZVILKA_NATIVE_RACE_HELPER_EXIT')):
                    del env[name]
            env['RAZVILKA_MANAGED_PROBE_CASE_SET'] = 'wg-inactivity'
            env['RAZVILKA_MANAGED_PROBE_BUILD_MODE'] = mode
            log = output/(f'{mode}-{sample}-{variant}.log')
            started = time.monotonic_ns()
            with log.open('xb') as stream:
                result = subprocess.run(['sh',str(source/'scripts/test-managed-probe-native.sh')],
                                        cwd=source,env=env,stdout=stream,stderr=subprocess.STDOUT)
            wall = (time.monotonic_ns()-started)/1e6
            text = log.read_text(errors='replace')
            records = re.findall(r'actual_wg_inactivity_measurement engine=(wireguard|amneziawg) elapsed_ns=(\d+) outcome=(passed|refused) closed=(true|false) original_body_budget_seconds=8 full_apply=false',text)
            outcomes = re.findall(r'^--- (PASS|FAIL|SKIP): TestManagedStrategyProbeNativeWGInactivityMeasurement \(([0-9.]+)s\)$',text,re.M)
            passed = (result.returncode==0 and len(outcomes)==1 and outcomes[0][0]=='PASS'
                      and len(records)==2 and [r[0] for r in records]==['wireguard','amneziawg']
                      and all(r[2:] == ('passed','true') for r in records) and '--- SKIP:' not in text)
            row = {'mode':mode,'sample':sample,'variant':variant,'exit_code':result.returncode,
                   'accepted':passed,'driver_wall_including_build_ms':wall,'log_sha256':digest(log.read_bytes()),
                   'calls':[{'engine':r[0],'elapsed_ns':int(r[1]),'outcome':r[2],'closed':r[3]=='true'} for r in records],
                   'test_outcomes':outcomes}
            rows.append(row)
            failed |= not passed
            print(json.dumps(row),flush=True)
            (output/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
    if any(manifest(source)!=manifests[name] for name,source in sources.items()):
        raise SystemExit('source changed during comparison')
if len(rows)!=16:
    raise SystemExit('fixed population incomplete')
(output/'result.json').write_text(json.dumps({'revision':revision,'samples':len(rows),
    'conclusion':'failure' if failed else 'success','same_host':True,
    'failed_samples_preserved':True,'full_apply':False},indent=2)+'\n')
raise SystemExit(1 if failed else 0)
PY
