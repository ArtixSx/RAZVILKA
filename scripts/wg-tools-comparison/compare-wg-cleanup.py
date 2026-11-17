#!/usr/bin/env python3
"""External diagnostic: same-source WG cleanup full manual Apply ABBA; no checkout writes."""
import hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tarfile, tempfile, time

REVISION = 'e3297ff117563d396d8935aca6c252dc65418371'
BASE_REVISION = '9971aa1bdb4f4daf3afd65b85ebe7e1cdae4156c'
TARGETS = {
    'internal/dataplane/wg_inactivity_kernel_links.go': {
        'candidate': 'eb32e42d352db058c48cb3bfd56f7b5ca8eedfce89f91802914a84a742eb924f',
        'baseline': '7f1b0a6a8aa490d0f1900c76d738ba1c6b7ee009803d2c7874fee652555fa337'},
    'internal/dataplane/wg_inactivity_empty_table.go': {
        'candidate': '4d84dd0e44a1dbf55c190ccf9c0f380cf1ad1c2b9bc8868536b1030adf23fb57',
        'baseline': 'e3c8f9c3b3816f759806271b8a76f7a17592c5d02451e6432ed9254504c17209'},
}
SUPERVISOR_SHA = '8b3c876a45462909a6b6442af10c3ac28a2713610a3d77cac8fc02a8c0d0567a'
GATE_TESTS = ['TestWGCleanupToolOriginalLifetimeAndBothLeaves', 'TestWGCleanupToolRefusalsAndNoFallback',
              'TestWGCleanupToolCloseJoinsOriginalCleanupRead', 'TestWGCleanupToolComparisonSingleJoinedCallback',
              'TestWGCleanupToolObservationRequiresOriginalSourceTuple', 'TestNativeWGKernelLinkOriginalHeldSource']
LEAF_MARKER = 'actual_wg_cleanup_tool_leaf original_scope=true full_check_pair=true kernel_dump=true effect_refused=true'
FLOW_MARKER = 'explicit manual diagnostic: genuine native validation + authenticated manual intent → SAME Review/Apply/COMMON/native consumer → included positive/excluded negative → original Stop/direct recovery; no probe/automatic/service-health evidence; Home classification only modeled'
TESTS = ['TestManagedProbeFailedCleanupTerminalVector', 'TestNativeFixturePhysicalSourceCopiesRefuse', 'TestManagedStrategyProbeNativeLANPhysical', 'TestManagedStrategyProbeNativeLANManualApply']

def sha(data): return hashlib.sha256(data).hexdigest()

def write_variant(source, payloads):
    if set(payloads) != set(TARGETS): raise RuntimeError('variant paths')
    for path, data in payloads.items(): (source/path).write_bytes(data)

def assert_variant_manifests(manifests):
    a, b = manifests['candidate'], manifests['baseline']
    if set(a) != set(b) or sorted(k for k in a if a[k] != b[k]) != sorted(TARGETS):
        raise RuntimeError('source delta')
    for path in TARGETS:
        if set(a[path]) != {'mode','sha256'} or set(b[path]) != {'mode','sha256'} or a[path]['mode'] != b[path]['mode']:
            raise RuntimeError('variant file shape')

def bounded_file(path, limit, executable=False):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or not 0 < before.st_size <= limit:
        raise RuntimeError('evidence/helper file shape')
    if executable and (before.st_mode & 0o111 == 0 or before.st_mode & 0o022): raise RuntimeError('helper mode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd); data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit+1-len(data)))
            if not chunk: break
            data.extend(chunk)
            if len(data) > limit: raise RuntimeError('file grew beyond limit')
        after, named = os.fstat(fd), path.lstat()
        fields = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if any(fields(s) != fields(before) for s in (opened,after,named)) or len(data) != before.st_size:
            raise RuntimeError('file changed during read')
        return bytes(data)
    finally: os.close(fd)

def helper_identity(path):
    data = bounded_file(path, 16 << 20, executable=True)
    return {'file':path.name, 'bytes':len(data), 'sha256':sha(data)}

def gate_log_valid(log):
    return ('--- SKIP:' not in log and '--- FAIL:' not in log and log.count(LEAF_MARKER) == 1 and
            all(len(re.findall(r'^--- PASS: '+re.escape(name)+r' \([0-9.]+s\)$',log,re.M)) == 1 for name in GATE_TESTS))

def raw_profiles(folder, outcomes):
    try:
        name = TESTS[-1]; root = folder/'profiles'/name
        for directory in (folder/'profiles',root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or directory != directory.resolve() or info.st_uid != os.geteuid():
                raise RuntimeError('profile directory identity')
        manifest = json.loads(bounded_file(root/'manifest.json', 8192))
        expected = {name+'.pprof', name+'.pprof.alloc'}
        if manifest.get('test') != name or type(manifest.get('original_test_exit')) is not int:
            raise RuntimeError('profile test identity')
        actor = [o for o in outcomes if o[1] == name]
        if len(actor) != 1 or actor[0][0] not in ('PASS','FAIL') or ((manifest['original_test_exit'] == 0) != (actor[0][0] == 'PASS')):
            raise RuntimeError('profile original outcome mismatch')
        rows = manifest.get('profiles')
        if not isinstance(rows,list) or len(rows) != 2 or {r.get('file') for r in rows} != expected or {p.name for p in root.iterdir()} != expected | {'manifest.json'}:
            raise RuntimeError('profile population')
        for row in rows:
            data = bounded_file(root/row['file'], 64 << 20)
            if row.get('bytes') != len(data) or row.get('sha256') != sha(data): raise RuntimeError('profile digest')
        return {'valid': True, 'manifest':manifest}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError) as error:
        return {'valid':False,'measurement_error':type(error).__name__}

def files(root):
    result = {}
    for p in sorted(root.rglob('*')):
        s = p.lstat(); row = {'mode': stat.S_IMODE(s.st_mode)}
        if p.is_symlink(): row['link'] = os.readlink(p)
        elif p.is_file(): row['sha256'] = sha(p.read_bytes())
        elif p.is_dir(): row['directory'] = True
        else: raise RuntimeError('nonregular source')
        result[p.relative_to(root).as_posix()] = row
    return result

def classify(folder, status):
    log = (folder/'native.log').read_text(encoding='utf-8', errors='strict')
    supervisor = json.loads((folder/'supervisor.json').read_text())
    capture = json.loads((folder/'log-capture.json').read_text())
    outcomes = re.findall(r'^--- (PASS|FAIL|SKIP): (\w+) \(([0-9.]+)s\)$', log, re.M)
    success = status == 0 and all(sum(o[0]=='PASS' and o[1]==name for o in outcomes)==1 for name in TESTS)
    success = success and '--- SKIP:' not in log and '--- FAIL:' not in log and log.count(FLOW_MARKER)==1
    boundary = supervisor.get('descendants_absent') is True and supervisor.get('no_overlap_boundary') is True and supervisor.get('forced_cleanup') is False
    capture_ok = capture.get('eof_complete') is True and capture.get('truncated') is False and capture.get('io_error') is False
    cleanup = 'actual_failed_apply_cleanup closed=true rolled_back=true independently_empty=true primary_apply_failed=true' in log
    completed_actor = any(o[1]==TESTS[-1] and o[0] in ('PASS','FAIL') for o in outcomes)
    unsafe = not boundary or not capture_ok or not completed_actor or (not success and not cleanup)
    build_ids=sorted(set(re.findall(r'^Build ID: (\S+)', log, re.M)))
    sizes=re.findall(r'^Actual compiled reader/consumer bytes: (\d+)$',log,re.M)
    profiles=len(build_ids)==1 and len(sizes)==1 and 0<int(sizes[0])<=64<<20 and '\nType: cpu\n' in log
    raw = raw_profiles(folder, outcomes)
    selected = [s for s in log.splitlines() if any(x in s for x in ('actual_wg_runtime_inactive', 'native actual HTTP', 'Managed NFQ original timing', 'Managed NFQ runtime apply refused', 'actual_failed_apply_cleanup', 'actual original LAN execution', 'Actual compiled reader/consumer bytes:'))]
    return {'pass': bool(success and boundary and capture_ok and profiles and raw['valid']), 'safe_next_sample': not unsafe,
            'supervisor': supervisor, 'log_capture': capture, 'test_outcomes': outcomes,
            'failed_apply_independently_empty': cleanup, 'counters_and_stages': selected,
            'profile_and_size_valid':profiles,'raw_profiles':raw,'binary_bytes':int(sizes[0]) if len(sizes)==1 else None,'pprof_build_ids':build_ids,
            'binary_sha256': None, 'binary_sha256_limit': 'unchanged driver removes private test ELF; only original byte count and pprof Build ID available'}

def main():
    if sys.platform != 'linux' or os.geteuid()!=0 or len(sys.argv)!=3: raise SystemExit('Linux root: compare-wg-cleanup.py CHECKOUT NEW_OUTPUT')
    repo = pathlib.Path(sys.argv[1]).resolve(strict=True); out = pathlib.Path(sys.argv[2])
    if not out.is_absolute() or out!=out.resolve() or not out.parent.is_dir() or out.exists() or out.is_symlink() or out==repo or out in repo.parents or repo in out.parents:
        raise SystemExit('new canonical disjoint output required')
    supervisor = pathlib.Path(__file__).with_name('supervise.py')
    if sha(supervisor.read_bytes())!=SUPERVISOR_SHA: raise SystemExit('supervisor drift')
    git = ['git','--no-lazy-fetch','-c','safe.directory='+str(repo),'-C',str(repo)]
    env = os.environ.copy(); env.update(GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GOTOOLCHAIN='local')
    if subprocess.check_output(git+['rev-parse',REVISION+'^{commit}'],env=env,text=True).strip()!=REVISION: raise SystemExit('revision unavailable')
    for suffix in (['diff','--quiet'],['diff','--cached','--quiet']): subprocess.run(git+suffix,env=env,check=True)
    out.mkdir(mode=0o700)
    work = pathlib.Path(tempfile.mkdtemp(prefix='razvilka-wg-cleanup-',dir='/tmp')).resolve()
    safe = True; rows=[]
    try:
        archive = work/'source.tar'
        with archive.open('xb') as f: subprocess.run(git+['archive',REVISION],env=env,stdout=f,check=True)
        source = work/'source'; source.mkdir(mode=0o700)
        with tarfile.open(archive) as tf: tf.extractall(source, filter='data')
        variants = {'candidate': {}, 'baseline': {}}; manifests = {}
        for path, pins in TARGETS.items():
            variants['candidate'][path] = (source/path).read_bytes()
            variants['baseline'][path] = subprocess.check_output(git+['show',BASE_REVISION+':'+path],env=env)
            for name in variants:
                if sha(variants[name][path]) != pins[name]: raise RuntimeError('exact kernel leaf source drift')
        for name, payloads in variants.items():
            write_variant(source, payloads); manifests[name]=files(source)
            (out/(name+'-source-manifest.json')).write_text(json.dumps(manifests[name],sort_keys=True)+'\n')
        assert_variant_manifests(manifests)
        proof={'revision':REVISION,'archive_sha256':sha(archive.read_bytes()),'only_variant_files':list(TARGETS),
               'variants':{name:{p:sha(b) for p,b in v.items()} for name,v in variants.items()},
               'baseline':'exact original kernel leaf bodies; all new helpers/methods/tests common in both source variants',
               'baseline_revision':BASE_REVISION,'supervisor_sha256':SUPERVISOR_SHA,
               'modes':['production','race'],'sequence':['baseline','candidate','candidate','baseline'],
               'original_driver':'scripts/test-managed-probe-lan-native.sh','LAN_CASE':'manual',
               'original_test_timeout_seconds':240,'internal_apply_budgets':'unchanged','execution':'pending'}
        (out/'source-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
        for control,body,expected in [('clean','exit 0\n',0),('failure','exit 1\n',1),('orphan','(trap "" TERM; exec setsid sleep 30) &\nexit 0\n',125)]:
            script=work/('control-'+control+'.sh'); script.write_text(body)
            folder=out/('control-'+control); folder.mkdir(mode=0o700); safe=False
            result=subprocess.run([sys.executable,str(supervisor),str(script),str(folder)],env=env,stdout=subprocess.DEVNULL)
            state=json.loads((folder/'supervisor.json').read_text()); safe=state.get('descendants_absent') is True
            valid=safe and result.returncode==expected and state.get('subreaper') is True
            if control=='orphan': valid=valid and state.get('forced_cleanup') is True and state.get('no_overlap_boundary') is False and state.get('adopted_children_reaped',0)>0
            else: valid=valid and state.get('no_overlap_boundary') is True and state.get('initial_exit_status')==expected
            if not valid: raise RuntimeError('supervisor control failed')
        # No inherited application selector, admission fixture, fault or budget.
        for name in list(env):
            if name.startswith('RAZVILKA_'): del env[name]
        env.update(RAZVILKA_MANAGED_PROBE_LAN_NATIVE='1',RAZVILKA_MANAGED_PROBE_LAN_CASE='manual',RAZVILKA_MANAGED_PROBE_CASE_SET='all')
        helper=work/'wg-inactivity-child'
        env['RAZVILKA_WG_INACTIVITY_HELPER']=str(helper)
        helper_sha=None
        stop=False
        for mode in proof['modes']:
            # Original cleanup contracts and actual protected held source first.
            # The tiny modeled metadata helper is always an ordinary stripped build;
            # only the parent tests/consumer use the requested race mode.
            if not stop:
                write_variant(source, variants['candidate'])
                gate=work/('gate-'+mode+'.sh')
                flag='-race' if mode=='race' else ''
                build_helper = ('go build -ldflags="-s -w" -o "$RAZVILKA_WG_INACTIVITY_HELPER" ./scripts/fixtures/wg-inactivity-child\n'
                                if mode == 'production' else '')
                helper_check = ('python3 - "$RAZVILKA_WG_INACTIVITY_HELPER" <<\'PY\'\n'
                    'import os,pathlib,stat,sys\n'
                    'p=pathlib.Path(sys.argv[1]); s=p.lstat()\n'
                    'if not p.is_absolute() or p!=p.resolve() or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or not 0<s.st_size<=16<<20 or not s.st_mode&0o111 or s.st_mode&0o022: raise SystemExit("private helper bounds")\n'
                    'print("actual_wg_comparison_helper ordinary_stripped=true bytes="+str(s.st_size))\nPY\n')
                gate.write_text('#!/bin/sh\nset -eu\nexport RAZVILKA_WG_INACTIVITY_READ_CHILD=1\n'+build_helper+helper_check+
                    'go test '+flag+' -ldflags="-s -w" -tags razvilka_native_fixture -count=1 -v -timeout=90s ./internal/dataplane -run \'^TestWGCleanupTool\'\n'+
                    'exec go test '+flag+' -ldflags="-s -w" -tags razvilka_native_fixture -count=1 -v -timeout=90s ./internal/startuptools -run \'^(TestWGCleanupToolObservationRequiresOriginalSourceTuple|TestNativeWGKernelLinkOriginalHeldSource)$\'\n')
                folder=out/('gate-'+mode); folder.mkdir(mode=0o700); safe=False
                gate_env=env.copy(); gate_env.update(GOMAXPROCS='2',GOFLAGS='-p=2')
                result=subprocess.run([sys.executable,str(supervisor),str(gate),str(folder)],env=gate_env,cwd=source,stdout=subprocess.DEVNULL)
                state=json.loads((folder/'supervisor.json').read_text()); safe=state.get('descendants_absent') is True
                log=(folder/'native.log').read_text(encoding='utf-8')
                capture=json.loads((folder/'log-capture.json').read_text())
                passed=result.returncode==0 and safe and state.get('no_overlap_boundary') is True and state.get('forced_cleanup') is False
                passed=passed and capture.get('eof_complete') is True and capture.get('io_error') is False and capture.get('truncated') is False
                passed=passed and gate_log_valid(log)
                if passed:
                    observed_helper = helper_identity(helper)
                    if helper_sha is not None and observed_helper['sha256'] != helper_sha: raise RuntimeError('helper changed between modes')
                    helper_sha = observed_helper['sha256']
                    (out/'helper-proof.json').write_text(json.dumps({**observed_helper,
                        'source_sha256':sha((source/'scripts/fixtures/wg-inactivity-child/main.go').read_bytes()),
                        'build':'ordinary go build -ldflags=-s -w; parent mode unchanged',
                        'role':'private metadata/diagnostic model only, never tool/profile/route evidence'},indent=2)+'\n')
                (folder/'gate-result.json').write_text(json.dumps({'pass':bool(passed),'exit':result.returncode,'original_context_seconds':20,'runner_timeout_seconds':90})+'\n')
                if files(source)!=manifests['candidate']: raise RuntimeError('source drift during prerequisite')
                if not passed: stop=True
            for i,variant in enumerate(proof['sequence'],1):
                row={'mode':mode,'sample':i,'variant':variant,'pass':False}; rows.append(row)
                if stop: row['not_run']='previous sample not demonstrably joined/clean'; continue
                folder=out/(mode+'-'+str(i)+'-'+variant); folder.mkdir(mode=0o700)
                write_variant(source, variants[variant])
                if files(source)!=manifests[variant]: raise RuntimeError('source drift before sample')
                if helper_identity(helper)['sha256'] != helper_sha: raise RuntimeError('helper changed before sample')
                env['RAZVILKA_MANAGED_PROBE_BUILD_MODE']=mode
                env['RAZVILKA_MANAGED_PROBE_PROFILE_OUTPUT']=str(folder/'profiles')
                safe=False; started=time.monotonic_ns()
                run=subprocess.run([sys.executable,str(supervisor),str(source/proof['original_driver']),str(folder)],env=env,cwd=source,stdout=subprocess.DEVNULL)
                row['driver_wall_including_build_ns']=time.monotonic_ns()-started; row['supervisor_exit']=run.returncode
                state=json.loads((folder/'supervisor.json').read_text()); safe=state.get('descendants_absent') is True
                row.update(classify(folder,run.returncode)); stop=not row['safe_next_sample']
                if files(source)!=manifests[variant]: raise RuntimeError('source drift after sample')
                if helper_identity(helper)['sha256'] != helper_sha: raise RuntimeError('helper changed after sample')
                (out/'samples.partial.json').write_text(json.dumps(rows,indent=2)+'\n')
        identities={mode:{variant:{(tuple(r.get('pprof_build_ids',[])),r.get('binary_bytes')) for r in rows if r['mode']==mode and r['variant']==variant} for variant in variants} for mode in proof['modes']}
        identity_valid=all(all(len(values)==1 and len(next(iter(values))[0])==1 and next(iter(values))[1] is not None for values in pair.values()) and next(iter(pair['candidate']))[0]!=next(iter(pair['baseline']))[0] for pair in identities.values())
        report={'source':proof,'samples':rows,'build_id_pairs_valid':identity_valid,'all_samples_pass':identity_valid and all(r['pass'] for r in rows),'limits':['No failed arm is censored or promoted; failure latency is not successful route latency.','Same host per population; compare variants only within mode, 2 samples each is not statistical speed proof.','Original tool/kernel/process checks remain; no actual router evidence.','CPU/counter values include cleanup and overlap; never sum cumulative profiles.','Binary SHA unavailable from unchanged driver; original bytes and pprof Build ID recorded.','Only the two original cleanup kernel leaves share a finite tool byte scope; all current/metadata/kernel reads and deadlines remain.', 'This manual full-flow comparison is separate from the original fullLAN24s rollback gate.']}
        report['raw']={p.relative_to(out).as_posix():sha(p.read_bytes()) for p in out.rglob('*') if p.is_file()}
        (out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
        return 0 if report['all_samples_pass'] else 1
    finally:
        if safe:
            if work.parent!=pathlib.Path('/tmp') or not work.name.startswith('razvilka-wg-cleanup-'): raise RuntimeError('cleanup boundary')
            shutil.rmtree(work)
        else: (out/'retained-source-workspace.txt').write_text(str(work)+'\n')

if __name__=='__main__': sys.exit(main())
