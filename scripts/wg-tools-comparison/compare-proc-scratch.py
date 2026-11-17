#!/usr/bin/env python3
"""External diagnostic: same-source proc scratch full manual Apply ABBA; no checkout writes."""
import hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tarfile, tempfile, time

REVISION = 'b6d15c1b34a6275af35fa905eaac3614bd2ad76e'
BASE_REVISION = '3a9b0e1c5b1186f4fff812f084cbe6751d2a72b9'
TARGET = 'internal/dataplane/network_backend_proc_read_linux.go'
SUPERVISOR_SHA = '8b3c876a45462909a6b6442af10c3ac28a2713610a3d77cac8fc02a8c0d0567a'
CANDIDATE_SHA = '58d01bc2df5eaff94f8e0d2996caecee7fea3371054f19614e8e6fe9f8c1575c'
BASELINE_SHA = '431d4b35fbd781b346bee3b2f76293602bae157fd6c2a294b79fa41cb52ec13f'
TESTS = ['TestManagedProbeFailedCleanupTerminalVector', 'TestNativeFixturePhysicalSourceCopiesRefuse', 'TestManagedStrategyProbeNativeLANPhysical', 'TestManagedStrategyProbeNativeLANManualApply']

def sha(data): return hashlib.sha256(data).hexdigest()

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
    success = success and '--- SKIP:' not in log and not any(o[0]=='FAIL' for o in outcomes)
    boundary = supervisor.get('descendants_absent') is True and supervisor.get('no_overlap_boundary') is True and supervisor.get('forced_cleanup') is False
    capture_ok = capture.get('eof_complete') is True and capture.get('truncated') is False and capture.get('io_error') is False
    cleanup = 'actual_failed_apply_cleanup closed=true rolled_back=true independently_empty=true primary_apply_failed=true' in log
    completed_actor = any(o[1]==TESTS[-1] and o[0] in ('PASS','FAIL') for o in outcomes)
    unsafe = not boundary or not capture_ok or not completed_actor or (not success and not cleanup)
    build_ids=sorted(set(re.findall(r'^Build ID: (\S+)', log, re.M)))
    sizes=re.findall(r'^Actual compiled reader/consumer bytes: (\d+)$',log,re.M)
    profiles=len(build_ids)==1 and len(sizes)==1 and 0<int(sizes[0])<=64<<20 and '\nType: cpu\n' in log
    selected = [s for s in log.splitlines() if any(x in s for x in ('actual_wg_runtime_inactive', 'native actual HTTP', 'Managed NFQ original timing', 'Managed NFQ runtime apply refused', 'actual_failed_apply_cleanup', 'actual original LAN execution', 'Actual compiled reader/consumer bytes:'))]
    return {'pass': bool(success and boundary and capture_ok and profiles), 'safe_next_sample': not unsafe,
            'supervisor': supervisor, 'log_capture': capture, 'test_outcomes': outcomes,
            'failed_apply_independently_empty': cleanup, 'counters_and_stages': selected,
            'profile_and_size_valid':profiles,'binary_bytes':int(sizes[0]) if len(sizes)==1 else None,'pprof_build_ids':build_ids,
            'binary_sha256': None, 'binary_sha256_limit': 'unchanged driver removes private test ELF; only original byte count and pprof Build ID available'}

def main():
    if sys.platform != 'linux' or os.geteuid()!=0 or len(sys.argv)!=3: raise SystemExit('Linux root: compare-proc-scratch.py CHECKOUT NEW_OUTPUT')
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
    work = pathlib.Path(tempfile.mkdtemp(prefix='razvilka-proc-scratch-',dir='/tmp')).resolve()
    safe = True; rows=[]
    try:
        archive = work/'source.tar'
        with archive.open('xb') as f: subprocess.run(git+['archive',REVISION],env=env,stdout=f,check=True)
        source = work/'source'; source.mkdir(mode=0o700)
        with tarfile.open(archive) as tf: tf.extractall(source, filter='data')
        candidate=(source/TARGET).read_bytes(); old=subprocess.check_output(git+['show',BASE_REVISION+':'+TARGET],env=env)
        if sha(candidate)!=CANDIDATE_SHA or sha(old)!=BASELINE_SHA: raise RuntimeError('exact proc reader source drift')
        variants={'candidate':candidate,'baseline':old}; manifests={}
        for name,data in variants.items():
            (source/TARGET).write_bytes(data); manifests[name]=files(source)
            (out/(name+'-source-manifest.json')).write_text(json.dumps(manifests[name],sort_keys=True)+'\n')
        if [k for k in manifests['candidate'] if manifests['candidate'][k]!=manifests['baseline'][k]]!=[TARGET]: raise RuntimeError('source delta')
        proof={'revision':REVISION,'archive_sha256':sha(archive.read_bytes()),'only_variant_file':TARGET,'variants':{k:sha(v) for k,v in variants.items()},'baseline':'exact original private per-call scratch on otherwise identical candidate source','baseline_revision':BASE_REVISION,'supervisor_sha256':SUPERVISOR_SHA,'modes':['production','race'],'sequence':['baseline','candidate','candidate','baseline'],'original_driver':'scripts/test-managed-probe-lan-native.sh','LAN_CASE':'manual','original_test_timeout_seconds':240,'internal_apply_budgets':'unchanged','execution':'pending'}
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
        stop=False
        for mode in proof['modes']:
            # Prove current detached scratch/error contracts and original held
            # kernel source under each build mode before the full Apply arms.
            if not stop:
                (source/TARGET).write_bytes(candidate)
                gate=work/('gate-'+mode+'.sh')
                flag='-race' if mode=='race' else ''
                gate.write_text('#!/bin/sh\nset -eu\nexport RAZVILKA_WG_INACTIVITY_READ_CHILD=1\ngo test '+flag+' -ldflags="-s -w" -tags razvilka_native_fixture -count=1 -v -timeout=90s ./internal/dataplane -run \'^TestBackendInventoryProcRead|^TestBackendProcIOSourceParity$\'\nexec go test '+flag+' -ldflags="-s -w" -count=1 -v -timeout=90s ./internal/startuptools -run \'^TestNativeWGKernelLinkOriginalHeldSource$\'\n')
                folder=out/('gate-'+mode); folder.mkdir(mode=0o700); safe=False
                gate_env=env.copy(); gate_env.update(GOMAXPROCS='2',GOFLAGS='-p=2')
                result=subprocess.run([sys.executable,str(supervisor),str(gate),str(folder)],env=gate_env,cwd=source,stdout=subprocess.DEVNULL)
                state=json.loads((folder/'supervisor.json').read_text()); safe=state.get('descendants_absent') is True
                log=(folder/'native.log').read_text(encoding='utf-8')
                capture=json.loads((folder/'log-capture.json').read_text())
                passed=result.returncode==0 and safe and state.get('no_overlap_boundary') is True and state.get('forced_cleanup') is False
                passed=passed and capture.get('eof_complete') is True and capture.get('io_error') is False and capture.get('truncated') is False
                passed=passed and len(re.findall(r'^--- PASS: TestNativeWGKernelLinkOriginalHeldSource \([0-9.]+s\)$',log,re.M))==1 and '--- SKIP:' not in log and '--- FAIL:' not in log
                for test in ['TestBackendInventoryProcReadRefusals', 'TestBackendInventoryProcReadFDKeepsCallerOwnership', 'TestBackendInventoryProcReadInvalidEntryDoesNotRead', 'TestBackendInventoryProcReadScratchIsolation', 'TestBackendInventoryProcReadScratchNested', 'TestBackendProcIOSourceParity']:
                    passed=passed and len(re.findall(r'^--- PASS: '+test+r' \([0-9.]+s\)$',log,re.M))==1
                (folder/'gate-result.json').write_text(json.dumps({'pass':bool(passed),'exit':result.returncode,'original_context_seconds':20,'runner_timeout_seconds':90})+'\n')
                if files(source)!=manifests['candidate']: raise RuntimeError('source drift during prerequisite')
                if not passed: stop=True
            for i,variant in enumerate(proof['sequence'],1):
                row={'mode':mode,'sample':i,'variant':variant,'pass':False}; rows.append(row)
                if stop: row['not_run']='previous sample not demonstrably joined/clean'; continue
                folder=out/(mode+'-'+str(i)+'-'+variant); folder.mkdir(mode=0o700)
                (source/TARGET).write_bytes(variants[variant])
                if files(source)!=manifests[variant]: raise RuntimeError('source drift before sample')
                env['RAZVILKA_MANAGED_PROBE_BUILD_MODE']=mode
                safe=False; started=time.monotonic_ns()
                run=subprocess.run([sys.executable,str(supervisor),str(source/proof['original_driver']),str(folder)],env=env,cwd=source,stdout=subprocess.DEVNULL)
                row['driver_wall_including_build_ns']=time.monotonic_ns()-started; row['supervisor_exit']=run.returncode
                state=json.loads((folder/'supervisor.json').read_text()); safe=state.get('descendants_absent') is True
                row.update(classify(folder,run.returncode)); stop=not row['safe_next_sample']
                if files(source)!=manifests[variant]: raise RuntimeError('source drift after sample')
                (out/'samples.partial.json').write_text(json.dumps(rows,indent=2)+'\n')
        identities={mode:{variant:{(tuple(r.get('pprof_build_ids',[])),r.get('binary_bytes')) for r in rows if r['mode']==mode and r['variant']==variant} for variant in variants} for mode in proof['modes']}
        identity_valid=all(all(len(values)==1 and len(next(iter(values))[0])==1 and next(iter(values))[1] is not None for values in pair.values()) and next(iter(pair['candidate']))[0]!=next(iter(pair['baseline']))[0] for pair in identities.values())
        report={'source':proof,'samples':rows,'build_id_pairs_valid':identity_valid,'all_samples_pass':identity_valid and all(r['pass'] for r in rows),'limits':['No failed arm is censored or promoted; failure latency is not successful route latency.','Same host per population; compare variants only within mode, 2 samples each is not statistical speed proof.','Original tool/kernel/process checks remain; no actual router evidence.','CPU/counter values include cleanup and overlap; never sum cumulative profiles.','Binary SHA unavailable from unchanged driver; original bytes and pprof Build ID recorded.','Scratch reuse changes no read, observation or deadline; sync.Pool is GC-discardable and not a fixed total-memory bound.']}
        report['raw']={p.relative_to(out).as_posix():sha(p.read_bytes()) for p in out.rglob('*') if p.is_file()}
        (out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
        return 0 if report['all_samples_pass'] else 1
    finally:
        if safe:
            if work.parent!=pathlib.Path('/tmp') or not work.name.startswith('razvilka-proc-scratch-'): raise RuntimeError('cleanup boundary')
            shutil.rmtree(work)
        else: (out/'retained-source-workspace.txt').write_text(str(work)+'\n')

if __name__=='__main__': sys.exit(main())
