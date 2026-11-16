#!/usr/bin/env python3
"""Contracts of the embedded source/report helpers, not a simulated native PASS."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = (REPO / 'scripts/compare-nfq-runtime-read.sh').read_text(encoding='utf-8')
BLOCKS = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT, re.S)
PREPARE = next(b for b in BLOCKS if b.startswith('import difflib,'))
ANALYZE = next(b for b in BLOCKS if b.startswith('import hashlib,importlib.util,'))
REL = 'internal/strategylab/selected_candidate_runtime_observation.go'
ORIGINAL = (REPO / REL).read_bytes()
ACTOR = 'internal/app/strategy_managed_probe_native_linux_test.go'
ACTOR_BYTES = (REPO / ACTOR).read_bytes()
TEST = 'TestManagedStrategyProbeNativeConsumer'
SERVICE = 'actual isolated consumer: managed native validation + held source socket + queue200 + wrong-source negative + exact counters + TLS/catalogue predicates + soleWait/ACK + COMMON cleanup; platform/WAN classification modeled; no router/LAN acceptance'


class Contracts(unittest.TestCase):
    def fixture(self):
        tmp = tempfile.TemporaryDirectory(prefix='razvilka-nfq-comparison-contract-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        candidate, baseline, out = [root / name for name in ['candidate', 'baseline', 'out']]
        for p in [candidate, baseline, out]:
            p.mkdir()
        for p in [candidate, baseline]:
            (p / REL).parent.mkdir(parents=True)
            (p / REL).write_bytes(ORIGINAL)
            (p / ACTOR).parent.mkdir(parents=True)
            (p / ACTOR).write_bytes(ACTOR_BYTES)
            (p / 'unrelated.txt').write_bytes(b'unchanged source\n')
        helper = out / 'prepare-source.py'
        helper.write_text(PREPARE, encoding='utf-8', newline='\n')
        namespace = {'__name__': 'source_contract', '__file__': str(helper)}
        exec(compile(PREPARE, str(helper), 'exec'), namespace)
        return root, candidate, baseline, out, namespace

    def prepare(self, candidate, baseline, out, ns):
        old = os.environ.get('NFQ_READ_SHA')
        os.environ['NFQ_READ_SHA'] = 'a' * 40
        try:
            ns['prepare'](candidate, baseline, out)
        finally:
            if old is None:
                del os.environ['NFQ_READ_SHA']
            else:
                os.environ['NFQ_READ_SHA'] = old

    def test_exact_single_wrapper_delta(self):
        _, candidate, baseline, out, ns = self.fixture()
        self.prepare(candidate, baseline, out, ns)
        before = ns['inventory'](candidate)
        after = ns['inventory'](baseline)
        self.assertEqual([p for p in before if before[p] != after[p]], [REL])
        self.assertEqual((candidate / REL).read_bytes(), ORIGINAL)
        altered = (baseline / REL).read_text()
        self.assertIn('return r.materialCurrentWithRuntimeReadLocked(ctx, nil)', altered)
        self.assertNotIn('WithReadObservation', altered)
        self.assertEqual(altered[altered.index('func (r *SelectedCandidateReview) materialRuntimeCompare('):],
                         ORIGINAL.decode()[ORIGINAL.decode().index('func (r *SelectedCandidateReview) materialRuntimeCompare('):])
        d = json.loads((out / 'source-comparison.json').read_text())
        self.assertEqual(d['changed_files'], [REL])
        self.assertEqual(d['baseline_wrapper_sha256'], hashlib.sha256((baseline / REL).read_bytes()).hexdigest())
        self.assertEqual(d['patch_sha256'], hashlib.sha256((out / 'baseline.patch').read_bytes()).hexdigest())

    def test_source_drift_refuses_before_mutation(self):
        for kind in ['baseline-byte', 'candidate-pin', 'extra-file', 'budget-drift']:
            with self.subTest(kind=kind):
                _, candidate, baseline, out, ns = self.fixture()
                if kind == 'baseline-byte':
                    (baseline / 'unrelated.txt').write_bytes(b'foreign')
                elif kind == 'candidate-pin':
                    for p in [candidate, baseline]:
                        (p / REL).write_bytes(ORIGINAL + b'\n')
                elif kind == 'extra-file':
                    (baseline / 'extra').write_bytes(b'foreign')
                else:
                    for p in [candidate, baseline]:
                        (p / ACTOR).write_bytes(ACTOR_BYTES.replace(b'14*time.Second', b'15*time.Second'))
                before = ns['inventory'](baseline)
                with self.assertRaises(ValueError):
                    self.prepare(candidate, baseline, out, ns)
                self.assertEqual(before, ns['inventory'](baseline))

    def test_overlapping_outputs_refuse_before_mutation(self):
        for side in ['candidate', 'baseline']:
            with self.subTest(side=side):
                _, candidate, baseline, _, ns = self.fixture()
                inside = (candidate if side == 'candidate' else baseline) / 'inside'
                inside.mkdir()
                before = ns['inventory'](baseline)
                with self.assertRaises(ValueError):
                    self.prepare(candidate, baseline, inside, ns)
                self.assertEqual(before, ns['inventory'](baseline))

    def report_fixture(self, alteration=None):
        root, candidate, baseline, out, ns = self.fixture()
        self.prepare(candidate, baseline, out, ns)
        for i, side in enumerate(['baseline', 'candidate', 'candidate', 'baseline'], 1):
            p = out / f'{i:02d}-{side}'
            p.mkdir()
            passed = side == 'candidate'
            counts = '[7 7 0]' if passed else '[0 0 0]'
            lines = [f'=== RUN   {TEST}',
                     f'native measured runtime read frames [begun completed error] {counts}',
                     'native measured Execute 13.8s actual inventory ToolCheck calls 12 ToolCheck wall 4.2s',
                     'native measured Execute member-read attempts/returned-bytes 40 42000']
            if passed:
                lines.append(SERVICE)
            lines.append(f'--- {"PASS" if passed else "FAIL"}: {TEST} (15.00s)')
            (p / 'native.log').write_text('\n'.join(lines) + '\n', encoding='utf-8')
            (p / 'exit-status.txt').write_text('0' if passed else '1')
            (p / 'log-status.txt').write_text('0')
            (p / 'supervisor.json').write_text(json.dumps({'no_overlap_boundary': True, 'descendants_absent': True, 'forced_cleanup': False}))
        if alteration:
            alteration(out, candidate)
        env = dict(os.environ, NFQ_READ_OUTPUT=str(out), NFQ_READ_WORK=str(root), NFQ_READ_SHA='a'*40, NFQ_READ_MODE='production')
        result = subprocess.run([sys.executable, '-c', ANALYZE], env=env, capture_output=True, text=True, timeout=10)
        if not (out / 'comparison.json').exists():
            self.fail(result.stdout + result.stderr)
        return result, json.loads((out / 'comparison.json').read_text())

    def test_failed_baseline_remains_censored(self):
        result, report = self.report_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(report['comparison_valid'])
        self.assertTrue(report['all_candidate_samples_pass'])
        self.assertFalse(report['all_samples_pass'])
        for row in report['samples']:
            if row['side'] == 'baseline':
                self.assertEqual(row['status'], 'fail')
                self.assertTrue(row['elapsed_is_censored'])
            else:
                self.assertFalse(row['elapsed_is_censored'])

    def test_false_pass_refusals(self):
        for kind in ['candidate-fail', 'candidate-zero', 'candidate-errors', 'baseline-active', 'missing-service', 'unknown-cleanup', 'skip', 'wrong-test', 'missing-timing', 'source-mutation']:
            with self.subTest(kind=kind):
                def alter(out, candidate):
                    side = '01-baseline' if kind == 'baseline-active' else '02-candidate'
                    p = out / side
                    log = (p / 'native.log').read_text()
                    if kind == 'candidate-fail':
                        log = log.replace('--- PASS:', '--- FAIL:')
                        (p / 'exit-status.txt').write_text('1')
                    elif kind == 'candidate-zero':
                        log = log.replace('[7 7 0]', '[0 0 0]')
                    elif kind == 'candidate-errors':
                        log = log.replace('[7 7 0]', '[7 6 1]')
                    elif kind == 'baseline-active':
                        log = log.replace('[0 0 0]', '[7 7 0]')
                    elif kind == 'missing-service':
                        log = log.replace(SERVICE, '')
                    elif kind == 'unknown-cleanup':
                        (p / 'supervisor.json').write_text(json.dumps({'no_overlap_boundary': False}))
                    elif kind == 'skip':
                        log += '\n--- SKIP: unexpected (0.00s)\n'
                    elif kind == 'wrong-test':
                        log = log.replace(TEST, TEST + 'LateWaitCleanup')
                    elif kind == 'missing-timing':
                        log = log.replace('actual inventory ToolCheck calls', 'missing timing')
                    elif kind == 'source-mutation':
                        (candidate / 'unrelated.txt').write_bytes(b'changed after population')
                    (p / 'native.log').write_text(log, encoding='utf-8')
                result, report = self.report_fixture(alter)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(report['comparison_valid'])


if __name__ == '__main__':
    unittest.main()
