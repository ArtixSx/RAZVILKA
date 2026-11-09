import csv
import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = '363f433611620cda4d14db2d0a7ae2475b0278f1'
CANDIDATE = '4cc9f869974713c9cebd833fccca383c03c102b7'
METRICS = ['wall_monotonic_ms', 'check_latency_ms',
           'post_to_http_readback_monotonic_ms', 'queue_wait_ms',
           'enqueue_to_server_completion_ms', 'readback_http_ms',
           'cpu_self_user_ms', 'cpu_self_system_ms',
           'cpu_joined_children_user_ms', 'cpu_joined_children_system_ms',
           'observed_self_peak_rss_kib', 'observed_new_children_peak_rss_kib',
           'derived_cpu_self_total_ms', 'derived_cpu_joined_children_total_ms',
           'derived_cpu_self_and_joined_children_ms']

def stats(values):
    values = sorted(values)
    if not values:
        return {'n': 0, 'p50': None, 'p95': None}
    return {'n': len(values), 'p50': values[math.ceil(len(values) * .5)-1],
            'p95': values[math.ceil(len(values) * .95)-1]}

def load(path):
    with path.open(newline='', encoding='utf-8') as source:
        return list(csv.DictReader(source))

def summarize(rows, kind):
    for row in rows:
        row['derived_cpu_self_total_ms'] = str(float(row['cpu_self_user_ms']) + float(row['cpu_self_system_ms']))
        row['derived_cpu_joined_children_total_ms'] = str(float(row['cpu_joined_children_user_ms']) + float(row['cpu_joined_children_system_ms']))
        row['derived_cpu_self_and_joined_children_ms'] = str(float(row['derived_cpu_self_total_ms']) + float(row['derived_cpu_joined_children_total_ms']))
    expected = ['live', 'dead-service', 'cancel', 'dead-node'] if kind == 'check' else ['single', 'selected-batch', 'all-vless']
    assert len(rows) == len(expected) * 13
    assert set(r['scenario'] for r in rows) == set(expected)
    output = {}
    for scenario in expected:
        group = [r for r in rows if r['scenario'] == scenario]
        assert sorted(int(r['sample']) for r in group) == list(range(13))
        first = next(r for r in group if r['sample'] == '0')
        repeated = [r for r in group if r['phase'] == 'repeated']
        assert len(repeated) == 12 and first['phase'] != 'repeated'
        if kind == 'check':
            assert all(r['algorithm'] == 'current-reuse' for r in group)
            assert all(r['available'] == ('true' if scenario == 'live' else 'false') for r in group)
            assert all(r['cleanup'] == ('not_required' if scenario == 'dead-node' else 'verified') for r in group)
            if scenario == 'live':
                assert all(r['service_requests'] == '1' and not r['error_code'] for r in group)
        else:
            count = '1' if scenario == 'single' else '2'
            assert all(r['cleanup'] == 'verified' and r['native_checks'] == count and r['completed'] == count for r in group)
            for row in group:
                checks = json.loads(row['check_results_json'])
                assert len(checks) == int(count)
                for check in checks:
                    assert check['available'] and check['cleanup_status'] == 'verified'
                    assert not check['direct_leak'] and not check.get('error_code')
                    assert check['service_id'] == 'telegram' and check['test_level'] == 'service'
                    assert check['route_path_id'] == 'xray:' + check['node_id']
                    assert check['network_profile'] == 'wan-0123456789ab'
                    assert re.fullmatch(r'node-check-[a-f0-9]{24}', check['probe_id'])
                    evidence = check['evidence']
                    assert evidence['verdict'] == 'PASS' and evidence['service'] == 'telegram'
                    assert evidence['network_profile'] == check['network_profile']
                    assert all(evidence[key] == check['route_path_id'] for key in ['route_path_id', 'expected_route_path_id', 'observed_route_path_id'])
        for row in group:
            assert row['resource_schema'] == 'linux-rusage-observed-rss-v1'
            assert row['sampler_interval_ms'] == '10'
            assert int(row['rss_read_errors']) >= 0
        metrics = {}
        for key in METRICS:
            if key not in first:
                continue
            values = [float(r[key]) for r in repeated if r[key] != '']
            assert all(math.isfinite(v) and v >= 0 for v in values)
            metrics[key] = {'first': float(first[key]) if first[key] else None, 'repeated': stats(values)}
        stage_metrics = {}
        if kind == 'check':
            for row in repeated:
                for stage in json.loads(row['stages_json']):
                    stage_metrics.setdefault(stage['id'], []).append(stage.get('duration_ms', 0))
        output[scenario] = {'n': len(group), 'first_phase': first['phase'], 'metrics': metrics,
                            'repeated_stages': {k: stats(v) for k, v in stage_metrics.items()},
                            'rss_read_errors': sum(int(r['rss_read_errors']) for r in group)}
    return output

result = {'run_id': 42642213693, 'baseline': BASE, 'candidate': CANDIDATE,
          'algorithm': 'current-reuse', 'quantile': 'nearest-rank; first sample excluded from repeated N12',
          'limitations': ['baseline then candidate fixed order', 'cold fixture is not cold OS cache',
                          'controlled loopback namespace and WAN identity, not router/LAN',
                          'empty child RSS is missing observation, not zero memory'],
          'files': {}, 'revisions': {}}
for label, sha in [('baseline', BASE), ('candidate', CANDIDATE)]:
    directory = ROOT / label
    environment = (directory / 'environment.txt').read_text()
    assert re.search(r'^' + sha + r'$', environment, re.M)
    binary_hash = re.search(r'^([a-f0-9]{64})\s+.*xray$', environment, re.M).group(1)
    result['revisions'][label] = {'binary_sha256': binary_hash,
                                'check': summarize(load(directory / 'check-current-reuse.csv'), 'check'),
                                'queue': summarize(load(directory / 'queue-http-current.csv'), 'queue')}
    for path in directory.iterdir():
        if path.is_file():
            result['files'][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
assert result['revisions']['baseline']['binary_sha256'] == result['revisions']['candidate']['binary_sha256']
result['validation'] = 'PASS'
(ROOT / 'paired-analysis.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
for kind, metric in [('check', 'wall_monotonic_ms'), ('queue', 'enqueue_to_server_completion_ms')]:
    for scenario in result['revisions']['baseline'][kind]:
        values = [result['revisions'][v][kind][scenario]['metrics'][metric] for v in ['baseline', 'candidate']]
        print(kind, scenario, json.dumps(values))
print('PASS: rows, verdicts, cleanup, algorithm, identities and binary hash; paired-analysis.json written')
