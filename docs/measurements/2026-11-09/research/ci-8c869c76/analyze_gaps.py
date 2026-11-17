import csv
import datetime
import json
import math
from pathlib import Path

root = Path(__file__).resolve().parent
def dt(value):
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
def quantile(values):
    values = sorted(values)
    return {'n': len(values), 'p50': values[math.ceil(len(values)*.5)-1], 'p95': values[math.ceil(len(values)*.95)-1]} if values else {'n': 0}

out = {'basis': 'reconstructed UTC event gaps, not a new monotonic stage measurement',
       'quantile': 'nearest-rank, repeated N12 only', 'revisions': {}}
for revision in ['baseline', 'candidate']:
    rows = list(csv.DictReader((root/revision/'queue-http-current.csv').open()))
    out['revisions'][revision] = {}
    for scenario in ['single', 'selected-batch', 'all-vless']:
        spans = {'post_to_first_check_ms': [], 'inter_check_gap_ms': [], 'last_check_to_readback_ms': []}
        for row in rows:
            if row['scenario'] != scenario or row['phase'] != 'repeated':
                continue
            checks = sorted(json.loads(row['check_results_json']), key=lambda check: check['started_at'])
            spans['post_to_first_check_ms'].append((dt(checks[0]['started_at'])-dt(row['post_started_utc'])).total_seconds()*1000)
            spans['last_check_to_readback_ms'].append((dt(row['http_received_utc'])-dt(checks[-1]['finished_at'])).total_seconds()*1000)
            if len(checks) == 2:
                spans['inter_check_gap_ms'].append((dt(checks[1]['started_at'])-dt(checks[0]['finished_at'])).total_seconds()*1000)
        out['revisions'][revision][scenario] = {key: quantile(values) for key, values in spans.items()}
(root/'queue-gap-analysis.json').write_text(json.dumps(out, indent=2))
print(json.dumps(out['revisions']))
