"""Bounded read-only GEN2 profile decoder; no Go build/binary required.
Schema: https://github.com/google/pprof/blob/main/proto/profile.proto
CPU samples are attribution of preparation+Run+join attempt, never wall readiness.
"""
import argparse, collections, gzip, hashlib, json, re
from pathlib import Path

def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data): raise ValueError('truncated varint')
        byte = data[pos]; pos += 1; value |= (byte & 127) << shift
        if byte < 128: return value, pos
    raise ValueError('varint overflow')

def fields(data):
    result = collections.defaultdict(list); pos = 0; count = 0
    while pos < len(data):
        count += 1
        if count > 1000000: raise ValueError('field count')
        key, pos = varint(data, pos); number, wire = key >> 3, key & 7
        if number == 0: raise ValueError('zero field')
        if wire == 0: value, pos = varint(data, pos)
        elif wire == 2:
            size, pos = varint(data, pos)
            if size > len(data) - pos: raise ValueError('truncated bytes')
            value = data[pos:pos+size]; pos += size
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if size > len(data) - pos: raise ValueError('truncated fixed field')
            value = data[pos:pos+size]; pos += size
        else: raise ValueError('unsupported wire')
        result[number].append(value)
    return result

def packed(values):
    result = []
    for value in values:
        if isinstance(value, int): result.append(value); continue
        pos = 0
        while pos < len(value):
            item, pos = varint(value, pos); result.append(item)
    return result

def analyze(path):
    if path.name != 'successor-run.cpu.pprof': raise ValueError('GEN2 basename required')
    with open(path, 'rb') as stream: compressed = stream.read((2 << 20) + 1)
    if len(compressed) > 2 << 20: raise ValueError('compressed bound')
    with gzip.open(path, 'rb') as stream: raw = stream.read((4 << 20) + 1)
    if len(raw) > 4 << 20: raise ValueError('decoded bound')
    profile = fields(raw); strings = [s.decode('utf8') for s in profile[6]]
    types = [fields(t) for t in profile[1]]
    indices = [i for i,t in enumerate(types) if strings[t[1][0]] == 'cpu' and strings[t[2][0]] == 'nanoseconds']
    if len(indices) != 1: raise ValueError('exact CPU sample type required')
    index = indices[0]
    funcs = {f[1][0]: strings[f[2][0]] for f in map(fields, profile[5])}
    locations = {l[1][0]: [funcs[fields(line)[1][0]] for line in l[4]] for l in map(fields, profile[4])}
    flat = collections.Counter(); cumulative = collections.Counter(); targets = collections.defaultdict(collections.Counter); total = 0
    allow = ('xrayDomainTCPExecutable).current', 'xrayDomainTCPImageRead).current', 'startuptools.hashImage', 'domainTCPPoolListenerWitness).current', 'domainTCPGlobalSuccessor).comparePrior', 'domainTCPGlobalSuccessor).counterfactualRows', 'domainTCPOriginalScope).compareStandby', 'netidentity.captureProc', 'heldReview).pathsCurrent', 'Lease).versionBatchCurrent')
    for sample in map(fields, profile[2]):
        values = packed(sample[2])
        if index >= len(values) or values[index] >= 1 << 63: raise ValueError('CPU value')
        value = values[index]; total += value
        stack = [name for loc in packed(sample[1]) for name in locations[loc]]
        if len(stack) > 512: raise ValueError('stack bound')
        if stack: flat[stack[0]] += value
        for name in set(stack): cumulative[name] += value
        for target in allow:
            found = next((i for i,name in enumerate(stack) if target in name), None)
            if found is not None:
                origins = [name for name in stack[found+10:] if any(token in name for token in ('domainTCPGlobalSuccessor)', 'domainTCPPoolListenerWitness)', 'domainTCPStandbyPoolEntry)', 'DomainTCPOriginalScope)', 'domainTCPPreparedCapture)', 'domainTCPOriginalCaptureResource)', 'syntheticBaseline'))]
                key = ' -> '.join(stack[found:found+10])
                if origins: key += ' | outer original callers: ' + ' -> '.join(origins[:12])
                targets[target][key] += value
    seconds = lambda c: {k:v/1e9 for k,v in c.most_common(40)}
    return dict(profile_sha256=hashlib.sha256(compressed).hexdigest(),profile_bytes=len(compressed),decoded_bytes=len(raw),total_cpu_seconds=total/1e9,profile_duration_seconds=profile.get(10,[0])[0]/1e9,profile_start_unix_nanoseconds=profile.get(9,[0])[0],flat_cpu_seconds=seconds(flat),cumulative_cpu_seconds=seconds(cumulative),target_parent_stacks_cpu_seconds={k:seconds(v) for k,v in targets.items()})

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('profile',type=Path);parser.add_argument('--log',required=True,type=Path);parser.add_argument('--sha',required=True);parser.add_argument('--run-id',required=True,type=int);parser.add_argument('--job-id',required=True,type=int);parser.add_argument('--architecture',default='not recorded');parser.add_argument('--cpu',default='not recorded');args=parser.parse_args()
    if not re.fullmatch(r'[a-f0-9]{40}',args.sha): raise ValueError('exact source SHA required')
    with args.log.open('rb') as stream: raw=stream.read((2 << 20) + 1)
    if len(raw)>2<<20: raise ValueError('log bound')
    log=raw.decode('utf-8-sig');markers=re.findall(r'GEN2_CPU_PROFILE_COMPLETE bytes=(\d+) joined=(true|false) overflow=(true|false) output_error=(true|false)',log)
    if len(markers)!=1: raise ValueError('one exact GEN2 completion marker required')
    size,joined,overflow,error=markers[0]
    if overflow!='false' or error!='false': raise ValueError('profile output refusal retained; not complete stream')
    out=analyze(args.profile)
    if int(size)!=out['profile_bytes']: raise ValueError('marker/file byte mismatch')
    out.update(sha=args.sha,run_id=args.run_id,job_id=args.job_id,architecture=args.architecture,cpu=args.cpu,log_sha256=hashlib.sha256(raw).hexdigest(),original_run_result_received=joined=='true',profile_window='GEN2 preparation + original Run through join attempt',limitations=['Go parent CPU only, excluding exec child CPU; cumulative stacks overlap and do not decompose wall latency.','Profile stop is not native cleanup, readiness, service or router proof.','GEN1 profiles cannot substitute for this GEN2 attribution; profiling overhead included.','Architecture/CPU must come from the same job provenance, never guessed from another runner.'])
    output=args.profile.parent/'successor-cpu-analysis.json';output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf8');print(output)
if __name__=='__main__':main()
