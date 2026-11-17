"""Read-only bounded attribution using existing pprof protobuf decoder."""
import collections,gzip,hashlib,importlib.util,json
from pathlib import Path
root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('decoder',root/'analyze-successor-cpu.py'); decoder=importlib.util.module_from_spec(spec); spec.loader.exec_module(decoder)
f=root/'live.cpu.pprof'
compressed=f.read_bytes(); assert len(compressed)<2<<20
with gzip.open(f,'rb') as stream: raw=stream.read((4<<20)+1)
assert len(raw)<=4<<20
fields=decoder.fields; packed=decoder.packed; p=fields(raw); strings=[s.decode('utf-8') for s in p[6]]
types=[fields(t) for t in p[1]]; idx=[i for i,t in enumerate(types) if strings[t[1][0]]=='cpu' and strings[t[2][0]]=='nanoseconds']; assert len(idx)==1
funcs={v[1][0]:strings[v[2][0]] for v in map(fields,p[5])}
locations={v[1][0]:[funcs[fields(line)[1][0]] for line in v[4]] for v in map(fields,p[4])}
bycaller=collections.Counter(); stacks=collections.Counter(); cpu=0; origin=0
for sample in map(fields,p[2]):
 value=packed(sample[2])[idx[0]]; assert 0<=value<1<<63; cpu+=value
 stack=[name for loc in packed(sample[1]) for name in locations[loc]]; assert len(stack)<=512
 found=next((i for i,name in enumerate(stack) if name.endswith('/components.originHash')),None)
 if found is not None:
  origin+=value; bycaller[stack[found+1] if found+1<len(stack) else '<root>']+=value
  stacks[' -> '.join(stack[found+1:found+9])]+=value
out={'sha':'5289a7d8cace5c63641d14218ca1f48b4d17fa2e','run_id':42680281173,'artifact':'mihomo-manual-http-5289a7d8cace5c63641d14218ca1f48b4d17fa2e','raw_sha256':hashlib.sha256(compressed).hexdigest(),'total_cpu_seconds':cpu/1e9,'origin_hash_cpu_seconds':origin/1e9,'duration_seconds':p[10][0]/1e9,'origin_direct_callers_cpu_seconds':{k:v/1e9 for k,v in bycaller.most_common()},'origin_caller_stacks_cpu_seconds':{k:v/1e9 for k,v in stacks.most_common(30)},'limitations':['Whole manual fixture CPU, not only Apply. Cumulative stacks overlap.','Parent Go CPU excludes exec children. Original scenario FAILED110s deadline.','Attribution only: no authority, skipped validation or performance gain inferred.']}
output=f.parent/'origin-cpu-analysis.json'; output.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8'); print(json.dumps({k:v for k,v in out.items() if k!='origin_caller_stacks_cpu_seconds'},indent=2))
