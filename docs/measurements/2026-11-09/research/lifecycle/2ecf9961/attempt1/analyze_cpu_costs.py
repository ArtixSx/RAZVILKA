# Read-only profile attribution; schema https://github.com/google/pprof/blob/main/proto/profile.proto
import gzip,json,hashlib
from pathlib import Path
from collections import defaultdict
ROOT=Path(__file__).resolve().parent

def varint(b,p):
 v=0
 for shift in range(0,70,7):
  x=b[p];p+=1;v|=(x&127)<<shift
  if x<128:return v,p
 raise ValueError("varint")

def fields(b):
 d=defaultdict(list);p=0
 while p<len(b):
  key,p=varint(b,p);field,wire=key>>3,key&7
  if wire==0:v,p=varint(b,p)
  elif wire==2:
   n,p=varint(b,p);v=b[p:p+n];assert len(v)==n;p+=n
  elif wire in (1,5):n=8 if wire==1 else 4;v=b[p:p+n];p+=n
  else:raise ValueError(wire)
  d[field].append(v)
 return d

def packed(values):
 out=[]
 for v in values:
  if isinstance(v,int):out.append(v);continue
  p=0
  while p<len(v):x,p=varint(v,p);out.append(x)
 return out

results={}
for case in ['selected','canceled']:
 path=ROOT/(case+'-artifact')/'original-run.cpu.pprof'
 with gzip.open(path,'rb') as f:raw=f.read((4<<20)+1)
 assert len(raw)<=4<<20
 profile=fields(raw);strings=[x.decode() for x in profile[6]]
 types=[fields(x) for x in profile[1]]
 index=next(i for i,t in enumerate(types) if strings[t[1][0]]=='cpu' and strings[t[2][0]]=='nanoseconds')
 funcs={f[1][0]:strings[f[2][0]] for f in map(fields,profile[5])}
 locs={l[1][0]:[funcs[fields(line)[1][0]] for line in l[4]] for l in map(fields,profile[4])}
 total=0;cum=defaultdict(int);hashparents=defaultdict(int)
 for sample in map(fields,profile[2]):
  value=packed(sample[2])[index];total+=value
  stack=[fn for loc in packed(sample[1]) for fn in locs[loc]]
  for fn in set(stack):cum[fn]+=value
  target='github.com/ArtixSx/razvilka/internal/startuptools.hashImage'
  if target in stack:
   i=stack.index(target);hashparents[' -> '.join(stack[i+1:i+4])]+=value
 selected={k:v/1e9 for k,v in cum.items() if any(x in k for x in ['startuptools.hashImage','heldReview).unchanged','Lease).observationBytes','xrayDomainTCPImageRead).current','xrayDomainTCPResourceFiles).current','netidentity.captureProc','blockSHANI'])}
 results[case]={'profile_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'total_cpu_s':total/1e9,'cumulative_cpu_s':selected,'startup_hash_parent_stacks_cpu_s':{k:v/1e9 for k,v in sorted(hashparents.items(),key=lambda kv:-kv[1])},'limitation':'Whole Run CPU includes cleanup; cumulative functions overlap; not wall deadline or causal speed.'}
 print(case,total/1e9,selected)
(ROOT/'cpu-source-costs.json').write_text(json.dumps(results,indent=2)+'\n')
