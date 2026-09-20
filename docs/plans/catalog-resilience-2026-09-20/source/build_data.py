from pathlib import Path
from ipaddress import ip_network, collapse_addresses
import hashlib, json
ROOT = Path(__file__).resolve().parent
DOMAINS = '''cdn-telegram.org
comments.app
contest.com
fragment.com
graph.org
quiz.directory
t.me
tdesktop.com
telega.one
telegra.ph
telegram-cdn.org
telegram.dog
telegram.me
telegram.org
telegram.space
telesco.pe
tg.dev
ton.org
toncenter.com
tx.me
usercontent.dev
'''
OFFICIAL = '''91.108.56.0/22
91.108.4.0/22
91.108.8.0/22
91.108.16.0/22
91.108.12.0/22
149.154.160.0/20
91.105.192.0/23
91.108.20.0/22
185.76.151.0/24
2001:b28:f23d::/48
2001:b28:f23f::/48
2001:67c:4e8::/48
2001:b28:f23c::/48
2a0a:f280::/32
'''
COMMUNITY = '''91.105.192.0/23
91.108.4.0/22
91.108.8.0/21
91.108.16.0/21
91.108.56.0/22
95.161.64.0/20
149.154.160.0/20
185.76.151.0/24
2001:67c:4e8::/48
2001:b28:f23c::/47
2001:b28:f23f::/48
2a0a:f280::/32
'''
def nets(data):
    return [ip_network(x, strict=True) for x in data.splitlines() if x]
def canonical(xs):
    return [n for family in (4,6) for n in collapse_addresses(n for n in xs if n.version == family)]
def subtract(left, right):
    out = list(left)
    for b in right:
        new = []
        for a in out:
            if a.version != b.version or not a.overlaps(b):
                new.append(a)
            elif a.subnet_of(b):
                pass
            else:
                new.extend(a.address_exclude(b))
        out = new
    return [str(n) for n in canonical(out)]
for name, text in [('Telegram_V2Fly_domains.txt', DOMAINS), ('Telegram_official_CIDRs.txt', OFFICIAL)]:
    (ROOT / name).write_text(text, encoding='utf-8')
domain_bytes=DOMAINS.encode()
blob_hash=hashlib.sha1(b'blob '+str(len(domain_bytes)).encode()+b'\0'+domain_bytes).hexdigest()
assert blob_hash == 'aed880e37775c67556c4975ffebaf6c6681862bf', blob_hash
comparison = {
    'checked_date': '2026-09-20',
    'kind': 'local_set_comparison_of_retrieved_source_data_not_network_probe',
    'official_count': len(nets(OFFICIAL)),
    'loyalsoldier_and_metacubex_count': len(nets(COMMUNITY)),
    'official_canonical_count': len(canonical(nets(OFFICIAL))),
    'added_coverage_in_community': subtract(nets(COMMUNITY), nets(OFFICIAL)),
    'missing_coverage_in_community': subtract(nets(OFFICIAL), nets(COMMUNITY)),
}
assert comparison['added_coverage_in_community'] == ['95.161.64.0/20']
assert comparison['missing_coverage_in_community'] == []
(ROOT/'CIDR_COMPARISON.json').write_text(json.dumps(comparison, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
manifest = {
 'status': 'read_only_snapshots_and_codex_task_not_application_update',
 'date': '2026-09-20',
 'audited_razvilka_commit': '245e78a63038d287465337fbd6c2c4ebd7edbf3c',
 'sources': [
  {'file':'Telegram_V2Fly_domains.txt', 'url':'https://github.com/v2fly/domain-list-community/blob/master/data/telegram', 'git_blob_sha1': blob_hash, 'entries':len(DOMAINS.splitlines()), 'format':'domain-suffix-lines','license_file':'LICENSE_V2Fly.txt','coverage_note':'Source includes related ecosystem domains, not only the messaging app. Inspect before importing.'},
  {'file':'Telegram_official_CIDRs.txt','url':'https://core.telegram.org/resources/cidr.txt','entries':len(nets(OFFICIAL)),'format':'cidr-lines','transcription':'Values from the fetched text response, normalized LF and final newline. No cryptographic signature from Telegram claimed.'},
 ],
 'comparison_sources':[
  {'url':'https://github.com/Loyalsoldier/geoip/blob/release/text/telegram.txt', 'git_blob_sha1':'b2e4a09a0c7fc80d62acecb185f27e82f0570df5'},
  {'url':'https://github.com/MetaCubeX/meta-rules-dat/blob/meta/geo/geoip/telegram.list','git_blob_sha1':'c480679a86fb9bc916ac5a919dc16dfc550808bf'}
 ],
 'code_changes':False, 'router_tested':False, 'gateway_health_checked':False,
 'checksum_note':'SHA-256 below is integrity of this package, not an upstream publisher signature.'
}
for s in manifest['sources']:
    s['sha256']=hashlib.sha256((ROOT/s['file']).read_bytes()).hexdigest()
(ROOT/'SOURCE_MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
print(json.dumps({'domains':len(DOMAINS.splitlines()),'v2fly_blob_verified':True,'comparison':comparison},ensure_ascii=False,indent=2))
