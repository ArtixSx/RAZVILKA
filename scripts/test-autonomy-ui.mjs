import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
const require=createRequire(import.meta.url);
const {validatePolicy,validateWindow,websiteDefinition,minutes,splitValues,escapeHTML}=require('../cmd/razvilka/web/autonomy-ui.js');
let count=0;
function test(name,fn){fn();count++;console.log(`PASS ${name}`);}
function policy(){return {schema:1,revision:1,setup_complete:true,enabled:true,timezone:'Europe/Berlin',all_lan:false,default_sources:['192.168.1.50/32'],source_ids:['feed-fixture'],protocols:['vless','hysteria2','tuic','shadowsocks'],preferred_routes:['nfqws2','usque'],check_seconds:120,reserve_seconds:300,reserve_target:3,candidates_per_round:2,failure_confirm_seconds:20,max_switches_per_hour:6,application:{mode:'check',start:'03:00',end:'04:00',days:[1,2,3,4,5]},components:{mode:'check',start:'04:00',end:'05:00',days:[0,6]}};}
test('valid policy',()=>assert.equal(validatePolicy(policy()).reserve_target,3));
for(const [name,change] of [
 ['empty scope',p=>p.default_sources=[]],['ambiguous scope',p=>p.all_lan=true],['global CIDR',p=>p.default_sources=['0.0.0.0/0']],['domain as source',p=>p.default_sources=['google.com']],['localhost',p=>p.default_sources=['127.0.0.1']],['no sources or local routes',p=>{p.source_ids=[];p.preferred_routes=[]}],['source URL not ID',p=>p.source_ids=['https://private/?key=123']],['unknown protocol',p=>p.protocols=['trojan']],['empty protocol',p=>p.protocols=[]],['fast check',p=>p.check_seconds=1],['fast reserve',p=>p.reserve_seconds=60],['unbounded batch',p=>p.candidates_per_round=99],['unbounded reserve',p=>p.reserve_target=99],['no zone',p=>p.timezone=''],['unknown zone',p=>p.timezone='No/SuchZone'],['local zone',p=>p.timezone='Local'],['unsupported install',p=>p.application.mode='install'],['unsupported component prepare',p=>p.components.mode='prepare'],['empty days',p=>p.application.days=[]],['equal window',p=>p.application.end=p.application.start],['bad time',p=>p.application.start='24:00'],['unknown preferred',p=>p.preferred_routes=['shell']],['bad switches',p=>p.max_switches_per_hour=100],['bad quorum',p=>p.failure_confirm_seconds=1]
])test(name,()=>{const p=policy();change(p);assert.throws(()=>validatePolicy(p));});
test('local routes do not require subscriptions',()=>{const p=policy();p.source_ids=[];assert.doesNotThrow(()=>validatePolicy(p))});
test('explicit all LAN',()=>{const p=policy();p.all_lan=true;p.default_sources=[];assert.doesNotThrow(()=>validatePolicy(p));});
test('cross midnight',()=>{const p=policy();p.application.start='23:50';p.application.end='01:10';assert.doesNotThrow(()=>validatePolicy(p));});
test('prepare only application',()=>{const p=policy();p.application.mode='prepare';assert.doesNotThrow(()=>validatePolicy(p));});
for(const input of ['http://example.org','https://name:secret@example.org','https://localhost','https://192.168.1.1','https://[::1]','https://host.local','https://example.org:8443','javascript:alert(1)','']) test(`reject website ${input}`,()=>assert.throws(()=>websiteDefinition('Site',input)));
test('generic service no hardcoding',()=>assert.deepEqual(websiteDefinition('Новый произвольный сервис','www.example.org/account?secret=x').domains,['www.example.org']));
test('no query secret in probe',()=>assert.equal(websiteDefinition('Site','https://example.org/path?token=hidden').probe_url,'https://example.org/'));
test('normalizes hostname',()=>assert.equal(websiteDefinition('Site','HTTPS://ExAmPlE.org.').domains[0],'example.org'));
test('missing name',()=>assert.throws(()=>websiteDefinition('','example.org')));
test('safe escaping',()=>assert.equal(escapeHTML('<img src=x onerror="bad">'), '&lt;img src=x onerror=&quot;bad&quot;&gt;'));
test('deduplicates user selection',()=>assert.deepEqual(splitValues('a,b; a\n c'),['a','b','c']));
test('strict minutes',()=>assert.equal(minutes('02:55'),175));
test('invalid minute',()=>assert.equal(minutes('24:00'),-1));
console.log(`AUTONOMY_UI_PURE_TESTS=${count}`);
