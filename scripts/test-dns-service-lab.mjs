import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const require=createRequire(import.meta.url),m=require('../cmd/razvilka/web/dns-service-lab.js');let tests=0;
function test(name,fn){fn();tests++;console.log('PASS',name);}
const snapshot={profiles:[{id:'xbox-dns',provider_id:'xbox-dns'},{id:'lab',provider_id:'flashstart'},{id:'local',provider_id:'local'},{id:'missing',provider_id:'missing'}],providers:[{id:'xbox-dns',configured:true,doh:'https://xbox-dns.ru/dns-query',kind:'smart-dns-gateway'},{id:'flashstart',configured:true,doh:'https://example.org',scope:'negative-control'},{id:'local',configured:true,doh:'https://example.org',trusted_local:true}]};
test('only configured public non-negative DoH',()=>assert.deepEqual(m.profilesForLab(snapshot).map(p=>p.id),['xbox-dns']));
test('empty state',()=>assert.deepEqual(m.profilesForLab(null),[]));
test('explicit consent request',()=>assert.equal(m.requestFor('youtube',['xbox-dns'],2,true).confirm,'COMPARE_SERVICE_DNS'));
test('HTTPS has explicit intent',()=>assert.equal(m.requestFor('youtube',['xbox-dns'],2,true,true).confirm,'COMPARE_SERVICE_DNS_AND_HTTPS'));
test('HTTPS limits DNS shortlist to two',()=>assert.throws(()=>m.requestFor('youtube',['a','b','c'],2,true,true)));
for(const [name,args] of [ ['no consent',['youtube',['xbox-dns'],1,false]],['no service',['',['xbox-dns'],1,true]],['empty profiles',['youtube',[],1,true]],['duplicates',['youtube',['xbox-dns','xbox-dns'],1,true]],['too many',['youtube',['a','b','c','d'],1,true]],['unsafe revision',['youtube',['a'],NaN,true]],['fraction revision',['youtube',['a'],1.5,true]],['negative revision',['youtube',['a'],-1,true]],['url input',['youtube',['https://example.org'],1,true]],['service injection',['<script>',['a'],1,true]] ])test(name,()=>assert.throws(()=>m.requestFor(...args)));
const result={service_verified:false,route_verified:false,eligible_for_apply:false,results:[{provider_id:'xbox-dns',family:'ipv4',status:'resolved',addresses:['<svg/onload=alert(1)>']} ]};
test('DNS result cannot be service PASS',()=>assert.match(m.resultMarkup(result),/не подтверждение/));
test('escape data',()=>assert.ok(!m.resultMarkup(result).includes('<svg/onload')));
test('explain local resolver failure without blaming the site',()=>assert.match(m.resultMarkup({...result,results:[{status:'error',addresses:[],error_code:'DNS_BOOTSTRAP_FAILED'}]}),/Локальный DNS не смог найти адрес провайдера/));
for(const key of ['service_verified','route_verified','eligible_for_apply'])test('reject claimed '+key,()=>assert.throws(()=>m.resultMarkup({...result,[key]:true})));
test('missing result',()=>assert.throws(()=>m.resultMarkup({})));
const body=m.requestFor('youtube',['private'],4,true);
const response={ok:true,live_applied:false,service_id:'youtube',config_revision:4,result:{service_verified:false,route_verified:false,eligible_for_apply:false,results:['ipv4','ipv6'].map(family=>({profile_id:'private',provider_id:'cloudflare',family,status:'no-address',addresses:[]}))}};
test('bind complete reply to selected profiles and revision',()=>assert.match(m.acceptResponse(response,body,4),/DNS-ответы/));
test('reject changed current revision',()=>assert.throws(()=>m.acceptResponse(response,body,5)));
test('reject changed backend revision',()=>assert.throws(()=>m.acceptResponse({...response,config_revision:5},body,4)));
test('reject missing backend revision',()=>assert.throws(()=>m.acceptResponse({...response,config_revision:undefined},body,4)));
test('reject partial profile batch',()=>assert.throws(()=>m.acceptResponse({...response,result:{...response.result,results:response.result.results.slice(0,1)}},body,4)));
test('reject duplicate family hiding missing answer',()=>assert.throws(()=>m.acceptResponse({...response,result:{...response.result,results:[response.result.results[0],response.result.results[0]]}},body,4)));
test('reject substituted profile',()=>assert.throws(()=>m.acceptResponse({...response,result:{...response.result,results:response.result.results.map(row=>({...row,profile_id:'other'}))}},body,4)));
const addressRow={profile_id:'private',family:'ipv4',status:'resolved',addresses:['1.1.1.1','8.8.8.8'],answer_fingerprint:'sha256:fixture'};
const check={profile_id:'private',family:'ipv4',answer_fingerprint:'sha256:fixture',address_count:2,result:{address:'1.1.1.1',application_path:'system-routing-unverified',route_verified:false,service_verified:true,tls_verified:true,status:'pass',tcp_ms:3,tls_ms:5,ttfb_ms:9}};
test('HTTPS proves only its address',()=>assert.match(m.addressChecksMarkup([check],[addressRow]),/1 из 2 адресов/));
for(const [name,change] of [['substituted address',c=>c.result.address='8.8.8.8'],['missing TLS',c=>c.result.tls_verified=false],['invented route',c=>c.result.route_verified=true],['different DNS generation',c=>c.answer_fingerprint='other'],['unmeasured count',c=>c.address_count=1]])test('reject '+name,()=>{const c=structuredClone(check);change(c);assert.throws(()=>m.addressChecksMarkup([c],[addressRow]));});
test('missing HTTPS observation is not success',()=>assert.throws(()=>m.addressChecksMarkup([],[addressRow])));
test('expired answer explained',()=>assert.match(m.addressChecksMarkup([{...check,result:{...check.result,service_verified:false,status:'not-checked',error_code:'DNS_ANSWER_EXPIRED'}}],[addressRow]),/Срок DNS-ответа истёк/));
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
for(const id of ['dc1Form','dc1Inputs','dc1Service','dc1Profiles','dc1Consent','dc1Results','dc1Submit','dc1Cancel','dc1Status'])test(id+' exists once',()=>assert.equal(html.split('id="'+id+'"').length-1,1));
test('script integrated with the interface cache version',()=>{
 const scriptVersion=html.match(/src="\/dns-service-lab.js\?v=([^"\s]+)"/)?.[1];
 const styleVersion=html.match(/href="\/interface.css\?v=([^"\s]+)"/)?.[1];
 assert.ok(scriptVersion);assert.equal(scriptVersion,styleVersion);
});
test('stylesheet compiled into existing bundle',()=>assert.match(readFileSync(new URL('../cmd/razvilka/web/interface.css',import.meta.url),'utf8'),/\.dc1-lab/));
const source=readFileSync(new URL('../cmd/razvilka/web/dns-service-lab.js',import.meta.url),'utf8');
test('no independent polling or raw result HTML',()=>assert.ok(!/localStorage|setInterval|setTimeout|innerHTML\s*=\s*(response|result)\b/.test(source)));
function browserFixture(){
 const elements=new Map(),checked=[{value:'private',checked:true}],requests=[],storage=new Map();
 for(const id of ['dc1Form','dc1Inputs','dc1Service','dc1Profiles','dc1Consent','dc1VerifyService','dc1Results','dc1Submit','dc1Cancel','dc1Status'])elements.set(id,{value:id==='dc1Service'?'youtube':'',checked:id==='dc1Consent',innerHTML:'',textContent:'',disabled:false,hidden:false,events:{},addEventListener(type,fn){this.events[type]=fn;},querySelectorAll(selector){return selector==='input:checked'?checked.filter(x=>x.checked):checked;},replaceChildren(){this.innerHTML='';}});
 let resolve,reject,refreshes=0;
 const context={AbortController,console,crypto:webcrypto,sessionStorage:{getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)},document:{getElementById:id=>elements.get(id)},state:{status:{revision:4},services:[{id:'youtube',name:'YouTube',probe_url:'https://www.youtube.com/'}],dns:{profiles:[{id:'private',name:'Приватный',provider_id:'cloudflare'}],providers:[{id:'cloudflare',configured:true,doh:'https://cloudflare-dns.com/dns-query'}]}},workflowState:{epoch:1},renderDNS(){},showAuth(){context.workflowState.epoch++;},workflowSession:epoch=>epoch===context.workflowState.epoch,workflowError:error=>error.message,scheduleWorkspaceControl(){refreshes++;},workflowRequest:(path,options)=>{requests.push({path,...options});return new Promise((yes,no)=>{resolve=yes;reject=no;});}};
 vm.runInNewContext(source,context);
 return {context,requests,refreshes:()=>refreshes,e:id=>elements.get(id),resolve:value=>resolve(value),reject:error=>reject(error),submit:()=>elements.get('dc1Form').events.submit({preventDefault(){}})};
}
const dnsJob={id:42,mode:'service-dns-compare',state:'queued',dns_request:body,message:'Задание сохранено на роутере'};
test('job descriptor binds its request',()=>assert.deepEqual(m.requestFromJob(dnsJob),body));
test('runtime action cannot be interpreted as DNS',()=>assert.throws(()=>m.requestFromJob({...dnsJob,mode:'service-stop'})));
for(const mode of ['success','cancel','logout','changed-revision','missing-result','malformed-result']){
 const f=browserFixture(),pending=f.submit();
 assert.equal(f.e('dc1Inputs').disabled,true);
 assert.equal(f.e('dc1Cancel').hidden,true);
 f.resolve({persistent:true,job:dnsJob});await pending;
 assert.equal(f.e('dc1Results').innerHTML,'');
 assert.equal(f.e('dc1Inputs').disabled,true,'202 is not completed');
 assert.match(f.e('dc1Status').textContent,/Вкладку можно закрыть/);
 f.context.acceptDNSLabJobs({durable_jobs:[{...dnsJob,state:'running'}]});
 let cancel;
 if(mode==='cancel'){
  cancel=f.e('dc1Cancel').events.click();
  assert.equal(f.requests.at(-1).method,'DELETE');
  assert.match(f.requests.at(-1).path,/job_id=42$/);
  f.resolve({durable_jobs:[{...dnsJob,state:'canceling'}]});await cancel;
  assert.equal(f.e('dc1Inputs').disabled,true,'cancel request must join router cleanup');
 }
 if(mode==='logout')f.context.showAuth();
 if(mode==='changed-revision')f.context.state.status.revision=5;
 const result=mode==='missing-result'?undefined:mode==='malformed-result'?{...response,service_id:'different'}:response;
 if(mode!=='logout')f.context.acceptDNSLabJobs({durable_jobs:[{...dnsJob,state:mode==='cancel'?'canceled':'completed',message:'Проверка отменена.',dns_result:result}]});
 assert.equal(f.e('dc1Inputs').disabled,false);
 assert.equal(f.e('dc1Results').innerHTML.length>0,mode==='success');
 if(mode==='success'){
  f.context.state.status.revision=5;f.context.renderDNS();
  assert.equal(f.e('dc1Results').innerHTML,'');
 } else if(mode==='cancel')assert.match(f.e('dc1Status').textContent,/отменена/);
 else if(mode==='logout')assert.equal(f.e('dc1Status').textContent,'');
 else if(mode==='changed-revision')assert.match(f.e('dc1Status').textContent,/Настройки изменились/);
 else if(mode==='missing-result')assert.match(f.e('dc1Status').textContent,/подробности уже недоступны/);
 else assert.match(f.e('dc1Status').textContent,/не соответствует/);
 tests++;console.log('PASS async browser '+mode);
}
{
 const f=browserFixture(),first=f.submit();
 f.reject(Error('connection lost'));await first;
 const key=JSON.parse(f.requests[0].body).idempotency_key;
 const retry=f.submit();assert.equal(JSON.parse(f.requests[1].body).idempotency_key,key);
 f.resolve({persistent:true,job:dnsJob});await retry;
 f.context.acceptDNSLabJobs({durable_jobs:[{...dnsJob,state:'completed',dns_result:response}]});
 const next=f.submit();assert.notEqual(JSON.parse(f.requests[2].body).idempotency_key,key);
 f.resolve({persistent:true,job:{...dnsJob,id:43}});await next;
 tests++;console.log('PASS lost reply reuses token; completed observation allows new comparison');
}
{
 const f=browserFixture(),pending=f.submit();f.context.showAuth();
 f.resolve({persistent:true,job:dnsJob});await pending;
 assert.equal(f.e('dc1Results').innerHTML,'');assert.equal(f.e('dc1Status').textContent,'');
 assert.equal(f.requests.length,1,'logout must not send cancel');
 f.context.acceptDNSLabJobs({durable_jobs:[{...dnsJob,state:'completed',dns_result:response}]});
 assert.ok(f.e('dc1Results').innerHTML.length>0,'next authenticated shared refresh retrieves router result');
 tests++;console.log('PASS logout ignores late ACK; next login restores result without POST');
}
console.log(JSON.stringify({tests,status:'passed'}));
