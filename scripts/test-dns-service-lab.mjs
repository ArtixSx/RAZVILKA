import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const require=createRequire(import.meta.url),m=require('../cmd/razvilka/web/dns-service-lab.js');let tests=0;
function test(name,fn){fn();tests++;console.log('PASS',name);}
const snapshot={profiles:[{id:'xbox-dns',provider_id:'xbox-dns'},{id:'lab',provider_id:'flashstart'},{id:'local',provider_id:'local'},{id:'missing',provider_id:'missing'}],providers:[{id:'xbox-dns',configured:true,doh:'https://xbox-dns.ru/dns-query',kind:'smart-dns-gateway'},{id:'flashstart',configured:true,doh:'https://example.org',scope:'negative-control'},{id:'local',configured:true,doh:'https://example.org',trusted_local:true}]};
test('only configured public non-negative DoH',()=>assert.deepEqual(m.profilesForLab(snapshot).map(p=>p.id),['xbox-dns']));
test('empty state',()=>assert.deepEqual(m.profilesForLab(null),[]));
test('explicit consent request',()=>assert.equal(m.requestFor('youtube',['xbox-dns'],2,true).confirm,'COMPARE_SERVICE_DNS'));
for(const [name,args] of [ ['no consent',['youtube',['xbox-dns'],1,false]],['no service',['',['xbox-dns'],1,true]],['empty profiles',['youtube',[],1,true]],['duplicates',['youtube',['xbox-dns','xbox-dns'],1,true]],['too many',['youtube',['a','b','c','d'],1,true]],['unsafe revision',['youtube',['a'],NaN,true]],['fraction revision',['youtube',['a'],1.5,true]],['negative revision',['youtube',['a'],-1,true]],['url input',['youtube',['https://example.org'],1,true]],['service injection',['<script>',['a'],1,true]] ])test(name,()=>assert.throws(()=>m.requestFor(...args)));
const result={service_verified:false,route_verified:false,eligible_for_apply:false,results:[{provider_id:'xbox-dns',family:'ipv4',status:'resolved',addresses:['<svg/onload=alert(1)>']} ]};
test('DNS result cannot be service PASS',()=>assert.match(m.resultMarkup(result),/не подтверждение/));
test('escape data',()=>assert.ok(!m.resultMarkup(result).includes('<svg/onload')));
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
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
for(const id of ['dc1Form','dc1Inputs','dc1Service','dc1Profiles','dc1Consent','dc1Results','dc1Submit','dc1Cancel','dc1Status'])test(id+' exists once',()=>assert.equal(html.split('id="'+id+'"').length-1,1));
test('script integrated with the interface cache version',()=>{
 const scriptVersion=html.match(/src="\/dns-service-lab.js\?v=([^"\s]+)"/)?.[1];
 const styleVersion=html.match(/href="\/interface.css\?v=([^"\s]+)"/)?.[1];
 assert.ok(scriptVersion);assert.equal(scriptVersion,styleVersion);
});
test('stylesheet compiled into existing bundle',()=>assert.match(readFileSync(new URL('../cmd/razvilka/web/interface.css',import.meta.url),'utf8'),/\.dc1-lab/));
const source=readFileSync(new URL('../cmd/razvilka/web/dns-service-lab.js',import.meta.url),'utf8');
test('no localStorage secrets or independent polling',()=>assert.ok(!/localStorage|setInterval|innerHTML\s*=\s*(response|result)\b/.test(source)));
function browserFixture(){
 const elements=new Map(),checked=[{value:'private'}];
 for(const id of ['dc1Form','dc1Inputs','dc1Service','dc1Profiles','dc1Consent','dc1Results','dc1Submit','dc1Cancel','dc1Status'])elements.set(id,{value:id==='dc1Service'?'youtube':'',checked:id==='dc1Consent',innerHTML:'',textContent:'',disabled:false,hidden:false,events:{},addEventListener(type,fn){this.events[type]=fn;},querySelectorAll(){return checked;},replaceChildren(){this.innerHTML='';}});
 let resolve;
 const context={AbortController,console,document:{getElementById:id=>elements.get(id)},state:{status:{revision:4},services:[{id:'youtube',name:'YouTube',probe_url:'https://www.youtube.com/'}],dns:{profiles:[{id:'private',name:'Приватный',provider_id:'cloudflare'}],providers:[{id:'cloudflare',configured:true,doh:'https://cloudflare-dns.com/dns-query'}]}},workflowState:{epoch:1},renderDNS(){},showAuth(){context.workflowState.epoch++;},workflowSession:epoch=>epoch===context.workflowState.epoch,workflowError:error=>error.message,workflowRequest:()=>new Promise(r=>{resolve=r;})};
 vm.runInNewContext(source,context);
 return {context,e:id=>elements.get(id),resolve:value=>resolve(value),submit:()=>elements.get('dc1Form').events.submit({preventDefault(){}})};
}
for(const mode of ['success','cancel','logout','changed-revision']){
 const f=browserFixture(),pending=f.submit();
 assert.equal(f.e('dc1Inputs').disabled,true);
 if(mode==='cancel')f.e('dc1Cancel').events.click();
 if(mode==='logout')f.context.showAuth();
 if(mode==='changed-revision')f.context.state.status.revision=5;
 // Deliberately resolve after abort: a late transport response is not success.
 f.resolve(response);await pending;
 assert.equal(f.e('dc1Inputs').disabled,false);
 assert.equal(f.e('dc1Results').innerHTML.length>0,mode==='success');
 if(mode==='success'){
  f.context.state.status.revision=5;f.context.renderDNS();
  assert.equal(f.e('dc1Results').innerHTML,'');
 } else if(mode==='cancel')assert.match(f.e('dc1Status').textContent,/отменено/);
 else if(mode==='logout')assert.equal(f.e('dc1Status').textContent,'');
 else assert.match(f.e('dc1Status').textContent,/Настройки изменились/);
 tests++;console.log('PASS async browser '+mode);
}
console.log(JSON.stringify({tests,status:'passed'}));
