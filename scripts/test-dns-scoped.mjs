import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const require=createRequire(import.meta.url),m=require('../cmd/razvilka/web/dns-scoped.js');
let tests=0;const test=(name,fn)=>{fn();tests++;console.log('PASS',name);};
const view={available:true,state:'configured',config_revision:4,service_id:'telegram',profile_id:'private',client:'192.168.1.40',listener:'192.168.1.1:10553',ingress:'br0',profile_ids:['private'],candidates:[{service_id:'telegram',client:'192.168.1.40'}]};
const body=m.requestFor(view,'telegram','private',view.listener,view.ingress);
const response={ok:true,live_applied:false,review:{expected_revision:4,reviewed_digest:'a'.repeat(64)},plan:{ready:true,scoped_dns:{listener:view.listener,ingress:'br0',bindings:[{service_id:'telegram',profile_id:'private',client:view.client,domain:'telegram.org'}]}}};
test('bind apply to applied client',()=>assert.equal(body.dns_apply.client,view.client));
test('explicit confirmation after full scope review',()=>assert.equal(m.acceptReview(response,body,4).confirm,'APPLY_SCOPED_DNS'));
for(const [name,change] of [['profile',r=>r.plan.scoped_dns.bindings[0].profile_id='other'],['device',r=>r.plan.scoped_dns.bindings[0].client='192.168.1.41'],['service',r=>r.plan.scoped_dns.bindings[0].service_id='other'],['scope',r=>r.plan.scoped_dns.bindings=[]],['listener',r=>r.plan.scoped_dns.listener='0.0.0.0:10553'],['revision',r=>r.review.expected_revision=5],['digest',r=>r.review.reviewed_digest='invalid'],['mutation',r=>r.live_applied=true]])test('reject substituted '+name,()=>{const r=structuredClone(response);change(r);assert.throws(()=>m.acceptReview(r,body,4));});
test('reject changed current revision',()=>assert.throws(()=>m.acceptReview(response,body,5)));
test('reject unsupported build',()=>assert.throws(()=>m.requestFor({...view,available:false},'telegram','private',view.listener,'br0')));
test('reject unapplied device scope',()=>assert.throws(()=>m.requestFor({...view,candidates:[]},'telegram','private',view.listener,'br0')));
test('remove stopped policy without an apply candidate',()=>assert.deepEqual(m.requestFor({...view,state:'stopped',candidates:[]},'telegram','','','','remove').dns_apply,{action:'remove'}));
test('saved policy never means working',()=>assert.match(m.configuredText(view),/проверяется отдельно/));
test('stopped policy is visible',()=>assert.match(m.configuredText({...view,state:'stopped'}),/выключен/));
const job={id:7,mode:'service-dns-apply',state:'queued',service_id:'telegram',dns_apply_action:'apply',message:'Задание сохранено'};
test('validate public job identity',()=>assert.ok(m.validJob(job)));
test('completed job is history, not current health',()=>{
 const text=m.jobText({...job,state:'completed',message:'DNS применён и проверен с роутера'});
 assert.match(text,/Последнее задание/);assert.match(text,/Текущее состояние показано выше/);assert.doesNotMatch(text,/применён и проверен/);
});
test('reject different action',()=>assert.ok(!m.validJob({...job,dns_apply_action:'reset'})));
const source=readFileSync(new URL('../cmd/razvilka/web/dns-scoped.js',import.meta.url),'utf8');
const ids=['dnsScopedForm','dnsScopedFields','dnsScopedService','dnsScopedProfile','dnsScopedListener','dnsScopedIngress','dnsScopedCurrent','dnsScopedEligibility','dnsScopedPreview','dnsScopedRemove','dnsScopedConfirm','dnsScopedCancel','dnsScopedReview','dnsScopedStatus'];
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
for(const id of ids)test('unique element '+id,()=>assert.equal(html.split('id="'+id+'"').length-1,1));
test('shared reader, no independent polling',()=>assert.ok(!/setInterval|setTimeout|localStorage/.test(source)));
function fixture(){
 const elements=new Map(),requests=[],storage=new Map();
 for(const id of ids)elements.set(id,{value:({dnsScopedService:'telegram',dnsScopedProfile:'private',dnsScopedListener:view.listener,dnsScopedIngress:'br0'})[id]||'',innerHTML:'',textContent:'',hidden:false,disabled:false,events:{},addEventListener(type,fn){this.events[type]=fn;},replaceChildren(){this.innerHTML='';this.textContent='';}});
 const context={AbortController,console,crypto:webcrypto,sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},document:{getElementById:id=>elements.get(id)},state:{dns:{scoped:structuredClone(view),profiles:[{id:'private',name:'Приватный'}],service_drafts:{telegram:'private'}},status:{revision:4},services:[{id:'telegram',name:'Telegram'}]},workflowState:{epoch:1},workflowSession:epoch=>context.workflowState.epoch===epoch,workflowError:error=>error.message,renderDNS(){},renderStatus(){},showAuth(){context.workflowState.epoch++;},scheduleWorkspaceControl(){},workflowRequest:(path,options)=>new Promise((resolve,reject)=>requests.push({path,options,resolve,reject}))};
 vm.runInNewContext(source,context);return {c:context,e:id=>elements.get(id),requests,storage};
}
const tick=()=>new Promise(r=>setImmediate(r));
async function preview(f){
 f.e('dnsScopedForm').events.submit({preventDefault(){}});
 assert.equal(f.requests.at(-1).path,'/api/v1/dns/service-draft');
 f.requests.at(-1).resolve(f.c.state.dns);await tick();
 assert.equal(f.requests.at(-1).path,'/api/v1/dns/scoped/preview');
 f.requests.at(-1).resolve(response);await tick();
 assert.equal(f.e('dnsScopedConfirm').hidden,false);
}
for(const outcome of ['complete','lost-response','logout','cancel']){
 const f=fixture();await preview(f);
 const p=f.e('dnsScopedConfirm').events.click(),first=f.requests.at(-1);
 assert.equal(first.path,'/api/v1/dns/scoped/apply');
 if(outcome==='lost-response'){
  first.reject(new Error('timeout'));await p;
  const retry=f.e('dnsScopedConfirm').events.click();
  assert.equal(f.requests.at(-1).options.body,first.options.body,'lost response reuses exact key and review');
  f.requests.at(-1).resolve({persistent:true,job});await retry;
 }else if(outcome==='logout'){
  f.c.showAuth();first.resolve({persistent:true,job});await p;
  assert.equal(f.e('dnsScopedCurrent').textContent,'Войдите для просмотра DNS.');
  assert.equal(f.storage.size,0);assert.equal(f.e('dnsScopedConfirm').hidden,true);
  console.log('PASS late response after logout ignored');tests++;continue;
 }else{first.resolve({persistent:true,job});await p;}
 assert.equal(f.e('dnsScopedFields').disabled,true,'accepted job not completed');
 f.c.acceptDNSApplyJobs({durable_jobs:[{...job,state:'running'}]});
 if(outcome==='cancel'){
  const cancel=f.e('dnsScopedCancel').events.click();assert.match(f.requests.at(-1).path,/job_id=7/);
  f.requests.at(-1).resolve({durable_jobs:[{...job,state:'canceling'}]});await cancel;
  assert.equal(f.e('dnsScopedFields').disabled,true,'waits for joined cleanup');
 }
 f.c.acceptDNSApplyJobs({durable_jobs:[{...job,state:outcome==='cancel'?'canceled':'completed',message:'Завершено'}]});
 assert.equal(f.requests.at(-1).path,'/api/v1/dns');f.requests.at(-1).resolve(f.c.state.dns);await tick();
 assert.equal(f.e('dnsScopedFields').disabled,false);
 console.log('PASS browser '+outcome);tests++;
}
{
 const f=fixture();await preview(f);f.c.state.status.revision=5;f.c.renderStatus();
 assert.equal(f.e('dnsScopedConfirm').hidden,true);console.log('PASS changed revision invalidates review');tests++;
}
{
 const f=fixture();await preview(f);
 f.c.acceptDNSApplyJobs({durable_jobs:[{...job,state:'completed'}]});
 assert.equal(f.e('dnsScopedConfirm').hidden,false,'old history cannot consume new review');
 f.c.acceptDNSApplyJobs({durable_jobs:[{...job,id:8,state:'queued'}]});
 assert.equal(f.e('dnsScopedConfirm').hidden,true,'other tab pending operation invalidates review');
 console.log('PASS late history vs new active job');tests++;
}
console.log(`${tests} scoped DNS checks passed`);
