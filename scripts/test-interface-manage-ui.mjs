import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/interface.js',import.meta.url),'utf8');
const fn=source.match(/async function interfaceManage\([^]*?\n}/)[0];
function fixture(){
 const calls=[];let decide;
 const c={state:{authenticated:true,currentView:'services',services:[{id:'site',name:'Сайт',custom:true}]},interfaceState:{authEpoch:1,authRevoked:false,inspector:'site'},consoleSnapshot:{policy:{setup_complete:true,revision:3},services:{site:{enabled:true,sources:['192.0.2.1']}}},
 confirm:()=>{throw Error('native confirm must not run');},askConfirmation:()=>new Promise(resolve=>decide=resolve),
 interfaceRequest:async(path,options)=>{calls.push({path,options});return c.consoleSnapshot;},refreshCoreAfterEdit:async()=>{},window:{dispatchEvent(){}},CustomEvent:class{},encodeURIComponent,$:()=>({open:false}),interfaceUpdateInspector(){},consoleText(){}};
 vm.createContext(c);vm.runInContext(fn,c);return {c,calls,answer:value=>decide(value)};
}
for(const outcome of ['cancel','accept','revision','definition','managed','navigation','inspector','logout']){
 const f=fixture();const pending=f.c.interfaceManage('site',false,true);await f.c.interfaceManage('site',false,true);assert.equal(f.calls.length,0,'duplicate confirmation/write before consent');
 if(outcome==='revision')f.c.consoleSnapshot.policy.revision++;
 if(outcome==='definition')f.c.state.services[0].name='Новый состав';
 if(outcome==='managed')f.c.consoleSnapshot.services.site.sources=[];
 if(outcome==='navigation')f.c.state.currentView='settings';
 if(outcome==='inspector')f.c.interfaceState.inspector=null;
 if(outcome==='logout'){f.c.interfaceState.authEpoch++;f.c.interfaceState.authRevoked=true;f.c.state.authenticated=false;f.c.interfaceState.manageRequest=null;}
 f.answer(outcome!=='cancel');const result=await pending.catch(error=>error);
 if(['revision','definition','managed','navigation','inspector'].includes(outcome))assert.match(result.message,/изменились/);
 assert.equal(f.calls.length,outcome==='accept'?2:0,'incorrect mutation authority: '+outcome);
 if(['accept','cancel','logout'].includes(outcome))assert.equal(result,outcome==='accept');
 if(outcome==='accept'){assert.equal(f.calls[0].options.method,'DELETE');assert.deepEqual(JSON.parse(f.calls[0].options.body),{expected_revision:3,confirm:'REMOVE_SERVICE',delete_definition:false});}
 assert.equal(f.c.interfaceState.manageRequest,null);
}
{
 const f=fixture();let resolveOld,resolveNew;f.c.askConfirmation=()=>new Promise(resolve=>resolveOld=resolve);
 const pendingOld=f.c.interfaceManage('site',false,true);f.c.interfaceState.authEpoch++;f.c.interfaceState.manageRequest=null;
 f.c.askConfirmation=()=>new Promise(resolve=>resolveNew=resolve);
 const pendingNew=f.c.interfaceManage('site',false,true);const owner=f.c.interfaceState.manageRequest;
 resolveOld(true);await pendingOld;assert.equal(f.c.interfaceState.manageRequest,owner,'old confirmation cleared new session operation');assert.equal(f.calls.length,0);
 resolveNew(false);await pendingNew;assert.equal(f.c.interfaceState.manageRequest,null);
}
console.log('PASS service removal: async consent, cancellation, single flight, stale service/view/revision and auth ownership');
{
 const f=fixture();const pending=f.c.interfaceManage('site',false,true,true);f.answer(true);assert.equal(await pending,true);
 assert.equal(JSON.parse(f.calls[0].options.body).delete_definition,true,'custom deletion must explicitly request definition removal after route removal');
}
{
 const f=fixture();f.c.state.services[0].custom=false;
 await assert.rejects(f.c.interfaceManage('site',false,true,true),/пользовательские/);
 assert.equal(f.calls.length,0,'built-in catalogue definitions must not be deleted');
}
console.log('PASS custom deletion uses reviewed queued removal; built-in definition deletion refused');
{
 const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
 const deletion=app.match(/async function deleteCustomService\([^]*?\n}/)[0];
 for(const outcome of ['cancel','accept','pending','changed','logout','failure']){
  let answer;const calls=[],notices=[];
  const c={state:{authenticated:true,authGeneration:1,services:[{id:'custom-site',name:'Сайт',custom:true}]},encodeURIComponent,
   askConfirmation:()=>new Promise(resolve=>answer=resolve),showDetails:()=>{},showNotice:(...args)=>notices.push(args),refreshCoreAfterEdit:async()=>{},
   api:async(...args)=>{calls.push(args);if(outcome==='failure')throw Error('Route still active');return {pending:outcome==='pending'};}};
  vm.createContext(c);vm.runInContext(deletion,c);
  const pending=c.deleteCustomService('custom-site');assert.equal(await c.deleteCustomService('custom-site'),false);
  if(outcome==='changed')c.state.services[0].name='Новый состав';
  if(outcome==='logout'){c.state.authenticated=false;c.state.authGeneration++;}
  answer(outcome!=='cancel');assert.equal(await pending,outcome==='accept');
  assert.equal(calls.length,['accept','pending','failure'].includes(outcome)?1:0);
  assert.equal(c.state.customServiceDelete,null);
  if(outcome==='pending')assert.match(notices[0][1],/очереди/);
  if(outcome==='failure')assert.equal(notices.length,0,'failed deletion cannot report success');
 }
}
console.log('PASS unassigned custom deletion: single flight, cancellation, changed definition, auth and queued/failed outcome');
