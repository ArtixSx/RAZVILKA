import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const read=name=>readFileSync(new URL('../cmd/razvilka/web/'+name,import.meta.url),'utf8');
const source=read('interface.js'),consoleSource=read('console.js');
const functions=['interfaceFinishRequestedDeletion','interfaceUpdateInspector','interfaceManage'].map(name=>{
 const match=source.match(new RegExp('(?:async )?function '+name+'\\([^]*?\\n}'));
 assert.ok(match,name);return match[0];
}).join('\n');
const cacheFunctions=consoleSource.slice(consoleSource.indexOf('function consoleObservationClock()'),consoleSource.indexOf('const ci='));
function fixture(mode='complete'){
 let clock=100;const messages={},toasts=[],calls=[];
 const dialog={open:true,close(){this.open=false;}};
 const c={state:{authenticated:true,authGeneration:7,currentView:'services',services:[{id:'site',name:'Сайт',custom:true}],dataLoad:{services:{loaded:true,phase:'ready'}}},
  interfaceState:{authEpoch:2,authRevoked:false,inspector:'site'},consoleSnapshot:null,consoleAutonomyReceipt:null,consoleAutonomyError:'',
  performance:{now:()=>clock},Date,encodeURIComponent,
  $:id=>id==='#ui3ServiceDialog'?dialog:{},interfaceDataReady:()=>c.state.dataLoad.services.loaded,
  consoleText:(id,text)=>messages[id]=text,interfaceHTML(){},interfaceToast:text=>toasts.push(text),interfaceCloseInspector:()=>dialog.close(),
  askConfirmation:async()=>mode!=='cancel',
  CustomEvent:class{constructor(type,{detail}){this.detail=detail;}},
  window:{dispatchEvent:event=>c.consoleAcceptAutonomySnapshot(event.detail)},
  interfaceRequest:async(path,options)=>{
   calls.push({path,options});
   if(options?.method==='DELETE'){
    if(mode==='failure')throw Error('not accepted');
    return {ok:true,pending:true,live_applied:false};
   }
   // The unversioned immediate read is not a fresh observation receipt.
   return {policy:{setup_complete:true,revision:4},services:{site:{removing:true}},runtime:{},applied_services:{},blocked:false};
  },refreshCoreAfterEdit:async()=>{
   c.state.services=[];
   const final={policy:{setup_complete:true,revision:5},services:{},runtime:{},applied_services:{},blocked:false,
    observation:{instance_id:'a'.repeat(32),revision:2,state:'available',data_age_ms:0,observed_at:'2026-10-22T22:00:00Z'}};
   if(mode==='managed')final.services.site={removing:true};
   if(mode==='runtime')final.runtime.site={state:'requires-review'};
   if(mode==='applied')final.applied_services.site={enabled:true};
   if(mode==='blocked')final.blocked=true;
   if(mode==='no-blocked')delete final.blocked;
   if(mode==='queued-revision')final.policy.revision=4;
   if(mode==='other-instance')final.observation.instance_id='b'.repeat(32);
   if(mode==='retained')final.observation.state='retained';
   if(mode==='expired')final.observation.data_age_ms=15000;
   if(mode==='unversioned')delete final.observation;
   if(mode==='catalog-error')c.state.dataLoad.services.phase='error';
   if(mode==='catalog-loading')c.state.dataLoad.services.phase='loading';
   if(mode==='catalog-unloaded')c.state.dataLoad.services.loaded=false;
   if(mode==='autonomy-error')c.consoleAutonomyError='unavailable';
   c.consoleAcceptAutonomySnapshot(final);
   if(mode==='auth-changed')c.interfaceState.authEpoch++;
  }};
 vm.createContext(c);vm.runInContext(cacheFunctions+'\n'+functions,c);
 c.consoleAcceptAutonomySnapshot({policy:{setup_complete:true,revision:3},services:{site:{enabled:true}},runtime:{},applied_services:{site:{enabled:true}},blocked:false,
  observation:{instance_id:'a'.repeat(32),revision:1,state:'available',data_age_ms:0,observed_at:'2026-10-22T21:59:00Z'}});
 messages.ui3InspectorMessage='Удаление поставлено в очередь. Маршрут ещё не считается снятым.';
 return {c,dialog,messages,toasts,calls,age:ms=>clock+=ms};
}

for(const mode of ['complete','managed','runtime','applied','blocked','no-blocked','queued-revision','other-instance','retained','expired','unversioned','catalog-error','catalog-loading','catalog-unloaded','autonomy-error','auth-changed','cancel','failure']){
 const f=fixture(mode);
 const result=await f.c.interfaceManage('site',false,true,true).catch(error=>error);
 if(mode==='complete'){
  assert.equal(result,true);assert.equal(f.dialog.open,false);
  assert.deepEqual(f.toasts,['Сервис удалён из каталога.']);
  assert.equal(f.messages.ui3InspectorMessage,'');assert.equal(f.c.interfaceState.requestedDeletion,null);
  f.c.interfaceUpdateInspector();assert.equal(f.toasts.length,1,'completion must be shown once');
 }else{
  assert.equal(f.dialog.open,true,mode+' closed inspector without confirmed deletion');assert.equal(f.toasts.length,0,mode);
  if(!['auth-changed','cancel','failure'].includes(mode))assert.match(f.messages.ui3InspectorMessage,/ещё не подтверждено/,mode+' retained a misleading queue message');
 }
 if(mode==='cancel')assert.equal(f.calls.length,0);
 if(['cancel','failure'].includes(mode))assert.equal(f.c.interfaceState.requestedDeletion,undefined,'unaccepted request became a completion token');
}
{
 const f=fixture();await f.c.refreshCoreAfterEdit();f.c.interfaceUpdateInspector();
 assert.equal(f.dialog.open,true,'unrelated disappearance is not this session’s deletion');assert.equal(f.toasts.length,0);
 assert.equal(f.messages.ui3InspectorMessage,'','unrelated disappearance retained old queue message');
 assert.doesNotMatch(f.messages.r5InspectorDetail,/маршрут.*не измен/i,'missing catalog cannot prove network effects');
}
{
 const f=fixture('retained');await f.c.interfaceManage('site',false,true,true);
 f.c.consoleSnapshot.observation.state='available';f.age(15000);f.c.interfaceUpdateInspector();
 assert.equal(f.dialog.open,true,'expired receipt was treated as fresh');
}
console.log('PASS inspector deletion: accepted session request + fresh completed server state closes once; stale, pending, failed and unrelated missing states remain uncertain');
