import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const ui=readFileSync(new URL('../cmd/razvilka/web/interface.js',import.meta.url),'utf8');
const extract=(source,name)=>{const found=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(found,name);return found[0];};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const deferred=()=>{let resolve;const promise=new Promise(yes=>resolve=yes);return {promise,resolve};};
function fixture(){
 const configs=['sing-box','xray','usque'].map(id=>({id,name:id,files:[{id:'main',exists:false,staged:false}]}));
 const state={authGeneration:4,currentView:'engines',selectedEngine:'sing-box',selectedEngineFile:'main',engineConfigs:configs,engineEditorDirty:false};
 const interfaceState={authEpoch:2,authRevoked:false},elements=new Map(),calls=[],notices=[],focus=[],tabs=[],frames=[],renders=[];
 let confirmation=async()=>true,refresh=async()=>true;
 const $=id=>{if(!elements.has(id))elements.set(id,{hidden:id==='#authScreen',disabled:false,focus(){focus.push(id);},value:'private draft'});return elements.get(id);};
 const ctx={state,interfaceState,$,consoleEngineMeta:{'sing-box':{},xray:{},usque:{}},Object,Promise,
   askConfirmation:(...args)=>confirmation(...args),readEngineNavigationMetadata:async()=>{calls.push({method:'GET',path:'/api/v1/engine-configs'});return refresh();},
   selectedEngineView:()=>state.engineConfigs.find(e=>e.id===state.selectedEngine),invalidateEngineEditorContext(){},
   noticeBelongsOnlyToEngine:()=>false,hideNotice(){},showNotice:(...args)=>notices.push(args),renderEngineControl(){},
   setView:name=>{state.currentView=name;},switchEngineTab:tab=>tabs.push(tab),
   renderServices:()=>renders.push('services'),requestAnimationFrame:fn=>frames.push(fn),
   showAuth(){state.authGeneration++;$('#authScreen').hidden=false;},
 };
 vm.createContext(ctx);vm.runInContext(extract(app,'openEngineConfiguration')+extract(app,'selectEngine')+extract(app,'assignSelectedEngineToService')+extract(ui,'interfaceOpenEngineStep'),ctx);
 return {ctx,state,interfaceState,elements,notices,calls,focus,tabs,renders,$,runFrames:()=>{while(frames.length)frames.shift()();},confirm:fn=>confirmation=fn,refresh:fn=>refresh=fn};
}
let tests=0;async function test(name,action){await action();tests++;console.log('PASS '+name);}
await test('each card step opens its exact engine and never starts a write',async()=>{
 for(const [step,target,tab] of [['profile','#engineFileSelect','config'],['check','#r4Validate','check'],['apply','#engineApplyConfig','config']]){
   const f=fixture();await f.ctx.interfaceOpenEngineStep('xray',step);assert.equal(f.state.selectedEngine,'xray');assert.equal(f.state.currentView,'engineconfig');
   assert.equal(f.focus.at(-1),target);assert.equal(f.tabs.at(-1),tab);assert.equal(f.calls.length,0);
 }
});
await test('checks focus the real validator first and the service selector after a matching format receipt',async()=>{
 const f=fixture();f.ctx.engineProgressView=()=>({format:true});
 await f.ctx.interfaceOpenEngineStep('xray','check');assert.equal(f.focus.at(-1),'#r4ProbeService');assert.equal(f.calls.length,0);
});
await test('reopening the same engine keeps dirty values without a switch review',async()=>{
 const f=fixture();f.state.engineEditorDirty=true;f.confirm(()=>{throw new Error('same engine asked to discard');});
 await f.ctx.interfaceOpenEngineStep('sing-box','profile');assert(f.state.engineEditorDirty);assert.equal(f.$('#engineEditor').value,'private draft');
});
await test('declining a switch keeps the original engine, dirty draft and view',async()=>{
 const f=fixture();f.state.engineEditorDirty=true;f.confirm(async()=>false);await f.ctx.interfaceOpenEngineStep('xray','apply');
 assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.state.currentView,'engines');assert(f.state.engineEditorDirty);assert.equal(f.focus.length,0);
});
await test('missing description cannot fall back to a different engine',async()=>{
 const f=fixture();f.state.engineConfigs=f.state.engineConfigs.filter(e=>e.id!=='xray');await f.ctx.interfaceOpenEngineStep('xray','profile');
 assert.equal(f.calls.length,1);assert.equal(f.state.currentView,'engines');assert.equal(f.state.selectedEngine,'sing-box');assert.match(f.notices.at(-1)[1],/недоступны/);
});
await test('independent read can provide the requested description',async()=>{
 const f=fixture();f.state.engineConfigs=f.state.engineConfigs.filter(e=>e.id!=='xray');f.refresh(async()=>{f.state.engineConfigs.push({id:'xray',files:[{id:'main'}]});return true;});
 await f.ctx.interfaceOpenEngineStep('xray','profile');assert.equal(f.state.selectedEngine,'xray');assert.equal(f.state.currentView,'engineconfig');assert.equal(f.calls[0].method,'GET');
});
await test('a revoked navigation read cannot open an engine even if a retained description appears',async()=>{
 const f=fixture();f.state.engineConfigs=[];f.refresh(async()=>{f.state.engineConfigs.push({id:'xray',files:[{id:'main'}]});return false;});
 await f.ctx.interfaceOpenEngineStep('xray','profile');assert.equal(f.state.currentView,'engines');assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.focus.length,0);assert.equal(f.notices.length,0);
});
await test('busy missing-catalog navigation preserves the chosen engine and local dirty profile',async()=>{
 const f=fixture();f.state.engineEditorDirty=true;f.state.engineConfigs=f.state.engineConfigs.filter(e=>e.id!=='xray');
 f.refresh(async()=>{throw Object.assign(new Error('modeled read busy'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}});});
 await f.ctx.interfaceOpenEngineStep('xray','profile');assert.equal(f.state.currentView,'engines');assert.equal(f.state.selectedEngine,'sing-box');assert(f.state.engineEditorDirty);
 assert.equal(f.$('#engineEditor').value,'private draft');assert.equal(f.focus.length,0);assert.equal(f.calls.length,1);assert.match(f.notices.at(-1)[1],/не прочитаны/);
});
await test('leaving during a switch review revokes the old selection',async()=>{
 const f=fixture(),review=deferred();f.state.engineEditorDirty=true;f.confirm(()=>review.promise);const pending=f.ctx.interfaceOpenEngineStep('xray','check');
 await flush();f.state.currentView='settings';review.resolve(true);await pending;assert.equal(f.state.selectedEngine,'sing-box');assert(f.state.engineEditorDirty);assert.equal(f.focus.length,0);
});
await test('newer card request wins over a late older confirmation',async()=>{
 const f=fixture(),old=deferred(),latest=deferred();let n=0;f.state.engineEditorDirty=true;f.confirm(()=>++n===1?old.promise:latest.promise);
 const first=f.ctx.interfaceOpenEngineStep('usque','profile'),second=f.ctx.interfaceOpenEngineStep('xray','check');old.resolve(true);await first;
 assert.equal(f.state.selectedEngine,'sing-box');latest.resolve(true);await second;assert.equal(f.state.selectedEngine,'xray');assert.equal(f.focus.at(-1),'#r4Validate');
});
await test('logout while confirmation or read is pending cannot open private settings',async()=>{
 for(const mode of ['confirm','read']){
   const f=fixture(),pending=deferred();if(mode==='confirm'){f.state.engineEditorDirty=true;f.confirm(()=>pending.promise);}else{f.state.engineConfigs=[];f.refresh(()=>pending.promise);}
   const action=f.ctx.interfaceOpenEngineStep('xray','profile');await flush();f.ctx.showAuth();pending.resolve(true);await action;
   assert.equal(f.state.currentView,'engines');assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.focus.length,0);
 }
});
await test('engine operation blocks navigation and disabled Apply explains preparation',async()=>{
 const busy=fixture();busy.state.engineIntent={};await busy.ctx.interfaceOpenEngineStep('xray','profile');assert.equal(busy.state.currentView,'engines');
 const f=fixture();f.$('#engineApplyConfig').disabled=true;await f.ctx.interfaceOpenEngineStep('xray','apply');assert.equal(f.focus.at(-1),'#engineFileSelect');assert.match(f.notices.at(-1)[1],/Подготовьте/);
});
await test('current read 401 closes auth; old read errors cannot replace new notices',async()=>{
 const f=fixture();f.state.engineConfigs=[];f.refresh(async()=>{throw Object.assign(new Error('expired'),{status:401});});await f.ctx.interfaceOpenEngineStep('xray','profile');assert.equal(f.$('#authScreen').hidden,false);
 const old=fixture(),done=deferred();old.state.engineConfigs=[];old.refresh(async()=>{await done.promise;throw new Error('old read');});
 const action=old.ctx.interfaceOpenEngineStep('xray','profile');await flush();old.ctx.showAuth();done.resolve();await action;assert.equal(old.notices.length,0);
});
await test('unknown step and engine are inert',async()=>{
 const f=fixture();await f.ctx.interfaceOpenEngineStep('xray','future');await f.ctx.interfaceOpenEngineStep('future','profile');assert.equal(f.calls.length,0);assert.equal(f.focus.length,0);
});
await test('choose service opens the visible catalog after an excluded or filtered view without writing',()=>{
 const f=fixture();Object.assign(f.interfaceState,{filter:'excluded',query:'old search',category:'ИИ-сервисы'});f.$('#ui3ServiceSearch').value='old search';
 f.ctx.assignSelectedEngineToService();f.runFrames();assert.equal(f.state.currentView,'services');assert.equal(f.interfaceState.filter,'all');assert.equal(f.interfaceState.query,'');assert.equal(f.interfaceState.category,'');
 assert.equal(f.$('#ui3ServiceSearch').value,'');assert.equal(f.focus.at(-1),'#ui3ServiceSearch');assert.equal(f.state.selectedEngine,'sing-box');assert.equal(f.calls.length,0);assert.deepEqual(f.renders,['services']);assert.match(f.notices.at(-1)[2],/Открыть настройки сервиса/);
});
await test('a queued choose-service focus cannot pull the user back after navigation or logout',()=>{
 for(const leave of ['view','auth']){
   const f=fixture();f.ctx.assignSelectedEngineToService();if(leave==='view')f.state.currentView='settings';else f.ctx.showAuth();f.runFrames();assert.equal(f.focus.length,0);assert.equal(f.calls.length,0);
 }
});
await test('choose service stays inert during an engine operation or without a selected engine',()=>{
 const busy=fixture();busy.state.engineIntent={};busy.ctx.assignSelectedEngineToService();busy.runFrames();assert.equal(busy.state.currentView,'engines');assert.equal(busy.notices.length,0);
 const missing=fixture();missing.state.engineConfigs=[];missing.ctx.assignSelectedEngineToService();missing.runFrames();assert.equal(missing.state.currentView,'engines');assert.equal(missing.focus.length,0);
});
console.log(JSON.stringify({suite:'engine-card-flow',tests}));
