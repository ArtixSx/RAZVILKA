import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const helper=readFileSync(new URL('../cmd/razvilka/web/panel-node-browse.js',import.meta.url),'utf8');
const workflow=readFileSync(new URL('../cmd/razvilka/web/workflow-actions.js',import.meta.url),'utf8');
const browser=readFileSync(new URL('../cmd/razvilka/web/node-browser.js',import.meta.url),'utf8');
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
const extract=(name,source=app)=>{const found=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(found,name);return found[0];};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
function fixture(){
  let now=Date.parse('2026-10-16T12:00:00Z'),handler,confirm=async()=>true;
  const elements=new Map(),listeners=new Map(),timers=new Map(),calls=[],writes=[];
  const node={id:'node-'+ 'c'.repeat(64),name:'Live',protocol:'VLESS',state:'available'};
  const state={authenticated:true,authGeneration:1,currentView:'nodes',nodes:{available:true,generation:1,nodes:[node]},dataLoad:{nodes:{phase:'busy'}},services:[{id:'video',name:'Video'}],status:{revision:1}};
  function $(id){if(!elements.has(id))elements.set(id,{hidden:false,disabled:false,value:'',textContent:'',innerHTML:'',open:false,style:{},
    close(){this.open=false;},showModal(){this.open=true;},focus(){},querySelector(selector){return $(id+selector);},replaceChildren(){this.innerHTML='';}});return elements.get(id);}
  const liveElements=[$('#nodeBrowserContent'),$('#nodeSummary'),$('#nodeOpenImport')];
  const context={state,$,$$:()=>liveElements,console,Map,Set,Date:class extends Date{constructor(value){super(value===undefined?now:value);}static now(){return now;}},
    document:{hidden:false,addEventListener(name,fn){listeners.set(name,[...(listeners.get(name)||[]),fn]);}},
    setTimeout(fn,delay){const key=timers.size+1;timers.set(key,{fn,delay});return key;},clearTimeout:key=>timers.delete(key),
    panelLoad:{generation:1},panelReads:{epoch:1},panelSnapshotCurrent:revision=>revision===context.panelLoad.generation,
    invalidatePanelReads(){context.panelReads.epoch++;},panelBusy:error=>error?.status===409,
    cancelPanelRefresh(){context.panelLoad.generation++;},
    showAuth(){state.authenticated=false;state.authGeneration++;for(const fn of listeners.get('razvilka:auth-required')||[])fn({});},
    esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),
    api:async(url,options={})=>{context.nodeBrowseGuardRequest(url,options.method||'GET');calls.push({url,...options});if(options.method){writes.push({url,...options});context.invalidateSavedNodeBrowse(true);}return handler(url,options);},
    readPanelResource:async(url)=>handler(url,{}),askConfirmation:(...args)=>confirm(...args),showDetails(){},
    renderNodeBrowser(){$('#nodeList').innerHTML='Live actions';},nodeByID:id=>state.nodes.nodes.find(row=>row.id===id),nodeDisplayName:row=>row.name,
    nodeBrowser:{selected:new Set([node.id]),visible:[node.id],page:0,pageSize:24},nodeCountry:()=>({name:'<Country>',code:'XX'}),nodeTransportLabel:row=>row.transport||'tcp',nodeBrowserSourceName:id=>'<Source>'+id,workflowState:{deleteSeq:0,fetchSeq:0,deletion:null,epoch:0,bulkBusy:false},
    clearNodeCheckRequest(){},renderWorkflowControls(){},nodeCanCheck:()=>true,workflowSession:()=>true,
    workflowError:error=>error.message,interfaceToast(){},scheduleNodeBrowserRefresh(){},submitNodeCheckRequest:async(...args)=>{writes.push(args);return {job:{id:1,scope:'all-vless',service_id:'video'}};},
    nodeBrowserActive:()=>true,nodeMeasurementModel:{readStatus:async()=>({response:{},fallback:{},partial:false})},
  };
  vm.createContext(context);
  vm.runInContext(helper+'\n'+['panelSectionState','renderNodes','closeNodeCheck','closeNodeRoute','clearNodeReveal','openNodeEdit','saveNodeAlias','toggleNodeDisabled','revealNode','refreshNodes','acceptPanelSection'].map(name=>extract(name)).join('\n')+'\n'+extract('workflowCheckAllVLESS',workflow)+'\n'+extract('acceptNodeConnectivity',browser)+'\n'+extract('pollNodeBrowserChecks',browser)+'\n'+extract('captureLiveNodeBrowser',browser)+'\n'+extract('renderHistoricalNodeBrowser',browser),context);
  context.workflowRequest=(url,options={})=>handler(url,options);
  const envelope=(revision=1,instance='a'.repeat(32))=>({schema:1,instance_id:instance,revision,generated_at:new Date(now-2000).toISOString(),observed_at:new Date(now).toISOString(),data_age_ms:2000,max_age_seconds:900,state:'retained',dataplane:'not-checked',data:{nodes:[{id:'node-'+ 'b'.repeat(64),name:'<Saved>',protocol:'VLESS',transport:'ws'}]}});
  handler=async()=>envelope();
  return {context,state,$,calls,writes,node,envelope,handler:fn=>{handler=fn;},confirm:fn=>{confirm=fn;},advance:ms=>{now+=ms;},runtime:()=>vm.runInContext('nodeBrowse',context),live(){context.panelSectionState('nodes','ready');context.renderNodes();}};
}
let count=0;
async function test(name,fn){await fn();count++;console.log('PASS '+name);}

await test('busy snapshot stays detached, searchable and free of live health or actions',async()=>{
  const f=fixture(),original=f.state.nodes;
  await f.context.loadSavedNodeBrowse(1);
  assert.equal(f.state.nodes,original);assert.match(f.$('#nodeSavedList').innerHTML,/&lt;Saved>/);
  assert.doesNotMatch(f.$('#nodeSavedList').innerHTML,/button|input|select|data-node|PASS|health|пинг|Проверить|Подключить|Удалить|Конфигурация/);
  assert.match(f.$('#nodeSavedNotice').textContent,/последний успешный список получен 2 сек назад/);
  assert.equal(f.$('#nodeBrowserContent').hidden,true);assert.equal(f.$('#nodeOpenImport').hidden,true);
  f.$('#nodeSavedSearch').value='ws';f.context.renderNodes();assert.match(f.$('#nodeSavedList').innerHTML,/Saved/);
  f.$('#nodeSavedSearch').value='unknown';f.context.renderNodes();assert.equal(f.$('#nodeSavedList').innerHTML,'');assert.match(f.$('#nodeSavedEmpty').textContent,/совпадений нет/);
  assert.equal(f.calls.length,1,'local search performed live IO');
  f.context.openNodeEdit(f.node.id);await f.context.saveNodeAlias({preventDefault(){}});
  assert.equal(f.$('#nodeEditDialog').open,false);assert.equal(f.writes.length,0);
  for(const method of ['PATCH','POST','DELETE'])assert.throws(()=>f.context.nodeBrowseGuardRequest('/api/v1/nodes/'+f.node.id,method));
  assert.doesNotThrow(()=>f.context.nodeBrowseGuardRequest('/api/v1/node-checks/current?job_id=3','DELETE'),'accepted job Stop was blocked');
});

await test('late saved response never replaces successful live list or an accepted newer revision',async()=>{
  const f=fixture(),pending=deferred();f.handler(()=>pending.promise);
  const read=f.context.loadSavedNodeBrowse(1);f.live();pending.resolve(f.envelope(4));await read;
  assert.equal(f.$('#nodeSavedBrowse').hidden,true);assert.match(f.$('#nodeList').innerHTML,/Live/);
  f.context.panelSectionState('nodes','busy');f.handler(async()=>f.envelope(3));await f.context.loadSavedNodeBrowse(1);assert.equal(f.runtime().saved.value.revision,4);
  f.live();assert.equal(f.$('#nodeBrowserContent').hidden,false);assert.equal(f.$('#nodeOpenImport').hidden,false);
});

await test('ordinary refresh preserves edits while disabling save and invalidating old confirmation',async()=>{
  const f=fixture();f.live();f.context.openNodeEdit(f.node.id);f.$('#nodeEditAlias').value='Typed';
  const confirmation=deferred();f.confirm(()=>confirmation.promise);const changing=f.context.toggleNodeDisabled(f.node.id,false);
  f.context.panelSectionState('nodes','loading');f.context.renderNodes();
  assert.equal(f.$('#nodeEditDialog').open,true);assert.equal(f.$('#nodeEditAlias').value,'Typed');assert.equal(f.$('#nodeSavedBrowse').hidden,true);
  assert.equal(f.$('#nodeEditFormbutton[type="submit"]').disabled,true);
  await f.context.saveNodeAlias({preventDefault(){}});assert.equal(f.writes.length,0);
  f.live();confirmation.resolve(true);await changing;assert.equal(f.writes.length,0);
  assert.equal(f.$('#nodeEditAlias').value,'Typed');assert.equal(f.$('#nodeEditFormbutton[type="submit"]').disabled,false);
});

await test('saved transition closes editors, reviews, secret presentation and delayed reveal',async()=>{
  const f=fixture();f.live();const body=deferred();f.handler(()=>body.promise);
  const revealing=f.context.revealNode(f.node.id);await Promise.resolve();
  for(const id of ['nodeEditDialog','nodeGroupDialog','r4DeleteDialog'])f.$('#'+id).open=true;
  f.$('#nodeRevealContent').value='old secret';f.state.nodeRouteReview={ready:true,review:{review_token:'old'}};
  f.context.panelSectionState('nodes','busy');f.context.renderNodes();
  f.live();body.resolve({config:{password:'late secret'}});await revealing;
  for(const id of ['nodeEditDialog','nodeGroupDialog','r4DeleteDialog','nodeRevealDialog'])assert.equal(f.$('#'+id).open,false,id);
  assert.equal(f.$('#nodeRevealContent').value,'');assert.equal(f.state.nodeRouteReview,null);assert.equal(f.runtime().showing,false);
});

await test('late all-VLESS confirmation cannot submit after saved mode and live recovery',async()=>{
  const f=fixture();f.live();f.$('#nodeBrowserService').value='video';
  f.handler(async url=>url.endsWith('/current')?{durable_all_vless:true}:{nodes:[f.node],generation:1});
  const confirmation=deferred();let asked=false;f.confirm(()=>{asked=true;return confirmation.promise;});
  const checking=f.context.workflowCheckAllVLESS();for(let i=0;i<10&&!asked;i++)await new Promise(resolve=>setImmediate(resolve));assert.equal(asked,true);
  f.context.panelSectionState('nodes','busy');f.context.renderNodes();f.live();confirmation.resolve(true);await checking;
  assert.equal(f.writes.length,0,'old catalog confirmation admitted work');
});

await test('auth and mutation epochs reject delayed and pre-mutation publications',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);const old=f.envelope(2),pending=deferred();f.handler(()=>pending.promise);
  const read=f.context.loadSavedNodeBrowse(1);f.context.invalidateSavedNodeBrowse(true);pending.resolve(old);await read;assert.equal(f.runtime().saved,null);
  f.handler(async()=>old);await f.context.loadSavedNodeBrowse(1);assert.equal(f.runtime().saved,null);
  f.advance(3000);f.handler(async()=>f.envelope(3));await f.context.loadSavedNodeBrowse(1);assert.equal(f.runtime().saved.value.revision,3);
  f.context.showAuth();assert.equal(f.runtime().saved,null);assert.equal(f.$('#nodeSavedList').innerHTML,'');
  for(const status of [401,403]){const denied=fixture();await denied.context.loadSavedNodeBrowse(1);denied.handler(async()=>{throw Object.assign(new Error('denied'),{status});});await denied.context.loadSavedNodeBrowse(1);assert.equal(denied.state.authenticated,false);assert.equal(denied.runtime().saved,null);}
});

await test('local TTL, backwards clock and empty endpoint cannot claim nodes deleted',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.advance(898000);f.context.renderNodes();assert.equal(f.runtime().saved,null);assert.equal(f.$('#nodeSavedList').innerHTML,'');assert.match(f.$('#nodeSavedNotice').textContent,/не означает.*удалены/);
  const backward=fixture();await backward.context.loadSavedNodeBrowse(1);backward.advance(-1000);backward.context.renderNodes();assert.equal(backward.runtime().saved,null);
  f.handler(async()=>({schema:1,state:'empty',instance_id:'',revision:0,generated_at:null,observed_at:new Date().toISOString(),data_age_ms:0,max_age_seconds:900,dataplane:'not-checked'}));await f.context.loadSavedNodeBrowse(1);assert.equal(f.$('#nodeSavedList').innerHTML,'');
});

await test('explicit live read works independently from route metadata and failed read remains readonly',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);
  f.handler(async url=>{if(url==='/api/v1/nodes')return {available:true,nodes:[f.node]};throw new Error('route metadata unavailable');});
  await f.context.refreshNodes();assert.equal(f.state.dataLoad.nodes.phase,'ready');assert.equal(f.$('#nodeSavedBrowse').hidden,true);
  f.handler(async()=>{throw Object.assign(new Error('busy'),{status:409});});await f.context.refreshNodes();
  assert.equal(f.state.dataLoad.nodes.phase,'busy');assert.equal(f.runtime().blocked,true);
});

await test('process and strict field bounds never add secret, health or source authority',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);const original=f.state.nodes;
  f.handler(async()=>f.envelope(1,'b'.repeat(32)));await f.context.loadSavedNodeBrowse(1);assert.equal(f.runtime().instance,'b'.repeat(32));assert.equal(f.state.nodes,original);
  for(const modify of [value=>value.data.nodes[0].health={state:'available'},value=>value.data.nodes[0].host='private',value=>value.data.sources=[],value=>value.data.nodes.push(value.data.nodes[0]),value=>value.data.nodes[0].name='x'.repeat(321),value=>value.generated_at='2000-01-01',value=>value.instance_id='bad']){
    const value=f.envelope();modify(value);assert.equal(f.context.validSavedNodeBrowse(value),false);
  }
  assert.match(app,/nodeBrowseGuardRequest\(url/);assert.match(app,/invalidateSavedNodeBrowse\(!url.startsWith/);
  assert(html.indexOf('/panel-node-browse.js?')<html.indexOf('/app.js?'));
  assert.match(html,/id="nodeSavedRefresh"/);assert.match(html,/Текущие задания и остановка/);
  assert(readFileSync(new URL('check.sh',import.meta.url),'utf8').includes('test-panel-node-browse-ui.mjs'));
});

await test('new process revokes prior live editors but cannot revoke a newer successful live response',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.live();f.context.openNodeEdit(f.node.id);
  f.handler(async()=>f.envelope(1,'b'.repeat(32)));await f.context.loadSavedNodeBrowse(1);
  assert.equal(f.$('#nodeEditDialog').open,false);assert.equal(f.runtime().blocked,true);assert.equal(f.$('#nodeSavedBrowse').hidden,false);
  const pending=deferred();f.handler(()=>pending.promise);const read=f.context.loadSavedNodeBrowse(1);
  f.live();f.context.openNodeEdit(f.node.id);f.$('#nodeEditAlias').value='New process edit';
  pending.resolve(f.envelope(1,'d'.repeat(32)));await read;
  assert.equal(f.$('#nodeEditDialog').open,true);assert.equal(f.$('#nodeEditAlias').value,'New process edit');assert.equal(f.$('#nodeSavedBrowse').hidden,true);
});

await test('logout clears historical DOM even away from nodes and malformed live payload grants no action',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.state.currentView='services';f.context.showAuth();
  assert.equal(f.$('#nodeSavedList').innerHTML,'');assert.equal(f.$('#nodeSavedNotice').textContent,'');
  const invalid=fixture();invalid.state.nodes={};invalid.context.panelSectionState('nodes','ready');invalid.context.renderNodes();
  assert.equal(invalid.context.nodeBrowseActionsAllowed(),false);assert.equal(invalid.$('#nodeSavedBrowse').hidden,false);
});

await test('real poll function separates job-status errors from protected-list refusal and recovery',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.live();
  f.context.nodeMeasurementModel.readStatus=async()=>{throw new Error('job status missing');};
  await f.context.pollNodeBrowserChecks();assert.equal(f.state.dataLoad.nodes.phase,'ready');assert.equal(f.runtime().blocked,false);
  f.context.nodeMeasurementModel.readStatus=async()=>({response:{},fallback:{},partial:false});
  f.handler(async url=>{if(url==='/api/v1/nodes')throw Object.assign(new Error('busy list'),{status:409,payload:{code:'RESTORE_OPERATION_BUSY'}});return f.envelope();});
  await f.context.pollNodeBrowserChecks();assert.equal(f.state.dataLoad.nodes.phase,'busy');assert.equal(f.runtime().blocked,true);assert.equal(f.$('#nodeSavedBrowse').hidden,false);
  f.handler(async url=>{if(url==='/api/v1/nodes')return {available:true,nodes:[f.node]};throw new Error('unrelated metadata unavailable');});
  await f.context.pollNodeBrowserChecks();assert.equal(f.state.dataLoad.nodes.phase,'ready');assert.equal(f.runtime().blocked,false);assert.equal(f.$('#nodeSavedBrowse').hidden,true);
});

await test('temporary known busy retains full readonly browser and filters without health or action identity',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.live();
  f.node.transport='ws';f.node.origins=[{source_id:'feed'}];f.node.health={verdict:'PASS',secret:'private'};
  f.context.captureLiveNodeBrowser([f.node]);const original=f.state.nodes;
  f.$('#nodeSearch').value='Live';f.$('#nodeStateFilter').value='available';f.context.nodeBrowser.source='feed';
  f.context.panelSectionState('nodes','busy');f.context.renderNodes();
  assert.equal(f.state.nodes,original);assert.equal(f.$('#nodeSavedBrowse').hidden,true);
  assert.equal(f.$('#nodeBrowserContent').hidden,false);assert.match(f.$('#nodeList').innerHTML,/Live/);
  assert.match(f.$('#nodeBrowserReadNotice').textContent,/Только просмотр/);
  assert.doesNotMatch(f.$('#nodeList').innerHTML,/data-node|button|input|PASS|private|Проверить|Подключить/);
  assert.doesNotMatch(JSON.stringify(f.runtime().full),/node-[a-f0-9]{64}|health|secret|verdict/);
  assert.equal(f.$('#nodeSearch').value,'Live');assert.equal(f.context.nodeBrowser.source,'feed');
  assert.equal(f.$('#nodeStateFilter').value,'available');assert.equal(f.$('#nodeStateFilter').disabled,true);
  f.$('#nodeSearch').value='missing';f.context.renderNodes();assert.equal(f.$('#nodeList').innerHTML,'');
  f.context.panelSectionState('nodes','loading');f.context.renderNodes();assert.equal(f.$('#nodeSavedBrowse').hidden,true);
  assert.equal(f.context.nodeBrowseActionsAllowed(),false);assert.throws(()=>f.context.nodeBrowseGuardRequest('/api/v1/nodes/x','DELETE'));
  assert.doesNotThrow(()=>f.context.nodeBrowseGuardRequest('/api/v1/node-checks/current?job_id=3','DELETE'));
  f.live();assert.equal(f.$('#nodeStateFilter').disabled,false);assert.equal(f.context.nodeBrowseActionsAllowed(),true);
});
await test('temporary full browser requires prior live receipt, same process/auth and bounded freshness',async()=>{
  for (const mode of ['no-prior','error','expired','backward','process','auth','mutation','instance']) {
    const f=fixture();await f.context.loadSavedNodeBrowse(1);
    if(mode!=='no-prior'){f.live();f.context.captureLiveNodeBrowser([f.node]);}
    if(mode==='expired')f.advance(120000);
    if(mode==='backward')f.advance(-1);
    if(mode==='process')f.state.status.process_id=22;
    if(mode==='auth')f.state.authGeneration++;
    if(mode==='mutation')f.context.invalidateSavedNodeBrowse(true);
    if(mode==='instance')f.runtime().instance='d'.repeat(32);
    f.context.panelSectionState('nodes',mode==='error'?'error':'busy');f.context.renderNodes();
    assert.equal(f.$('#nodeSavedBrowse').hidden,false,mode);assert.equal(f.runtime().full,null,mode);
    f.live();assert.equal(f.context.nodeBrowseActionsAllowed(),true,mode);
  }
});
await test('expired temporary view cannot leave its historical notice over a fresh live read',async()=>{
  const f=fixture();await f.context.loadSavedNodeBrowse(1);f.live();f.context.captureLiveNodeBrowser([f.node]);
  f.context.panelSectionState('nodes','busy');f.context.renderNodes();assert.match(f.$('#nodeBrowserReadNotice').textContent,/Только просмотр/);
  f.advance(120000);f.context.renderNodes();assert.equal(f.$('#nodeSavedBrowse').hidden,false);
  f.live();assert.equal(f.$('#nodeBrowserReadNotice').hidden,true);assert.equal(f.$('#nodeBrowserReadNotice').textContent,'');
});
console.log(`Node saved browse: ${count} modeled lifecycle checks passed (no native/browser claim)`);
