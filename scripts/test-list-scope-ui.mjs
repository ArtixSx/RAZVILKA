// Execute the actual shared scope editor against bounded read/write replies.
// No browser, router, network operation or Apply is launched by this suite.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const source=read('cmd/razvilka/web/list-scope-ui.js');
const copy=value=>JSON.parse(JSON.stringify(value));
const policy={schema:2,revision:3,clients:{mode:'lan_except',segment_ids:['Home'],device_ids:null,excluded_device_ids:['gone-id','old-device'],excluded_cidrs:['192.0.2.0/24'],new_devices:'inherit'},traffic:{mode:'selected_services',all_except_allowed:false,auto_hostlist_allowed:true,unavailable:'retain'},rules:null,russian:{enabled:false,auto_update_allowed:false,revision:0,service_ids:null,broad_tlds:[]},resource_exclusions:{schema:1,revision:2,manual:[{kind:'suffix',value:'bank.example'}],russian_snapshot:{catalog_id:'accepted',revision:1,digest:'a'.repeat(64),entries:[]}}};
const grants=[{resolved:'xray:node-one',provider_class:'node',provider_id:'node-one',source_ids:['saved-feed'],source_kinds:['public'],protocols:['vless']}];
function review({revision=8,p=policy,g=grants}={}) {
  return {revision,policy:copy(p),consent:p?{schema:1,sequence:2,config_revision:revision,policy:copy(p),grants:copy(g),digest:'b'.repeat(64)}:null,live_applied:false};
}
function options({revision=8,policyRevision=3,state='available',expired=false}={}) {
  const unavailable=state==='unavailable';
  return {schema:1,ok:true,revision,policy_revision:policyRevision,state,code:unavailable?'HOME_OBSERVATION_UNAVAILABLE':'',observed_at:unavailable?null:new Date().toISOString(),fresh_until:unavailable?null:new Date(Date.now()+(expired?-1000:60000)).toISOString(),effect_authorized:false,live_applied:false,
    segments:[{id:'br0',label:'Дом',native_name:'Home',interface:'br0',state:unavailable?'unavailable':'observed',code:'',selection_candidate:!unavailable}],
    devices:[{id:'new-device',label:'Компьютер',segment_id:unavailable?null:'br0',state:unavailable?'unavailable':'observed',code:'',selection_candidate:!unavailable},{id:'old-device',label:'Сохранённый телефон',segment_id:null,state:unavailable?'unavailable':'not_observed',code:'',selection_candidate:false}],retained_segment_ids:['Home'],retained_device_ids:['gone-id','old-device']};
}
function applied(r=review()) {
  return {revision:r.revision,policy_revision:r.policy?.revision||0,applied_revision:7,desired_matches_applied:false,applied_effective:{clients:{mode:'selected_devices',segment_ids:['Home'],device_ids:['applied-device'],excluded_device_ids:['applied-negative'],excluded_cidrs:null,new_devices:'base'}}};
}
function fixture(initial=review(),catalog=options()) {
  const calls=[],events=new Map(),rootEvents=new Map();
  const root={innerHTML:'',contains:()=>false,querySelectorAll:()=>[],addEventListener:(name,fn)=>rootEvents.set(name,fn)};
  const state={authenticated:true,authGeneration:1,currentView:'devices',status:{},dataLoad:{networkPolicyReview:{phase:'ready'},resourceExclusions:{phase:'ready'},homeScope:{phase:'ready'}},resourceExclusions:applied(initial)};
  const c={state,document:{activeElement:null,getElementById:id=>id==='listScopeContent'?root:null,addEventListener:(name,fn)=>events.set(name,fn)},console,Date,Map,Set,JSON,Number,Object,esc:value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))};
  let handler=async()=>{throw new Error('Unexpected request');};
  c.interfaceRequest=async(path,opts={})=>{const call={path,method:opts.method||'GET',body:opts.body?JSON.parse(opts.body):null};calls.push(call);return handler(call);};
  c.cancelPanelRefresh=()=>{};
  c.panelSectionState=(key,phase)=>{state.dataLoad[key]={phase};};
  c.refreshAfterMutation=async()=>{calls.push({refresh:true});};
  vm.createContext(c);vm.runInContext(source,c);
  c.acceptPanelSection=(key,value)=>{if(key==='networkPolicyReview')c.acceptListScopeReview(value);else if(key==='resourceExclusions')state.resourceExclusions=value;else assert.fail(key);c.panelSectionState(key,'ready');};
  c.acceptListScopeReview(initial);c.acceptListScopeOptions(catalog);
  const e=vm.runInContext('listScopeEditor',c);
  return {c,e,state,calls,root,events,rootEvents,setHandler(fn){handler=fn;}};
}
function successfulSave(f) {
  let stored;
  f.setHandler(async call=>{
    if(call.method==='POST') {
      const p=copy(call.body.policy);p.revision=(f.e.base.policy?.revision||0)+1;
      // The first real scope carries inactive exclusions through the server.
      if(!f.e.base.policy)p.resource_exclusions=copy(policy.resource_exclusions);
      stored=review({revision:f.e.base.revision+1,p,g:call.body.grants});
      return {...copy(stored),ok:true,approved:true};
    }
    return copy(stored);
  });
}
let checks=0;
async function check(name,fn){await fn();checks++;console.log('PASS '+name);}
await check('render and draft editing do not save, Apply, or construct a provider grant',()=>{
  const f=fixture();f.c.renderListScope();f.c.listScopeChange('new_devices','base');
  assert.equal(f.calls.length,0);assert.equal(f.e.dirty,true);assert.match(f.root.innerHTML,/Домашняя сеть/);assert.match(f.root.innerHTML,/Устройства без обхода/);assert.match(f.root.innerHTML,/Сайты без обхода/);assert.match(f.root.innerHTML,/gone-id/);assert.match(f.root.innerHTML,/Сейчас не наблюдается/);
});
await check('whole-policy save preserves null slices, rules, resources, existing grants and raw alias',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');successfulSave(f);await f.c.saveListScope();
  const writes=f.calls.filter(c=>c.method==='POST');assert.equal(writes.length,1);
  assert.equal(writes[0].path,'/api/v1/networkpolicy/review');
  assert.deepEqual(writes[0].body,{expected_revision:8,expected_policy_revision:3,policy:{...copy(policy),clients:{...copy(policy.clients),new_devices:'base'}},grants,confirm:'APPROVE_NETWORK_POLICY'});
  assert.equal(f.calls.filter(c=>c.method==='GET').length,1);assert.equal(f.e.dirty,false);assert.equal(f.e.unknown,false);assert.equal(f.e.base.policy.clients.segment_ids[0],'Home');
  assert.equal(f.state.networkPolicyReview.live_applied,false);assert.equal(f.state.resourceExclusions.applied_revision,7);assert.match(f.e.message,/Настройки сохранены — применение ещё не подтверждено/);
  assert(!f.calls.some(c=>c.path?.includes('/apply')));assert(!f.calls.some(c=>c.method==='POST'&&c.path?.endsWith('/exclusions')));
});
await check('null and empty grant arrays remain distinct',async()=>{
  for(const g of [null,[]]){const f=fixture(review({g}));f.c.listScopeChange('new_devices','base');successfulSave(f);await f.c.saveListScope();assert.deepEqual(f.calls.find(c=>c.method==='POST').body.grants,g);assert.equal(f.e.unknown,false);}
});
await check('first scope requires explicit actual segment and carries inactive resources without guessed grants',async()=>{
  const f=fixture(review({revision:17,p:null}),options({revision:17,policyRevision:0}));assert.deepEqual(copy(f.e.draft.segment_ids),[]);
  f.e.dirty=true;await f.c.saveListScope();assert.equal(f.calls.length,0);
  f.c.listScopeToggle('segment_ids','br0',true);successfulSave(f);await f.c.saveListScope();
  const body=f.calls.find(c=>c.method==='POST').body;assert.equal(body.expected_revision,17);assert.equal(body.expected_policy_revision,0);assert.deepEqual(body.grants,[]);assert.deepEqual(body.policy.clients.segment_ids,['br0']);assert.equal(body.policy.traffic.mode,'selected_services');assert.equal(body.policy.traffic.all_except_allowed,false);assert(!('resource_exclusions' in body.policy));assert.deepEqual(copy(f.e.base.policy.resource_exclusions),policy.resource_exclusions);
});
await check('selected devices use stable IDs and base membership; negative IDs survive mode changes',async()=>{
  const f=fixture();f.c.listScopeChange('mode','selected_devices');f.c.listScopeToggle('device_ids','new-device',true);
  assert.deepEqual(copy(f.e.draft.device_ids),['new-device']);assert.equal(f.e.draft.new_devices,'base');assert.deepEqual(copy(f.e.draft.excluded_device_ids),policy.clients.excluded_device_ids);
  f.c.listScopeChange('mode','lan_except');assert.deepEqual(copy(f.e.draft.device_ids),[]);assert.deepEqual(copy(f.e.draft.excluded_device_ids),policy.clients.excluded_device_ids);
});
await check('new selected device cannot be added without its reviewed home segment',()=>{
  const f=fixture();f.c.listScopeChange('mode','selected_devices');f.c.listScopeToggle('segment_ids','Home',false);f.c.listScopeToggle('device_ids','new-device',true);assert.equal(f.e.draft.device_ids,null);assert.match(f.e.message,/домашний сегмент/);
});
await check('unavailable source preserves all negative refs and permits explicit removal of only a saved ID',async()=>{
  const f=fixture(review(),options({state:'unavailable'}));f.c.renderListScope();assert.match(f.root.innerHTML,/HOME_OBSERVATION_UNAVAILABLE/);assert.match(f.root.innerHTML,/gone-id/);f.c.listScopeToggle('excluded_device_ids','gone-id',false);successfulSave(f);await f.c.saveListScope();
  const clients=f.calls.find(c=>c.method==='POST').body.policy.clients;assert.deepEqual(clients.excluded_device_ids,['old-device']);assert.deepEqual(clients.segment_ids,['Home']);assert.deepEqual(clients.excluded_cidrs,policy.clients.excluded_cidrs);
});
await check('expired or mismatched options cannot add new IDs or authorize a synthetic draft',async()=>{
  for(const catalog of [options({expired:true}),options({revision:9}),options({state:'unavailable'})]){
    const f=fixture(review(),catalog);f.c.listScopeToggle('excluded_device_ids','new-device',true);assert.deepEqual(copy(f.e.draft.excluded_device_ids),policy.clients.excluded_device_ids);
    f.e.draft.excluded_device_ids.push('new-device');f.e.dirty=true;await f.c.saveListScope();assert.equal(f.calls.length,0);assert.match(f.e.message,/новых ID/);
  }
});
await check('fresh observation alone cannot approve an uncorroborated cached or invented ID',async()=>{
  const f=fixture();f.c.listScopeToggle('segment_ids','invented-home',true);f.c.listScopeToggle('device_ids','old-device',true);assert.deepEqual(copy(f.e.draft.segment_ids),['Home']);assert.equal(f.e.draft.device_ids,null);assert.equal(f.calls.length,0);
});
await check('partial source offers per-row candidates without removing saved unavailable refs',()=>{
  const f=fixture(review(),options({state:'partial'}));f.c.listScopeToggle('excluded_device_ids','new-device',true);assert.deepEqual(copy(f.e.draft.excluded_device_ids),['gone-id','old-device','new-device']);f.c.renderListScope();assert.match(f.root.innerHTML,/Наблюдение неполное/);
});
await check('desired and applied snapshots remain separate and mixed revisions have no applied claim',()=>{
  const f=fixture();f.c.renderListScope();assert.match(f.root.innerHTML,/отличается от применённого плана/);assert.match(f.root.innerHTML,/applied-device/);assert.match(f.root.innerHTML,/applied-negative/);
  f.state.resourceExclusions.revision=7;f.c.renderListScope();assert.match(f.root.innerHTML,/ещё не обновлено/);assert.doesNotMatch(f.root.innerHTML,/applied-device/);
});
await check('background drift preserves full local draft and original CAS base',async()=>{
  const f=fixture();f.c.listScopeToggle('excluded_device_ids','gone-id',false);f.c.acceptListScopeReview(review({revision:9,p:{...copy(policy),revision:4}}));await f.c.saveListScope();assert.equal(f.e.base.revision,8);assert.deepEqual(copy(f.e.draft.excluded_device_ids),['old-device']);assert.equal(f.e.conflict,true);assert.equal(f.calls.length,0);
});
await check('409 prevents replay and retains the draft until an explicit reset',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');f.setHandler(async()=>{throw Object.assign(new Error('changed'),{status:409,payload:{code:'NETWORK_POLICY_REVIEW_CHANGED'}});});await f.c.saveListScope();await f.c.saveListScope();assert.equal(f.calls.filter(c=>c.method==='POST').length,1);assert.equal(f.e.dirty,true);assert.equal(f.e.conflict,true);assert.equal(f.e.draft.new_devices,'base');
});
await check('double click during save produces one POST and one independent verification GET',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');let finish,stored;
  f.setHandler(call=>{if(call.method==='POST'){const p=copy(call.body.policy);p.revision=4;stored=review({revision:9,p,g:call.body.grants});return new Promise(resolve=>finish=()=>resolve({...copy(stored),approved:true}));}return Promise.resolve(copy(stored));});
  const first=f.c.saveListScope();await f.c.saveListScope();assert.equal(f.calls.length,1);finish();await first;assert.equal(f.calls.filter(c=>c.method==='POST').length,1);assert.equal(f.calls.filter(c=>c.method==='GET').length,1);
});
await check('timeout is unknown and neither a background read nor reset can replay it',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');f.setHandler(async()=>{throw new Error('timeout');});await f.c.saveListScope();f.c.acceptListScopeReview(review());f.c.listScopeReset(f.state.networkPolicyReview);f.e.dirty=true;await f.c.saveListScope();assert.equal(f.calls.filter(c=>c.method==='POST').length,1);assert.equal(f.e.unknown,true);
});
await check('acknowledged save followed by a different read remains unconfirmed',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');let posted;
  f.setHandler(async call=>{if(call.method==='POST'){posted=copy(call.body.policy);posted.revision=4;return {...review({revision:9,p:posted}),approved:true};}return review({revision:10,p:policy});});await f.c.saveListScope();assert.equal(f.e.unknown,true);assert.equal(f.e.dirty,true);assert.match(f.e.message,/Сервер принял область/);
});
await check('unsupported save is shown and cannot look like successful Apply',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');f.setHandler(async()=>{throw Object.assign(new Error('unsupported'),{status:503,payload:{code:'NETWORK_POLICY_CONSENT_UNAVAILABLE'}});});await f.c.saveListScope();assert.match(f.e.message,/NETWORK_POLICY_CONSENT_UNAVAILABLE/);assert.doesNotMatch(f.e.message,/Настройки сохранены/);assert.equal(f.e.dirty,true);assert.equal(f.state.networkPolicyReview.policy.revision,3);
});
await check('late save reply after logout cannot read back or restore a previous session',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');let finish;f.setHandler(()=>new Promise(resolve=>finish=resolve));const pending=f.c.saveListScope();f.state.authenticated=false;f.state.authGeneration++;f.events.get('razvilka:auth-required')();finish({...review({revision:9}),approved:true});await pending;assert.equal(f.calls.filter(c=>c.method==='GET').length,0);assert.equal(f.e.draft,null);assert.equal(f.state.networkPolicyReview,null);assert.equal(f.state.homeScope,null);
});
await check('late verification GET cannot overwrite the next authenticated session',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');let finish;
  const saved=review({revision:9,p:{...copy(policy),revision:4,clients:{...copy(policy.clients),new_devices:'base'}}});
  f.setHandler(call=>call.method==='POST'?Promise.resolve({...copy(saved),approved:true}):new Promise(resolve=>finish=resolve));
  const pending=f.c.saveListScope();await new Promise(resolve=>setImmediate(resolve));f.state.authenticated=false;f.state.authGeneration++;f.events.get('razvilka:auth-required')();f.state.authenticated=true;f.c.acceptListScopeReview(review({revision:12,p:{...copy(policy),revision:7}}));finish(saved);await pending;assert.equal(f.state.networkPolicyReview.revision,12);assert.equal(f.e.base.revision,12);assert.equal(f.e.pending,null);
});
await check('late options after logout cannot resurrect private references',async()=>{
  const f=fixture();let finish;f.setHandler(()=>new Promise(resolve=>finish=resolve));const pending=f.c.refreshListScopeOptions();f.state.authenticated=false;f.state.authGeneration++;f.events.get('razvilka:auth-required')();finish(options());await pending;assert.equal(f.state.homeScope,null);assert.equal(f.e.optionsRead,null);
});
await check('explicit fresh read can resolve an unknown stored result without another mutation',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');let saved;
  f.setHandler(async call=>{saved=copy(call.body.policy);saved.revision=4;throw new Error('reply lost');});await f.c.saveListScope();assert.equal(f.e.unknown,true);
  const stored=review({revision:9,p:saved});f.setHandler(async call=>call.path.endsWith('/review')?stored:call.path.endsWith('/scope-options')?options({revision:9,policyRevision:4}):applied(stored));await f.c.refreshListScopeOptions(true);assert.equal(f.e.unknown,false);assert.equal(f.e.dirty,false);assert.equal(f.calls.filter(c=>c.method==='POST').length,1);assert.match(f.e.message,/применение ещё не подтверждено/);
});
await check('an in-flight Apply prevents policy writes without clearing the draft',async()=>{
  const f=fixture();f.c.listScopeChange('new_devices','base');f.state.applyRequest={};await f.c.saveListScope();assert.equal(f.calls.length,0);assert.equal(f.e.dirty,true);
});
await check('options capture is first-entry/explicit only and never common periodic polling',async()=>{
  const f=fixture();f.state.currentView='overview';f.setHandler(async call=>call.path.endsWith('/scope-options')?options():call.path.endsWith('/review')?review():applied());
  await f.c.refreshListScopeOptions();assert.equal(f.calls.length,0);f.state.currentView='devices';await f.c.refreshListScopeOptions();await f.c.refreshListScopeOptions();assert.equal(f.calls.filter(c=>c.path.endsWith('/scope-options')).length,1);await f.c.refreshListScopeOptions(true);assert.equal(f.calls.filter(c=>c.path.endsWith('/scope-options')).length,2);assert(!f.calls.some(c=>c.method==='POST'));
  const app=read('cmd/razvilka/web/app.js'),start=app.indexOf('function panelViewKeys('),end=app.indexOf('function refreshPanelView(',start);vm.runInContext(app.slice(start,end),f.c);
  for(const view of ['overview','services','devices','exclusions','onboard'])assert(!f.c.panelViewRequests(view).some(([,path])=>path?.endsWith('/scope-options')));
  assert(f.c.panelViewRequests('devices').some(([,path])=>path==='/api/v1/networkpolicy/review'));
});
await check('invalid options cannot replace retained data and labels cannot inject markup',()=>{
  const f=fixture(),bad=options();bad.effect_authorized=true;assert.throws(()=>f.c.acceptListScopeOptions(bad));assert.equal(f.state.homeScope.effect_authorized,false);f.state.homeScope.devices[0].label='<img src=x onerror=bad>';f.c.renderListScope();assert(!f.root.innerHTML.includes('<img'));assert.match(f.root.innerHTML,/&lt;img/);
});
await check('devices without a name show the host name or address, never only a raw ID',()=>{
  const f=fixture();f.state.homeScope.devices.push({id:'mac-aa-bb-cc-dd-ee-05',label:'mac-aa-bb-cc-dd-ee-05',segment_id:'br0',state:'observed',code:'',selection_candidate:true},{id:'mac-aa-bb-cc-dd-ee-06',label:'mac-aa-bb-cc-dd-ee-06',segment_id:'br0',state:'observed',code:'',selection_candidate:true});
  f.state.devices=[{id:'new-device',ips:['192.168.1.7']},{id:'mac-aa-bb-cc-dd-ee-05',hostname:'',ips:['fd00::5','192.168.1.5']},{id:'mac-aa-bb-cc-dd-ee-06',hostname:'nas',ips:['192.168.1.6']}];
  f.c.renderListScope();const html=f.root.innerHTML;
  assert.match(html,/192\.168\.1\.5/);assert.match(html,/>nas</);assert.match(html,/Компьютер/,'a router-known name is kept');
});
await check('bounded displayed choices preserve every negative ID and null/empty distinction',()=>{
  const f=fixture();f.state.homeScope.devices.push(...Array.from({length:400},(_,i)=>({id:`d-${i}`,label:`Device ${i}`,segment_id:'br0',state:'observed',code:'',selection_candidate:true})));f.c.renderListScope();assert((f.root.innerHTML.match(/data-scope-list="excluded_device_ids"/g)||[]).length<=102);assert.match(f.root.innerHTML,/gone-id/);assert.equal(f.e.draft.device_ids,null);assert.deepEqual(copy(f.e.draft.excluded_device_ids),policy.clients.excluded_device_ids);
});
await check('one shared editor is integrated; exclusions and wizard navigate to it',()=>{
  const html=read('cmd/razvilka/web/index.html');assert.equal((html.match(/id="listScopeContent"/g)||[]).length,1);assert(html.indexOf('/list-scope-ui.js?')<html.indexOf('/interface.js?'));assert.match(html,/Домашняя сеть и исключения устройств/);assert.match(read('cmd/razvilka/web/resource-exclusions-ui.js'),/Сайты без обхода/);
});
console.log(JSON.stringify({suite:'list-scope-ui',passed:checks}));
