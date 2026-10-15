import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const helper=readFileSync(new URL('../cmd/razvilka/web/panel-device-browse.js',import.meta.url),'utf8');
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
const extract=name=>{const match=app.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
function fixture(){
  let now=Date.parse('2026-10-16T10:00:00Z'),generation=1,handler;
  const elements=new Map(),listeners=new Map(),timers=new Map(),calls=[],writes=[];
  const state={authenticated:true,authGeneration:1,currentView:'devices',devices:[{id:'live-device',name:'Live',ips:['192.0.2.4'],discovered:true}],services:[{id:'video',name:'Video',route:'auto',sources:[]}],dataLoad:{devices:{phase:'busy'},services:{phase:'ready'}}};
  function $(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',innerHTML:'',hidden:true,style:{},open:false,
    showModal(){this.open=true;},close(){this.open=false;},focus(){},querySelector(selector){return $(id+selector);}});return elements.get(id);}
  const context={state,$,Date:class extends Date{constructor(value){super(value===undefined?now:value);}static now(){return now;}},console,
    document:{hidden:false,addEventListener(name,fn){listeners.set(name,[...(listeners.get(name)||[]),fn]);}},
    panelLoad:{generation:1},panelSnapshotCurrent:value=>value===generation,
    cancelPanelRefresh:()=>{generation++;},showAuth:()=>{state.authenticated=false;for(const fn of listeners.get('razvilka:auth-required')||[])fn({});},
    setTimeout(fn,delay){const key=timers.size+1;timers.set(key,{fn,delay});return key;},clearTimeout:key=>timers.delete(key),
    esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),routeLabel:value=>value,
    api:async(url,options={})=>{calls.push({url,...options});return handler(url,options);},
    askConfirmation:async()=>true,serviceDraftBody:(service,body)=>body,writeServiceDraft:async(...args)=>writes.push(args),
    refreshCoreAfterEdit:async()=>{},showPlan:async()=>{},showDetails(){},panelBusy:error=>error?.status===409,
  };
  vm.createContext(context);
  vm.runInContext(helper+'\n'+['deviceDisplayName','deviceAddressesHTML','acceptDeviceList','panelSectionState','renderDevices','openDeviceEdit','saveDeviceEdit','openDevicePolicy','updateDevicePolicyForm','saveDevicePolicy'].map(extract).join('\n'),context);
  context.refreshDevices=async()=>{};
  const envelope=(revision=1,instance='a'.repeat(32))=>({schema:1,instance_id:instance,revision,generated_at:new Date(now-2000).toISOString(),observed_at:new Date(now).toISOString(),data_age_ms:2000,max_age_seconds:900,state:'retained',dataplane:'not-checked',data:{devices:[{id:'saved-device',name:'<Saved>',group:'Work',known_addresses:['192.0.2.9','2001:db8::9'],last_seen_at:'2026-10-15T08:00:00Z'}]}});
  handler=async()=>envelope();
  return {context,state,$,calls,writes,timers,envelope,handler:fn=>{handler=fn;},advance:ms=>{now+=ms;},
    runtime:()=>vm.runInContext('deviceBrowseRuntime',context),logout:()=>context.showAuth(),
    dispatch:(name,event={})=>{for(const fn of listeners.get(name)||[])fn(event);}};
}
let count=0;
async function test(name,fn){await fn();count++;console.log('PASS '+name);}

await test('busy/fenced browse preserves historical fields without creating live identity or actions',async()=>{
  const f=fixture(),original=f.state.devices;
  await f.context.loadSavedDeviceBrowse(1);
  assert.equal(f.state.devices,original);assert.equal(f.state.devices[0].id,'live-device');
  const card=f.$('#deviceGrid').innerHTML;
  assert.match(card,/&lt;Saved>/);assert.match(card,/Известные ранее адреса/);assert.match(card,/Последнее обнаружение \(из сохранённых данных\)/);
  assert.doesNotMatch(card,/<button|<input|<select|data-device|online|offline|В СЕТИ|ОФЛАЙН|PASS|device-policy|device-edit/);
  assert.match(f.$('#deviceBrowseNotice').textContent,/Снимок сохранённых данных · создан 2 сек назад/);
  for(const phase of ['busy','error','loading']){f.context.panelSectionState('devices',phase);f.context.renderDevices();assert.match(f.$('#deviceGrid').innerHTML,/СОХРАНЕНО/);}
  f.$('#deviceSearch').value='2001:db8';f.context.renderDevices();assert.match(f.$('#deviceGrid').innerHTML,/192.0.2.9/);
  f.$('#deviceSearch').value='missing';f.context.renderDevices();assert.equal(f.$('#deviceGrid').innerHTML,'');assert.match(f.$('#deviceEmptystrong').textContent,/сохранённых/);
  f.$('#deviceSearch').value='';f.context.openDeviceEdit('live-device');f.context.openDevicePolicy('live-device');
  await f.context.saveDeviceEdit({preventDefault(){}});await f.context.saveDevicePolicy({preventDefault(){}});
  assert.equal(f.calls.filter(call=>call.method).length,0);assert.equal(f.writes.length,0);
});

await test('late fallback never replaces fresh live cards and old revisions cannot replace newer history',async()=>{
  const f=fixture(),pending=deferred();f.handler(()=>pending.promise);
  const read=f.context.loadSavedDeviceBrowse(1);f.context.panelSectionState('devices','ready');f.context.renderDevices();
  pending.resolve(f.envelope(2));await read;
  assert.match(f.$('#deviceGrid').innerHTML,/Live/);assert.doesNotMatch(f.$('#deviceGrid').innerHTML,/Saved/);assert.equal(f.$('#deviceBrowseNotice').hidden,true);
  f.context.panelSectionState('devices','busy');f.handler(async()=>f.envelope(1));await f.context.loadSavedDeviceBrowse(1);
  f.context.renderDevices();assert.equal(f.runtime().saved.value.revision,2);
});

await test('saved transition closes open editors and fences policy confirmation even after live returns',async()=>{
  const f=fixture();f.context.panelSectionState('devices','ready');f.context.renderDevices();
  f.context.openDeviceEdit('live-device');assert.equal(f.$('#deviceEditDialog').open,true);
  const confirm=deferred();f.context.askConfirmation=()=>confirm.promise;
  f.$('#devicePolicyID').value='live-device';f.$('#devicePolicyService').value='video';f.$('#devicePolicyScope').value='device';f.$('#devicePolicyDialog').open=true;
  const saving=f.context.saveDevicePolicy({preventDefault(){}});
  f.context.panelSectionState('devices','busy');await f.context.loadSavedDeviceBrowse(1);
  assert.equal(f.$('#deviceEditDialog').open,false);assert.equal(f.$('#devicePolicyDialog').open,false);assert.equal(f.$('#deviceEditID').value,'');
  f.context.panelSectionState('devices','ready');f.context.renderDevices();confirm.resolve(true);await saving;
  assert.equal(f.writes.length,0,'old confirmation wrote after read-only transition');
});

await test('ordinary loading preserves typed fields but fences saves and old confirmations',async()=>{
  const f=fixture();f.context.panelSectionState('devices','ready');f.context.renderDevices();
  f.context.openDeviceEdit('live-device');f.$('#deviceEditName').value='Typed name';f.$('#deviceEditGroup').value='Typed group';
  f.$('#devicePolicyDialog').open=true;f.$('#devicePolicyID').value='live-device';f.$('#devicePolicyService').value='video';f.$('#devicePolicyScope').value='device';
  const confirm=deferred();f.context.askConfirmation=()=>confirm.promise;const saving=f.context.saveDevicePolicy({preventDefault(){}});
  f.context.panelSectionState('devices','loading');f.context.renderDevices();await f.context.saveDeviceEdit({preventDefault(){}});
  assert.equal(f.$('#deviceEditDialog').open,true);assert.equal(f.$('#devicePolicyDialog').open,true);
  assert.equal(f.$('#deviceEditName').value,'Typed name');assert.equal(f.$('#deviceEditGroup').value,'Typed group');
  assert.match(f.$('#deviceBrowseNotice').textContent,/Обновляем/);assert.match(f.$('#deviceGrid').innerHTML,/type="button" disabled/);
  assert.equal(f.$('#deviceEditFormbutton[type="submit"]').disabled,true);
  f.context.panelSectionState('devices','ready');f.context.renderDevices();confirm.resolve(true);await saving;
  assert.equal(f.writes.length,0);assert.equal(f.calls.filter(call=>call.method).length,0);
  assert.equal(f.$('#deviceEditName').value,'Typed name');assert.equal(f.context.deviceBrowseMutationAllowed(),true);
  assert.equal(f.$('#deviceEditFormbutton[type="submit"]').disabled,false);
});

await test('empty live read restores live empty copy after saved expiry and filtered fallback',async()=>{
  const f=fixture();await f.context.loadSavedDeviceBrowse(1);f.$('#deviceSearch').value='missing';f.context.renderDevices();
  assert.match(f.$('#deviceEmptystrong').textContent,/сохранённых/);
  f.$('#deviceSearch').value='';f.advance(900000);f.context.renderDevices();
  f.context.acceptDeviceList({devices:[]});f.context.panelSectionState('devices','ready');f.context.renderDevices();
  assert.equal(f.$('#deviceEmptystrong').textContent,'Устройства пока не обнаружены');
  assert.match(f.$('#deviceEmptyspan').textContent,/Подключите устройство/);assert.equal(f.$('#deviceBrowseNotice').hidden,true);
});

await test('auth change fences delayed bodies and clears private historical presentation',async()=>{
  const f=fixture();await f.context.loadSavedDeviceBrowse(1);
  const late=deferred();f.handler(()=>late.promise);const read=f.context.loadSavedDeviceBrowse(1);
  f.logout();late.resolve(f.envelope(2));await read;f.context.renderDevices();
  assert.equal(f.runtime().saved,null);assert.equal(f.$('#deviceGrid').innerHTML,'');assert.equal(f.$('#deviceBrowseNotice').hidden,true);
  for(const status of [401,403]){const denied=fixture();await denied.context.loadSavedDeviceBrowse(1);denied.handler(async()=>{throw Object.assign(new Error('denied'),{status});});await denied.context.loadSavedDeviceBrowse(1);assert.equal(denied.state.authenticated,false);assert.equal(denied.runtime().saved,null);assert.equal(denied.$('#deviceGrid').innerHTML,'');}
});

await test('mutation invalidation rejects in-flight and old backend publications until a new capture',async()=>{
  const f=fixture();await f.context.loadSavedDeviceBrowse(1);const old=f.envelope(2),late=deferred();
  f.handler(()=>late.promise);const read=f.context.loadSavedDeviceBrowse(1);f.context.invalidateSavedDeviceBrowse(true);late.resolve(old);await read;
  assert.equal(f.runtime().saved,null);
  f.handler(async()=>old);await f.context.loadSavedDeviceBrowse(1);assert.equal(f.runtime().saved,null);
  f.advance(3000);f.handler(async()=>f.envelope(3));await f.context.loadSavedDeviceBrowse(1);assert.equal(f.runtime().saved.value.revision,3);
  assert.match(app,/invalidateSavedDeviceBrowse\(!url.startsWith\('\/api\/v1\/auth\/'\)\)/);
});

await test('TTL expires locally without another response and empty/expired do not claim deleted devices',async()=>{
  const f=fixture();await f.context.loadSavedDeviceBrowse(1);f.advance(898000);f.context.renderDevices();
  assert.equal(f.$('#deviceGrid').innerHTML,'');assert.equal(f.runtime().saved,null);assert.match(f.$('#deviceBrowseNotice').textContent,/не означает.*удалены/);
  for(const state of ['empty','expired']){const value={...f.envelope(4),state};delete value.data;f.handler(async()=>value);await f.context.loadSavedDeviceBrowse(1);assert.equal(f.$('#deviceGrid').innerHTML,'');}
  f.handler(async()=>({schema:1,instance_id:'',revision:0,generated_at:null,observed_at:f.envelope().observed_at,data_age_ms:0,max_age_seconds:900,state:'empty',dataplane:'not-checked'}));
  await f.context.loadSavedDeviceBrowse(1);assert.equal(f.runtime().saved,null);assert.match(f.$('#deviceBrowseNotice').textContent,/не означает.*удалены/);
  const backward=fixture();await backward.context.loadSavedDeviceBrowse(1);backward.advance(-1000);backward.context.renderDevices();assert.equal(backward.runtime().saved,null,'clock rollback prolonged snapshot TTL');
});

await test('restart replaces only saved process provenance and malformed or proof-bearing DTO is refused',async()=>{
  const f=fixture();await f.context.loadSavedDeviceBrowse(1);const original=f.state.devices;
  f.handler(async()=>f.envelope(1,'b'.repeat(32)));await f.context.loadSavedDeviceBrowse(1);
  assert.equal(f.runtime().instance,'b'.repeat(32));assert.equal(f.state.devices,original);
  for(const change of [value=>{value.data.devices[0].online=true;},value=>{value.data.devices[0].policies=[];},value=>{value.generated_at='2000-01-01T00:00:00Z';},value=>{value.revision=Number.MAX_SAFE_INTEGER+1;},value=>{value.data_age_ms=-1;},value=>{value.instance_id='bad';}]){
    const value=f.envelope(3);change(value);assert.equal(f.context.validSavedDeviceBrowse(value),false);
  }
  const many=f.envelope(4);many.data.devices[0].known_addresses=Array.from({length:300},(_,i)=>'2001:db8::'+i.toString(16));
  assert.equal(f.context.validSavedDeviceBrowse(many),true,'many historical IPv6 addresses were discarded');
});

assert(html.indexOf('/panel-device-browse.js?')<html.indexOf('/app.js?'));
assert.match(html,/id="deviceBrowseNotice" role="status"/);
assert(readFileSync(new URL('check.sh',import.meta.url),'utf8').includes('test-panel-device-browse-ui.mjs'));
console.log(`Device saved browse: ${count} modeled lifecycle checks passed (no native/browser claim)`);
