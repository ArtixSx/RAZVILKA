import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const helper=readFileSync(new URL('../cmd/razvilka/web/panel-community-browse.js',import.meta.url),'utf8');
const extract=name=>{const match=app.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0];};
const deferred=()=>{let resolve;const promise=new Promise(done=>resolve=done);return {promise,resolve};};
function fixture(){
  let now=Date.parse('2026-10-16T12:00:00Z'),memory,live,canceled=0;
  const elements=new Map(),listeners=new Map(),timers=new Map(),calls=[];
  const $=id=>{if(!elements.has(id))elements.set(id,{value:'',textContent:'',innerHTML:'',hidden:false,open:true,disabled:false,showModal(){this.open=true;},close(){this.open=false;},focus(){}});return elements.get(id);};
  const state={authenticated:true,authGeneration:1,status:{},community:[{id:'old-live',name:'Old live',category:'Test'}],communityPreview:null};
  const workflowState={epoch:1,communitySeq:0,communityImport:false};
  const context={state,$,workflowState,console,Date:class extends Date{constructor(value){super(value===undefined?now:value);}static now(){return now;}},
    document:{hidden:false,addEventListener(name,fn,capture){listeners.set(name,[...(listeners.get(name)||[]),{fn,capture}]);},querySelectorAll:()=>[]},
    workflowSession:epoch=>state.authenticated&&epoch===workflowState.epoch,workflowError:error=>error.message,
    api:async(path,options={})=>{calls.push({path,...options});return memory(path,options);},
    workflowRequest:async(path,options={})=>{calls.push({path,...options});return live(path,options);},
    cancelCustomSource:()=>{canceled++;},askConfirmation:async()=>true,refreshCoreAfterEdit:async()=>{},interfaceToast(){},interfaceManage:async()=>{},
    $$:()=>[],communityEntryIcon:()=>'',accessLabel:()=>'',consoleSnapshot:null,
    esc:value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),
    setTimeout(fn,delay){const key=timers.size+1;timers.set(key,{fn,delay});return key;},clearTimeout:key=>timers.delete(key),
    showAuth:()=>{state.authenticated=false;workflowState.epoch++;for(const {fn} of listeners.get('razvilka:auth-required')||[])fn({});},
  };
  vm.createContext(context);vm.runInContext(helper+'\n'+['searchCommunityCatalog','closeCommunityCatalog','renderCommunityResults','previewCommunityService','renderCommunityPreview','importCommunityService'].map(extract).join('\n'),context);
  const envelope=(revision=1,instance='a'.repeat(32))=>({schema:1,instance_id:instance,revision,generated_at:new Date(now-2000).toISOString(),observed_at:new Date(now).toISOString(),data_age_ms:2000,max_age_seconds:900,state:'retained',dataplane:'not-checked',data:{entries:[{id:'saved',name:'<Saved>',category:'Work',description:'Historical display only'}]}});
  memory=async()=>envelope();live=async()=>{throw Object.assign(new Error('busy'),{status:409});};
  return {context,state,workflowState,$,calls,listeners,timers,envelope,runtime:()=>vm.runInContext('communityBrowse',context),
    memory:fn=>{memory=fn;},live:fn=>{live=fn;},advance:ms=>{now+=ms;},canceled:()=>canceled};
}
let count=0;async function test(name,fn){await fn();count++;console.log('PASS '+name);}

await test('busy live list renders separate historical definitions and local search with no actions',async()=>{
  const f=fixture(),original=f.state.community;f.$('#communityOwnURL').value='private pending source';
  await f.context.searchCommunityCatalog(true);
  assert.equal(f.state.community,original);assert.equal(f.state.communityPreview,null);assert.equal(f.$('#communityOwnForm').hidden,true);
  const html=f.$('#communityResults').innerHTML;assert.match(html,/&lt;Saved>/);assert.match(html,/Historical display/);
  assert.doesNotMatch(html,/<button|<input|<select|data-community|PREVIEW|ДОБАВЛЕН|SHA|blocked|access-/);
  assert.match(f.$('#communityBrowseNotice').textContent,/Снимок каталога в памяти/);assert.match(f.$('#communityBrowseNotice').textContent,/не обновления источника/);
  const calls=f.calls.length;f.$('#communitySearch').value='no match';await f.context.searchCommunityCatalog();assert.equal(f.calls.length,calls);assert.match(f.$('#communityResults').innerHTML,/Ничего не найдено/);
  f.$('#communitySearch').value='historical';await f.context.searchCommunityCatalog();assert.match(f.$('#communityResults').innerHTML,/Saved/);
  await f.context.previewCommunityService('saved');await f.context.importCommunityService('saved');assert.equal(f.calls.length,calls);
  assert.equal(f.$('#communityOwnURL').value,'private pending source','read-only transition erased typed source');
});

await test('late memory response never replaces successful live search or its actionable list',async()=>{
  const f=fixture(),pending=deferred(),rows=[{id:'fresh',name:'Fresh live',category:'Test'}];f.memory(()=>pending.promise);f.live(async()=>rows);
  await f.context.searchCommunityCatalog(true);assert.equal(f.state.community,rows);assert.equal(f.context.communityBrowseActionsAllowed(),true);
  pending.resolve(f.envelope());await new Promise(resolve=>setImmediate(resolve));
  assert.match(f.$('#communityResults').innerHTML,/Fresh live/);assert.doesNotMatch(f.$('#communityResults').innerHTML,/Saved/);assert.equal(f.$('#communityBrowseNotice').hidden,true);
});

await test('accepted live catalog replaces only the empty retained preview notice',async()=>{
  const f=fixture(),pending=deferred();f.live(()=>pending.promise);
  const searching=f.context.searchCommunityCatalog(true);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.runtime().showing,true);
  assert.match(f.$('#communityPreview').textContent,/Сохранённые определения/);
  pending.resolve([{id:'telegram',name:'Telegram',category:'Messaging'}]);await searching;
  assert.equal(f.context.communityBrowseActionsAllowed(),true);
  assert.match(f.$('#communityPreview').innerHTML,/Выберите сервис/);
  assert.doesNotMatch(f.$('#communityPreview').innerHTML,/Сохранённые определения/);
  assert.match(f.$('#communityResults').innerHTML,/ПРОСМОТР/);
  assert.doesNotMatch(f.$('#communityResults').innerHTML,/PREVIEW/);
  // Searching the now-live list preserves the ready empty-state message.
  f.$('#communitySearch').value='Telegram';f.live(async()=>[{id:'telegram',name:'Telegram'}]);
  await f.context.searchCommunityCatalog(true);
  assert.match(f.$('#communityPreview').innerHTML,/Выберите сервис/);
  assert.equal(f.calls.filter(call=>call.method==='POST').length,0);
});

await test('live list refresh and late retained metadata preserve a user-selected preview',async()=>{
  const f=fixture();await f.context.searchCommunityCatalog(true);
  const selected={entry:{id:'telegram'},service:{domains:['telegram.org']}};
  f.state.communityPreview=selected;f.$('#communityPreview').innerHTML='<div>Selected Telegram details</div>';
  f.live(async()=>[{id:'telegram',name:'Telegram'}]);await f.context.searchCommunityCatalog(true);
  assert.equal(f.state.communityPreview,selected);
  assert.equal(f.$('#communityPreview').innerHTML,'<div>Selected Telegram details</div>');
  // A retained response arriving after live acceptance is presentation-only.
  f.memory(async()=>f.envelope(2));await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);
  assert.equal(f.state.communityPreview,selected);
  assert.equal(f.$('#communityPreview').innerHTML,'<div>Selected Telegram details</div>');
});

await test('native click event filters saved rows and only literal true forces a live retry',async()=>{
  const f=fixture();await f.context.searchCommunityCatalog(true);
  const listCalls=()=>f.calls.filter(call=>call.path.startsWith('/api/v1/community/services?')).length;
  const before=listCalls();f.$('#communitySearch').value='no match';
  // addEventListener passes this truthy Event as the handler's first argument.
  await f.context.searchCommunityCatalog(new Event('click'));
  assert.equal(listCalls(),before,'click event accidentally forced live catalog admission');
  assert.match(f.$('#communityResults').innerHTML,/Ничего не найдено/);
  await f.context.searchCommunityCatalog(true);
  assert.equal(listCalls(),before+1,'explicit read retry stopped requesting a live list');
});

await test('saved transition fences pending preview and delayed import confirmation after live returns',async()=>{
  const f=fixture();f.context.communityBrowseLiveAccepted();const pending=deferred();f.live(()=>pending.promise);
  const previewing=f.context.previewCommunityService('old-live');await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);
  f.context.communityBrowseUnavailable({status:503});pending.resolve({entry:{id:'old-live'},service:{domains:['old']}});await previewing;
  // Even an already running preview cannot restore actions to a saved image.
  assert.equal(f.state.communityPreview,null);assert.equal(f.context.communityBrowseActionsAllowed(),false);
  f.context.communityBrowseLiveAccepted();const preview={entry:{id:'old-live'},import_guard:'source-sha256',source_sha256:'b'.repeat(64),conflicts:[{}]};f.state.communityPreview=preview;
  const confirm=deferred();f.context.askConfirmation=()=>confirm.promise;const importing=f.context.importCommunityService('old-live');
  f.context.communityBrowseUnavailable({status:409});f.context.communityBrowseLiveAccepted();confirm.resolve(true);await importing;
  assert.equal(f.calls.filter(call=>call.method==='POST').length,0);
});

await test('source-form capture guard blocks preview submit while historical and preserves fields',async()=>{
  const f=fixture();await f.context.searchCommunityCatalog(true);let prevented=0,stopped=0;
  const captures=f.listeners.get('submit').filter(row=>row.capture);assert.equal(captures.length,1);
  captures[0].fn({target:{id:'communityOwnForm'},preventDefault(){prevented++;},stopImmediatePropagation(){stopped++;}});
  assert.equal(prevented,1);assert.equal(stopped,1);assert(f.canceled()>0);
  f.context.communityBrowseLiveAccepted();captures[0].fn({target:{id:'communityOwnForm'},preventDefault(){prevented++;},stopImmediatePropagation(){stopped++;}});assert.equal(prevented,1);
});

await test('auth denial and logout clear presentation and reject delayed protected bodies',async()=>{
  const f=fixture();await f.context.searchCommunityCatalog(true);const pending=deferred();f.memory(()=>pending.promise);
  const read=f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);f.context.showAuth();pending.resolve(f.envelope(2));await read;
  assert.equal(f.runtime().saved,null);assert.equal(f.$('#communityResults').textContent,'');assert.equal(f.state.community.length,0);
  for(const status of [401,403]){const x=fixture();x.memory(async()=>{throw Object.assign(new Error('denied'),{status});});await x.context.loadSavedCommunityBrowse(0,1);assert.equal(x.state.authenticated,false);assert.equal(x.runtime().saved,null);}
});

await test('capture TTL and clock rollback expire historical cards without enabling source or import',async()=>{
  for(const elapsed of [898000,-1000]){const f=fixture();await f.context.searchCommunityCatalog(true);f.advance(elapsed);f.context.renderSavedCommunityBrowse();assert.equal(f.runtime().saved,null);assert.doesNotMatch(f.$('#communityResults').innerHTML,/Saved/);assert.match(f.$('#communityBrowseNotice').textContent,/не означает.*удалены/);assert.equal(f.$('#communityOwnForm').hidden,true);assert.equal(f.context.communityBrowseActionsAllowed(),false);}
});

await test('mutation, process and revision fences preserve only current display bytes',async()=>{
  const f=fixture();await f.context.searchCommunityCatalog(true);const old=f.envelope(2),pending=deferred();f.memory(()=>pending.promise);
  const read=f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);f.context.invalidateSavedCommunityBrowse(true);pending.resolve(old);await read;assert.equal(f.runtime().saved,null);
  f.memory(async()=>old);await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);assert.equal(f.runtime().saved,null);
  f.advance(3000);f.memory(async()=>f.envelope(3));await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);assert.equal(f.runtime().revision,3);
  f.memory(async()=>f.envelope(2));await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);assert.equal(f.runtime().revision,3);
  f.context.communityBrowseLiveAccepted();f.memory(async()=>f.envelope(1,'b'.repeat(32)));await f.context.loadSavedCommunityBrowse(f.workflowState.communitySeq,1);
  assert.equal(f.runtime().instance,'b'.repeat(32));assert.equal(f.context.communityBrowseActionsAllowed(),true,'late process metadata overrode fresh live search');
});

await test('unknown source/proof DTO fields and oversized or old-success bodies grant no presentation',async()=>{
  const f=fixture();for(const change of [v=>{v.data.entries[0].source_sha256='a'.repeat(64);},v=>{v.data.entries[0].access={status:'blocked'};},v=>{v.data.entries[0].name='a'.repeat(513);},v=>{v.generated_at='2000-01-01T00:00:00Z';},v=>{v.data_age_ms=-1;}]){const value=f.envelope();change(value);assert.equal(f.context.validSavedCommunityBrowse(value),false);}
  await f.context.searchCommunityCatalog(true);f.context.closeCommunityCatalog();assert.equal(f.timers.size,0);
});

assert.match(app,/invalidateSavedCommunityBrowse\(!url.startsWith\('\/api\/v1\/auth\/'\)\)/);
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');assert(html.indexOf('/panel-community-browse.js?')<html.indexOf('/app.js?'));
assert(readFileSync(new URL('check.sh',import.meta.url),'utf8').includes('test-panel-community-browse-ui.mjs'));
console.log(`Community saved browse: ${count} modeled checks passed; no native/browser claim`);
