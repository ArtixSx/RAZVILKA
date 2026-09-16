import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const src=fs.readFileSync('cmd/razvilka/web/setup-workflows.js','utf8');
const html=fs.readFileSync('cmd/razvilka/web/index.html','utf8');
let passed=0;const test=(name,fn)=>{fn();passed++;console.log('PASS '+name)};
function fixture(){
 const els=new Map(),calls=[],details=[],docEvents=new Map();
 const el=id=>{if(!els.has(id))els.set(id,{id,value:'',checked:false,disabled:false,hidden:false,open:true,textContent:'',innerHTML:'',files:[],events:new Map(),addEventListener(k,f){this.events.set(k,f)},setAttribute(){},replaceChildren(){this.innerHTML=''},parentElement:{before(){}}});return els.get(id)};
 const state={status:{safe_mode:false,revision:1},components:[],services:[{id:'one',enabled:true,route:'warp-wg'}],communityPreview:null};
 const workflowState={epoch:1,communitySeq:0,communityImport:false};
 let selected='amneziawg',response=null,requestHook=null,refreshHook=null;
 const ctx={console,state,workflowState,TextEncoder,AbortController,Number,Set,Error,
  $:q=>el(q.replace(/^#/,'')),document:{createElement:()=>el('created'),addEventListener:(k,f)=>docEvents.set(k,f)},
  selectedEngineView:()=>({id:selected}),workflowSession:e=>e===workflowState.epoch,
  refreshComponents:async()=>refreshHook?.(),showDetails:(d,t)=>details.push({d,t}),manageComponent:async(id,action)=>calls.push({id,action}),workflowError:e=>e.message,
  workflowRequest:async(path,o={})=>{calls.push({path,options:o});return requestHook?await requestHook():response},renderCommunityPreview:()=>calls.push({render:true})};
 vm.createContext(ctx);vm.runInContext(src,ctx);el('communityOwnFormat').value='domains';el('communityOwnName').value='Example';el('communityOwnText').value='example.org';el('warpMinFailedServices').value='2';
 return {ctx,els,el,calls,details,docEvents,setResponse:r=>response=r,setRequest:f=>requestHook=f,setRefresh:f=>refreshHook=f,select:s=>selected=s,submit:()=>el('communityOwnForm').events.get('submit')({preventDefault(){}})};
}
let f=fixture();f.el('warpHealthEnabled').value='false';f.el('warpAutoApply').checked=true;f.ctx.repairWarpDependencies(f.el('warpAutoApply'));
test('select auto apply enables policy and candidate in draft',()=>{assert.equal(f.el('warpHealthEnabled').value,'true');assert.equal(f.el('warpAutoCandidate').checked,true)});
test('never grants Cloudflare TOS or makes a network write',()=>{assert.equal(f.el('warpHealthAcceptTOS').checked,false);assert.equal(f.el('warpAcceptTOS').checked,false);assert.equal(f.calls.length,0)});
test('one assigned WARP service with threshold two is explained',()=>assert.match(f.el('warpPolicyGuide').textContent,/порог отказов — 2/));
f.el('warpHealthEnabled').value='false';f.ctx.repairWarpDependencies(f.el('warpHealthEnabled'));
test('disable clears dependent operations, not secret permissions',()=>{for(const id of ['warpAutoApply','warpAutoCandidate','warpAllowAccountRefresh'])assert.equal(f.el(id).checked,false)});
f=fixture();f.ctx.state.components=[{id:'amneziawg',name:'AWG',provider:'platform',installed:false,available:false}];f.setResponse({can_install:false});await f.ctx.openEngineInstallation('amneziawg');
test('unsupported AWG displays selected compatibility plan, never installs',()=>{assert.equal(f.calls.length,1);assert.match(f.calls[0].path,/components\/amneziawg\/plan/);assert.equal(f.details.length,1)});
f=fixture();f.ctx.state.components=[{id:'amneziawg',installed:true}];await f.ctx.openEngineInstallation('amneziawg');test('installed component is not reinstalled',()=>assert.equal(f.calls.length,0));
f=fixture();f.ctx.state.components=[{id:'amneziawg',external_owner:true}];await f.ctx.openEngineInstallation('amneziawg');test('external component is not adopted',()=>assert.equal(f.calls.length,0));
f=fixture();f.ctx.state.components=[{id:'sing-box',name:'Sing-box',provider:'opkg',available:true}];await f.ctx.openEngineInstallation('sing-box');test('available selected component enters existing reviewed install workflow',()=>assert.deepEqual(f.calls,[{id:'sing-box',action:'install'}]));
f=fixture();f.setRefresh(()=>{f.ctx.workflowState.epoch++;f.ctx.state.components=[{id:'sing-box',available:true}]});await f.ctx.openEngineInstallation('sing-box');test('auth epoch after refresh blocks install',()=>assert.equal(f.calls.length,0));
f=fixture();f.setResponse({entry:{id:'adhoc-x'},import_guard:'source-sha256',source_sha256:'a'.repeat(64)});await f.submit();
test('pasted source posts data preview once, not import or Apply',()=>{assert.equal(f.calls.filter(x=>x.path).length,1);assert.equal(f.calls[0].path,'/api/v1/community/source-preview');const b=JSON.parse(f.calls[0].options.body);assert.equal(b.content,'example.org');assert.equal(b.expected_revision,1)});
test('preview accepted only with SHA contract',()=>assert.equal(f.ctx.state.communityPreview.source_sha256,'a'.repeat(64)));
f=fixture();f.setResponse({entry:{id:'adhoc-x'},source_sha256:'a'.repeat(64)});await f.submit();test('missing backend guard never creates import authority',()=>assert.equal(f.ctx.state.communityPreview,null));
f=fixture();f.el('communityOwnURL').value='https://github.com/a/b/blob/main/x';await f.submit();test('both URL and text rejected before network',()=>assert.equal(f.calls.length,0));
f=fixture();f.el('communityOwnText').value='a'.repeat(256*1024+1);await f.submit();test('oversized paste rejected',()=>assert.equal(f.calls.length,0));
f=fixture();let resolve;f.setRequest(()=>new Promise(r=>resolve=r));const pending=f.submit();f.ctx.workflowState.epoch++;f.docEvents.get('razvilka:auth-required')();resolve({entry:{id:'adhoc-x'},import_guard:'source-sha256',source_sha256:'a'.repeat(64)});await pending;test('late preview after logout not accepted and text cleared',()=>{assert.equal(f.ctx.state.communityPreview,null);assert.equal(f.el('communityOwnText').value,'')});
f=fixture();f.ctx.state.communityPreview={entry:{id:'adhoc-x'}};f.ctx.invalidateCustomSource();test('edited source invalidates reviewed image',()=>assert.equal(f.ctx.state.communityPreview,null));
test('single WARP manager and canonical warp-wg placement',()=>{assert.equal((html.match(/id="warpManager"/g)||[]).length,1);const app=fs.readFileSync('cmd/razvilka/web/app.js','utf8');assert.ok(/state.selectedEngine\s*===\s*'warp-wg'/.test(app),'canonical placement');const awg=fs.readFileSync('cmd/razvilka/web/awg-workspace.js','utf8');assert.match(awg,/selectEngine\('warp-wg'\)/)});
test('master shows explicit extras and sends one combined request',()=>{const a=fs.readFileSync('cmd/razvilka/web/console-autonomy.js','utf8');assert.match(a,/initial_service_ids/);assert.match(a,/starter_sha256/);assert.match(a,/!s.default_nfqws2/)});

const appSource=fs.readFileSync('cmd/razvilka/web/app.js','utf8');const noticeCode=appSource.slice(appSource.indexOf('function noticeBelongsOnlyToEngine('),appSource.indexOf('async function selectEngine('));const notice=vm.runInNewContext(noticeCode+';noticeBelongsOnlyToEngine');
test('unused NFQ prompt can be hidden on another engine only',()=>{assert.equal(notice({transaction:{blockers:[{code:'ENGINE_DRAFT_UNUSED',adapter:'nfqws2'}]}},'nfqws2'),true);assert.equal(notice({transaction:{blockers:[{code:'ENGINE_DRAFT_UNUSED',adapter:'nfqws2'},{code:'OTHER',adapter:'warp-wg'}]}},'nfqws2'),false);assert.equal(notice({error:'rollback failed'},'nfqws2'),false)});
console.log(JSON.stringify({suite:'setup-repair',passed}));
