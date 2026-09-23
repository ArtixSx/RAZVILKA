import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const nodeSource=fs.readFileSync('cmd/razvilka/web/node-browser.js','utf8');
const submitSource=nodeSource.slice(nodeSource.indexOf('let nodeCheckPendingRequest'),nodeSource.indexOf('async function pollNodeBrowserChecks'));
const source=fs.readFileSync('cmd/razvilka/web/workflow-actions.js','utf8');
const start=source.indexOf('function workflowAllVLESS(){');
const end=source.lastIndexOf('renderWorkflowControls();');
assert.ok(start>0&&end>start);
const code=source.slice(start,end);
let passed=0;
function fixture({capability=true,confirm=true,lostReply=false}={}){
 const calls=[], notices=[],nodes=Array.from({length:91},(_,i)=>({id:'n'+i,protocol:i<83?(i%2?'vless':' VLESS '):'Shadowsocks',disabled:false,state:'quarantined'}));
 const state={status:{revision:17},nodes:{nodes,generation:12},services:[{id:'telegram',name:'Telegram'}]},workflowState={bulkBusy:false,epoch:0};
 const nodeBrowser={job:null,source:'invisible-filter',visible:['n1'],page:3};
 let job=null,confirmHook=null;
 const saved=new Map();
 const ctx={state,workflowState,nodeBrowser,console,URL,Number,Set,Error,document:{},crypto:webcrypto,sessionStorage:{getItem:k=>saved.get(k),setItem:(k,v)=>saved.set(k,v),removeItem:k=>saved.delete(k)},nodeCanCheck:n=>!!n&&!n.disabled&&n.state!=='expired',
  $:()=>({value:'telegram'}),renderWorkflowControls(){},renderNodes(){},renderNodeBatchStatus(){},scheduleNodeBrowserRefresh(){},interfaceToast:m=>notices.push(m),workflowError:e=>e.message,
  workflowSession:e=>workflowState.epoch===e,
  askConfirmation:async()=>confirmHook?confirmHook():confirm,
  workflowRequest:async(path,options={})=>{
   calls.push({path,method:options.method||'GET',body:options.body?JSON.parse(options.body):null});
   if(path==='/api/v1/node-checks/current')return {all_vless:true,durable_all_vless:capability,job};
   if(path==='/api/v1/nodes')return state.nodes;
   if(path==='/api/v1/node-checks'){
    job={id:10,scope:'all-vless',service_id:'telegram',state:'running'};
    if(lostReply)throw new Error('lost reply');
    return {job};
   }
   throw new Error('unexpected API');
  }
 };
 ctx.api=ctx.workflowRequest;
 vm.createContext(ctx);vm.runInContext(submitSource+code,ctx);
 return {ctx,calls,notices,setConfirm:fn=>{confirmHook=fn},post:()=>calls.filter(x=>x.method==='POST')};
}
function ok(name,fn){fn();passed++;console.log('PASS '+name);}
let f=fixture();ok('all 83 VLESS across filters/pages, normalised protocol',()=>assert.equal(f.ctx.workflowAllVLESS().length,83));
await f.ctx.workflowCheckAllVLESS();
ok('one server-side selector, not a 64-ID page',()=>{assert.equal(f.post().length,1);assert.equal(f.post()[0].body.scope,'all-vless');assert.ok(!('node_ids' in f.post()[0].body));});
ok('explicit consent, generation and service',()=>{assert.equal(f.post()[0].body.confirm,'CHECK_ALL_VLESS');assert.equal(f.post()[0].body.generation,12);assert.equal(f.post()[0].body.service_id,'telegram')});
ok('durable revision and idempotency token included',()=>{assert.equal(f.post()[0].body.expected_revision,17);assert.match(f.post()[0].body.idempotency_key,/^[a-f0-9]{32}$/)});
ok('returned job adopted, submission flag cleared',()=>{assert.equal(f.ctx.nodeBrowser.job.id,10);assert.equal(f.ctx.workflowState.bulkBusy,false)});
f=fixture({capability:false});await f.ctx.workflowCheckAllVLESS();ok('old backend does not silently run a partial batch',()=>assert.equal(f.post().length,0));
f=fixture({confirm:false});await f.ctx.workflowCheckAllVLESS();ok('declined confirmation makes no POST',()=>assert.equal(f.post().length,0));
f=fixture();f.setConfirm(()=>{f.ctx.workflowState.epoch++;return true});await f.ctx.workflowCheckAllVLESS();ok('session change after dialog revokes submission',()=>assert.equal(f.post().length,0));
f=fixture({lostReply:true});await f.ctx.workflowCheckAllVLESS();ok('lost POST response uses GET, never replay',()=>{assert.equal(f.post().length,1);assert.equal(f.calls.at(-1).method,'GET');assert.equal(f.ctx.nodeBrowser.job.id,10)});
f=fixture();f.ctx.workflowState.bulkBusy=true;await f.ctx.workflowCheckAllVLESS();ok('double click rejected before any request',()=>assert.equal(f.calls.length,0));
f=fixture();f.ctx.nodeBrowser.job={state:'running'};await f.ctx.workflowCheckAllVLESS();ok('existing active job blocks submission',()=>assert.equal(f.calls.length,0));
ok('all-delete request and review are distinct from selected IDs',()=>{assert.match(source,/confirm:'DELETE_ALL_VLESS'/);assert.match(source,/review:intent\.result\.review/);assert.match(source,/result\.scope!=='all-vless'/)});
ok('no account credentials or localStorage added',()=>assert.doesNotMatch(code,/localStorage|vless:\/\//));
console.log(JSON.stringify({suite:'node-bulk-ui',passed}));
