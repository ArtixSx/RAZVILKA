import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const app=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const browser=readFileSync(new URL('../cmd/razvilka/web/node-browser.js',import.meta.url),'utf8');
const helper=app.slice(app.indexOf('async function apiDataMutation('),app.indexOf('async function api(url,'));
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function fixture(){
 const fields=new Map(),requests=[],timers=new Map();let timerID=0,confirmed=false,confirmations=0;
 const $=id=>{if(!fields.has(id))fields.set(id,{value:'',hidden:false,disabled:false,checked:false,textContent:'',innerHTML:'',close(){this.open=false;},classList:{remove(){},add(){}},querySelectorAll:()=>[]});return fields.get(id);};
 $('#authScreen').hidden=true;
 for(const [id,value] of Object.entries({nodeFeedPreset:'custom',nodeFeedLimit:'2',nodeFeedInterval:'60',nodeFeedName:'Original',nodeFeedURL:'https://original.example/list',nodeFeedFormat:'uri-lines'}))$('#'+id).value=value;
 const ctx={state:{authGeneration:1,currentView:'providers'},AbortController,document:{hidden:false},$,$$:()=>[],
  setTimeout(fn,ms){const id=++timerID;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),
  askConfirmation:async()=>{confirmations++;return confirmed;},
  api(path,options={}){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});requests.push({path,options,resolve,reject});return promise;}};
 vm.createContext(ctx);vm.runInContext(helper+browser+'\nthis.browser=nodeBrowser;this.renderNodeSubscriptions=()=>{};this.renderNodes=()=>{};this.pollNodeBrowserChecks=async()=>{};this.closeNodeCheck=()=>{};this.clearNodeReveal=()=>{};',ctx);
 return {ctx,$,requests,timers,confirm:()=>{confirmed=true;},confirmations:()=>confirmations,
  async deadline(){const entry=[...timers].find(([,t])=>t.ms===20000);assert.ok(entry,'20s deadline absent');timers.delete(entry[0]);entry[1].fn();await flush();},
  save:()=>ctx.saveNodeSubscription({preventDefault(){}})};
}
{
 const f=fixture();
 for(const [path,method] of [['/api/v1/apply','POST'],['/api/v1/components/xray/install','POST'],['/api/v1/node-feeds/sync','POST'],['/api/v1/node-feeds/feed-a','DELETE'],['/api/v1/node-feeds/feed-a/sync?x=1','POST']])await assert.rejects(f.ctx.apiDataMutation(path,{method}));
 assert.equal(f.requests.length,0,'forbidden paths must never reach transport');
 for(const [path,method] of [['/api/v1/node-groups','POST'],['/api/v1/node-groups/group-a','PUT'],['/api/v1/node-groups/group-a','DELETE'],['/api/v1/node-feeds','POST'],['/api/v1/node-feeds/feed-a','PUT'],['/api/v1/node-feeds/feed-a/sync','POST'],['/api/v1/nodes/import','POST']]){
  const pending=f.ctx.apiDataMutation(path,{method});f.requests.at(-1).resolve({ok:true});await pending;
 }
 assert.equal(f.timers.size,0);
}
{
 const f=fixture(),save=f.save();await flush();assert.equal(f.ctx.state.nodeFeedBusy,true);
 await f.save();assert.equal(f.requests.length,1);
 await f.deadline();await save;
 assert.equal(f.requests[0].options.signal.aborted,true);assert.equal(f.ctx.state.nodeFeedBusy,false);
 assert.equal(f.ctx.browser.feedUnknown,true);assert.match(f.$('#nodeFeedStatus').textContent,/могло быть сохранено/);
 assert.equal(f.$('#nodeFeedURL').value,'https://original.example/list');
 f.requests[0].resolve({source:{source_id:'feed-original'}});await flush();assert.equal(f.requests.length,1,'late create ACK must not enqueue sync');
 await f.save();assert.equal(f.requests.length,1);assert.equal(f.confirmations(),1,'unknown create needs explicit consent');
 f.confirm();const retry=f.save();await flush();assert.equal(f.requests.length,2);
 f.requests[1].reject(Object.assign(Error('conflict'),{status:409}));await retry;
 assert.equal(f.ctx.state.nodeFeedBusy,false);
}
{
 const f=fixture(),save=f.save();await flush();
 f.$('#nodeFeedName').value='New draft';f.$('#nodeFeedURL').value='https://new.example/list';f.ctx.browser.feedEdit++;
 f.requests[0].resolve({source:{source_id:'feed-original'}});await flush();
 assert.equal(f.$('#nodeFeedName').value,'New draft');assert.equal(f.$('#nodeFeedURL').value,'https://new.example/list');
 assert.equal(f.requests[1].path,'/api/v1/node-feeds/feed-original/sync');
 f.requests[1].resolve({job:{}});await save;assert.equal(f.ctx.state.nodeFeedBusy,false);
}
{
 const f=fixture(),old=f.save();await flush();const oldPost=f.requests[0];
 f.ctx.state.authGeneration++;f.ctx.stopNodeBrowserRefresh(true);await flush();
 assert.equal(oldPost.options.signal.aborted,true);assert.equal(f.ctx.state.nodeFeedBusy,false);
 f.ctx.browser.authRequired=false;f.ctx.browser.viewActive=true;f.confirm();
 f.$('#nodeFeedURL').value='https://new-session.example/list';const next=f.save();await flush();
 assert.equal(f.ctx.state.nodeFeedBusy,true);const newer=f.requests.at(-1);
 oldPost.resolve({source:{source_id:'feed-old'}});await old;
 assert.equal(f.ctx.state.nodeFeedBusy,true,'old finally must not release newer session write');
 assert.equal(f.$('#nodeFeedURL').value,'https://new-session.example/list');
 newer.reject(Object.assign(Error('invalid'),{status:400}));await next;assert.equal(f.ctx.state.nodeFeedBusy,false);
}
{
 const f=fixture(),pending=f.ctx.refreshNodeSubscription('feed-original');await flush();
 await f.deadline();await pending;assert.equal(f.ctx.browser.feedUnknown,true);
 await f.ctx.refreshNodeSubscription('feed-original');assert.equal(f.requests.length,1,'unknown queue ACK must not silently enqueue another job');
}
console.log('PASS data writes: closed routes, deadline/ignored abort, no replay, late ACK, new edits, owned auth cancellation, queue uncertainty');
