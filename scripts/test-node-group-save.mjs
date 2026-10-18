import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const fn=source.slice(source.indexOf('async function saveNodeGroup(event) {'),source.indexOf('\nasync function deleteNodeGroup('));
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function fixture(){
 const fields={nodeGroupID:{value:''},nodeGroupPreferred:{value:'node1'},nodeGroupName:{value:'Group'},nodeGroupMode:{value:'manual'},nodeGroupHold:{value:'1800'},nodeGroupDialog:{close(){this.closed=true;}}};
 const writes=[],reads=[],messages=[];let confirmations=0,accept=false;
 const context={state:{authGeneration:1},$:id=>fields[id.slice(1)],$$:()=>[{value:'node1'}],nodeBrowseActionsAllowed:()=>true,
  showDetails:(body,title)=>messages.push({body,title}),refreshNodes:async()=>{},
  askConfirmation:async()=>{confirmations++;return accept;},
  api:async(url,options)=>{const request={url,options,...deferred()};(options?writes:reads).push(request);return request.promise;}};
 vm.createContext(context);vm.runInContext(fn,context);
 return {context,fields,writes,reads,messages,confirmations:()=>confirmations,accept:()=>{accept=true;},save:()=>context.saveNodeGroup({preventDefault(){}})};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
{
 const f=fixture(),first=f.save();await f.save();assert.equal(f.writes.length,1);
 f.writes[0].resolve({group:{id:'group-created'}});await tick();
 assert.equal(f.fields.nodeGroupID.value,'group-created');
 f.reads[0].reject(Error('readback'));await first;
 assert.equal(f.messages[0].title,'Группа сохранена');assert.equal(f.context.state.nodeGroupSave,null);
 const retry=f.save();assert.equal(f.writes[1].options.method,'PUT');
 f.writes[1].reject(Object.assign(Error('conflict'),{status:409}));await retry;
 assert.equal(f.messages.at(-1).title,'Группа не сохранена');
}
{
 const f=fixture(),pending=f.save();f.context.state.authGeneration++;
 f.writes[0].resolve({group:{id:'old-session'}});await pending;
 assert.equal(f.fields.nodeGroupID.value,'');assert.equal(f.reads.length,0);assert.equal(f.messages.length,0);
 const fresh=f.save();assert.equal(f.writes.length,2,'new auth must not be permanently busy');
 f.writes[1].reject(Object.assign(Error('bad request'),{status:400}));await fresh;
}
{
 const f=fixture(),pending=f.save();f.writes[0].reject(Error('connection lost'));await pending;
 assert.equal(f.messages[0].title,'Результат сохранения неизвестен');
 await f.save();assert.equal(f.writes.length,1);assert.equal(f.confirmations(),1);
 f.accept();const retry=f.save();await tick();assert.equal(f.writes.length,2);
 f.writes[1].resolve({group:{id:'confirmed-retry'}});await tick();f.reads[0].resolve({});await retry;
 assert.equal(f.context.state.nodeGroupUnknown,null);
}
{
 const f=fixture(),pending=f.save();f.writes[0].resolve({group:{id:'created'}});await tick();
 f.context.state.authGeneration++;f.reads[0].resolve({stale:true});await pending;
 assert.equal(f.context.state.routeOptions,undefined,'late options must not replace new session state');
}
console.log('PASS group save: single flight, known success/readback failure, unknown outcome consent, auth fences and busy recovery');
