import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const fn=source.slice(source.indexOf("function openNodeGroup(id = '') {"),source.indexOf('\nasync function deleteNodeGroup('));
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function fixture(){
 const fields={nodeGroupID:{value:''},nodeGroupPreferred:{value:'node1'},nodeGroupName:{value:'Group'},nodeGroupMode:{value:'manual'},nodeGroupHold:{value:'1800'},nodeGroupDialog:{close(){this.closed=true;}}};
 const submit={disabled:false,textContent:'Сохранить группу'};
 fields.nodeGroupForm={querySelector:()=>submit};
 const writes=[],reads=[],messages=[],timers=new Map();let confirmations=0,accept=false,timerID=0;
 const context={AbortController,setTimeout(fn,ms){const id=++timerID;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),state:{authGeneration:1},$:id=>fields[id.slice(1)],$$:()=>[{value:'node1'}],nodeBrowseActionsAllowed:()=>true,
  showDetails:(body,title)=>messages.push({body,title}),refreshNodes:async()=>{},
  askConfirmation:async()=>{confirmations++;return accept;},
  api:async(url,options)=>{const request={url,options,...deferred()};(options?writes:reads).push(request);return request.promise;}};
 vm.createContext(context);vm.runInContext(source.slice(source.indexOf('async function apiDataMutation('),source.indexOf('async function api(url,'))+fn,context);
 return {context,fields,submit,writes,reads,messages,deadline:()=>{const [id,t]=[...timers].find(([,t])=>t.ms===20000);timers.delete(id);t.fn();},confirmations:()=>confirmations,accept:()=>{accept=true;},save:()=>context.saveNodeGroup({preventDefault(){}})};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
{
 const f=fixture(),first=f.save();await f.save();assert.equal(f.writes.length,1);assert.equal(f.submit.disabled,true);assert.equal(f.submit.textContent,'Сохраняется…');
 f.writes[0].resolve({group:{id:'group-created'}});await tick();
 assert.equal(f.fields.nodeGroupID.value,'group-created');
 f.reads[0].reject(Error('readback'));await first;
 assert.equal(f.messages[0].title,'Группа сохранена');assert.equal(f.context.state.nodeGroupSave,null);assert.equal(f.submit.disabled,false);assert.equal(f.submit.textContent,'Сохранить группу');
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

{
 const f=fixture(),pending=f.save();
 f.fields.nodeGroupDialog.close();
 f.context.openNodeGroup('other-group');
 assert.equal(f.fields.nodeGroupID.value,'');
 assert.equal(f.messages.at(-1).title,'Сохранение группы');
 assert.equal(f.submit.disabled,true);
 f.writes[0].resolve({group:{id:'group-original-result'}});await tick();f.reads[0].resolve({});await pending;
 assert.equal(f.submit.disabled,false);assert.equal(f.context.state.nodeGroupSave,null);
 // A new authenticated editor may open while an old-session request completes.
 const old=f.save();f.context.state.authGeneration++;
 f.context.state.nodes={nodes:[{id:'node1',name:'Node'}],groups:[{id:'other',name:'Other',node_ids:['node1']}]};
 f.context.nodeBrowser={selected:[]};f.context.esc=x=>x;f.context.nodeDisplayName=n=>n.name;
 for(const id of ['nodeGroupTitle','nodeGroupMembers'])f.fields[id]={};
 f.fields.nodeGroupDialog.showModal=function(){this.closed=false;};
 f.context.openNodeGroup('other');
 assert.equal(f.fields.nodeGroupID.value,'other');assert.equal(f.submit.disabled,false);
 f.writes[1].resolve({group:{id:'late-old'}});await old;
 assert.equal(f.fields.nodeGroupID.value,'other');assert.equal(f.fields.nodeGroupDialog.closed,false);
 assert.equal(f.submit.disabled,false);assert.equal(f.submit.textContent,'Сохранить группу');
}
console.log('PASS group editor pending close/reopen guard and feedback restoration across auth changes');

{
 const f=fixture(),pending=f.save();f.deadline();await pending;
 assert.equal(f.writes[0].options.signal.aborted,true);assert.equal(f.context.state.nodeGroupSave,null);
 assert.equal(f.submit.disabled,false);assert.equal(f.messages.at(-1).title,'Результат сохранения неизвестен');
 assert.equal(f.context.state.nodeGroupUnknown.auth,1);
 f.writes[0].resolve({group:{id:'group-late'}});await tick();assert.equal(f.fields.nodeGroupID.value,'');
 await f.save();assert.equal(f.writes.length,1,'unknown create cannot silently repeat');
}
console.log('PASS actual group deadline releases editor, ignores late create ACK and refuses blind retry');
