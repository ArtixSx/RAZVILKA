import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/hev-recovery-ui.js',import.meta.url),'utf8');
const snapshot=()=>({revision:7,recovery_required:true,repair_available:true,live_applied:false,review:{pending:true,identity:'a'.repeat(64)}});
function fixture(){const elements=new Map(),events=new Map(),requests=[];const element=id=>{if(!elements.has(id))elements.set(id,{disabled:false,textContent:'',events:{},addEventListener(k,f){this.events[k]=f;}});return elements.get(id);};const context={document:{getElementById:element,addEventListener:(k,f)=>events.set(k,f)},interfaceRequest(path,options){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});requests.push({path,options,resolve,reject});return promise;}};vm.runInNewContext(source,context);return{context,element,events,requests,click:id=>element('hevRecovery'+id).events.click()};}
{
 const f=fixture();assert.equal(f.requests.length,0);assert(f.element('hevRecoveryRepair').disabled);const read=f.click('Read');f.requests[0].resolve(snapshot());await read;assert.equal(f.element('hevRecoveryRepair').disabled,false);
 const write=f.click('Repair');assert.deepEqual(JSON.parse(f.requests[1].options.body),{expected_identity:'a'.repeat(64),expected_revision:7});f.requests[1].reject(new Error('response lost'));await write;assert(f.element('hevRecoveryRepair').disabled);await f.click('Repair');assert.equal(f.requests.length,2);
}
{
 const f=fixture();const read=f.click('Read');f.events.get('razvilka:auth-required')();f.requests[0].resolve(snapshot());await read;assert(f.element('hevRecoveryRepair').disabled);
 for(const value of [{...snapshot(),live_applied:true},{...snapshot(),revision:-1},{...snapshot(),review:{pending:true,identity:'foreign'}}])assert.equal(f.context.RazvilkaHEVRecovery.valid(value),false);
}
console.log('PASS HEV recovery UI: exact identity/revision, auth epoch and no replay after unknown result');
