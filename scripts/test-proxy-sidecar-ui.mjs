import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/proxy-sidecar-ui.js',import.meta.url),'utf8');
const snapshot=(backend='sing-box',boot_backend='sing-box')=>({schema:1,backend,boot_backend,revision:7,restart_required:backend!==boot_backend,live_applied:false,available:null,backends:[{id:'sing-box',name:'Sing-box'},{id:'hev',name:'HEV 2.17.1'}]});
function fixture(){const elements=new Map(),events=new Map(),requests=[];let n=0;const element=id=>{if(!elements.has(id))elements.set(id,{value:'',disabled:false,textContent:'',children:[],events:{},setAttribute(k,v){this[k]=v;},replaceChildren(){this.children=[];this.value='';},appendChild(v){this.children.push(v);},addEventListener(k,f){this.events[k]=f;}});return elements.get(id);};const context={document:{getElementById:element,createElement:()=>element('option'+(++n)),addEventListener:(k,f)=>events.set(k,f),dispatchEvent(){}},CustomEvent:class{},interfaceRequest(path,options){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});requests.push({path,options,resolve,reject});return promise;}};vm.runInNewContext(source,context);return {context,element,requests,events,click:id=>element('proxySidecar'+id).events.click(),choose(value){element('proxySidecarSelect').value=value;element('proxySidecarSelect').events.change({stopPropagation(){}});}};}
{
 const f=fixture();assert.equal(f.requests.length,0);assert(f.element('proxySidecarSave').disabled);const read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('hev');assert.equal(f.element('proxySidecarSave').disabled,false);const save=f.click('Save');assert.equal(f.requests[1].path,'/api/v1/runtime/proxy-sidecar');assert.deepEqual(JSON.parse(f.requests[1].options.body),{backend:'hev',expected_revision:7});f.requests[1].resolve(snapshot('hev'));await save;assert.match(f.element('proxySidecarStatus').textContent,/следующего запуска/);assert.match(f.element('proxySidecarStatus').textContent,/Текущий backend: Sing-box/);assert.equal(f.requests.length,2);assert(f.element('proxySidecarSave').disabled);
}
{
 const f=fixture();for(const value of [{...snapshot(),schema:2},{...snapshot(),available:true},{...snapshot(),live_applied:true},{...snapshot(),backend:'auto'},{...snapshot(),restart_required:true}])assert.equal(f.context.RazvilkaProxySidecarUI.validSnapshot(value),false);
 const read=f.click('Read');f.events.get('razvilka:auth-required')();f.requests[0].resolve(snapshot('hev','hev'));await read;assert(f.element('proxySidecarSave').disabled);assert.equal(f.element('proxySidecarSelect').children.length,0);
}
{
 const f=fixture();const read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('hev');const save=f.click('Save');f.requests[1].reject(new Error('inactivity unknown'));await save;assert(f.element('proxySidecarSave').disabled);assert.match(f.element('proxySidecarStatus').textContent,/Прочитайте/);assert.equal(f.requests.length,2);
}
console.log('PASS proxy sidecar UI: boot intent, exact CAS, no implicit restart, unknown schema, auth epoch, no replay');
