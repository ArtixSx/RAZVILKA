import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../cmd/razvilka/web/nfqws-first-start-ui.js',import.meta.url),'utf8');
const modelContext={};vm.runInNewContext(readFileSync(new URL('../cmd/razvilka/web/console-autonomy.js',import.meta.url),'utf8'),modelContext);
const recipeIDs=['','stock-tls-circular-v1','stock-tls-circular-auto-v1','stock-tls-circular-observe-auto-v1'];
const snapshot=(recipe='',revision=4,applied_recipe='')=>({recipe,applied_recipe,revision,recipes:[{id:'',name:'Базовый multisplit · TCP/443'},{id:'stock-tls-circular-v1',name:'Стандартный TLS circular · TCP/443'},{id:'stock-tls-circular-auto-v1',name:'Стандартный TLS circular + fastpath auto · TCP/443'},{id:'stock-tls-circular-observe-auto-v1',name:'TLS circular · наблюдение ответов + fastpath auto · TCP/443'}]});
function fixture(withCoreReadback=false){
  const elements=new Map(),events=new Map(),requests=[],published=[],readbacks=[];let created=0;
  const element=id=>{if(!elements.has(id))elements.set(id,{value:'',disabled:false,textContent:'',children:[],events:{},setAttribute(k,v){this[k]=v;},replaceChildren(){this.children=[];this.value='';},appendChild(value){this.children.push(value);},addEventListener(name,fn){this.events[name]=fn;}});return elements.get(id);};
  const context={RazvilkaAutonomyModel:modelContext.RazvilkaAutonomyModel,CustomEvent:class{constructor(type){this.type=type;}},
    document:{getElementById:element,createElement:()=>element('option-'+(++created)),addEventListener:(name,fn)=>events.set(name,fn),dispatchEvent:event=>published.push(event)},
    interfaceRequest(path,options){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});requests.push({path,options,resolve,reject});return promise;}
  };
  if(withCoreReadback)context.refreshAfterMutation=async()=>{readbacks.push('fresh-core-readback');};
  vm.runInNewContext(source,context);
  return {element,requests,published,readbacks,model:context.RazvilkaNFQWSFirstStartUI,click:id=>element('nfqFirstRecipe'+id).events.click(),
    choose(value){element('nfqFirstRecipeSelect').value=value;let stopped=false;element('nfqFirstRecipeSelect').events.change({stopPropagation(){stopped=true;}});assert.equal(stopped,true,'separate recipe intent dirtied the wizard');},
    logout:()=>events.get('razvilka:auth-required')()};
}
let passed=0;async function test(name,fn){await fn();passed++;console.log('PASS '+name);}

await test('entry is inert; explicit read enables only a closed draft choice',async()=>{
 const f=fixture();assert.equal(f.requests.length,0);assert.equal(f.element('nfqFirstRecipeSave').disabled,true);
 const read=f.click('Read');assert.equal(f.requests[0].path,'/api/v1/nfqws2/first-start-recipe');assert.equal(f.requests[0].options.method,undefined);
 f.requests[0].resolve(snapshot());await read;
 assert.equal(f.element('nfqFirstRecipeSelect').disabled,false);assert.equal(f.element('nfqFirstRecipeSave').disabled,true);
 f.choose('stock-tls-circular-v1');assert.equal(f.requests.length,1);assert.equal(f.element('nfqFirstRecipeSave').disabled,false);
});
await test('save stages exact revision and never calls plan apply or probe',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('stock-tls-circular-v1');
 const save=f.click('Save');await f.click('Save');assert.equal(f.requests.length,2);
 assert.deepEqual(JSON.parse(f.requests[1].options.body),{recipe:'stock-tls-circular-v1',expected_revision:4});assert.equal(f.requests[1].options.method,'PUT');
 f.requests[1].resolve(snapshot('stock-tls-circular-v1',5));await save;
 assert.match(f.element('nfqFirstRecipeStatus').textContent,/Выбор сохранён в черновике.*план.*Сервисы/);
 assert.equal(f.element('nfqFirstRecipeSave').disabled,true);assert.equal(f.published.length,1);assert.equal(f.published[0].type,'razvilka:panel-refresh');
 assert(f.requests.every(r=>r.path==='/api/v1/nfqws2/first-start-recipe'));
});
await test('stock fastpath auto remains an explicit CAS draft and has no live effect',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot());await read;
 assert.equal(f.element('nfqFirstRecipeSelect').children.length,4);
 f.choose('stock-tls-circular-auto-v1');assert.equal(f.requests.length,1);
 const save=f.click('Save');assert.deepEqual(JSON.parse(f.requests[1].options.body),{recipe:'stock-tls-circular-auto-v1',expected_revision:4});
 f.requests[1].resolve(snapshot('stock-tls-circular-auto-v1',5));await save;
 assert.equal(f.element('nfqFirstRecipeStatus').role,'status');
 assert(f.requests.every(r=>r.path==='/api/v1/nfqws2/first-start-recipe'));
});
for(const draft of recipeIDs)for(const applied of recipeIDs)await test(`all four recipes render draft=${draft||'default'} applied=${applied||'default'}`,async()=>{
 const f=fixture(),read=f.click('Read');const value=snapshot(draft,4,applied);f.requests[0].resolve(value);await read;
 assert.equal(f.model.validSnapshot(value),true);
 assert.deepEqual(f.element('nfqFirstRecipeSelect').children.map(option=>option.value),recipeIDs);
 assert.equal(f.element('nfqFirstRecipeSelect').value,draft);
 assert.equal(f.element('nfqFirstRecipeStatus').role,'status');
 assert(f.element('nfqFirstRecipeStatus').textContent.includes(value.recipes.find(entry=>entry.id===applied).name));
 assert.equal(f.element('nfqFirstRecipeSave').disabled,true);assert.equal(f.requests.length,1);
});
await test('observer recipe stages only exact CAS and keeps previous applied label',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot('',4,'stock-tls-circular-auto-v1'));await read;
 f.choose('stock-tls-circular-observe-auto-v1');const save=f.click('Save');
 assert.deepEqual(JSON.parse(f.requests[1].options.body),{recipe:'stock-tls-circular-observe-auto-v1',expected_revision:4});
 f.requests[1].resolve(snapshot('stock-tls-circular-observe-auto-v1',5,'stock-tls-circular-auto-v1'));await save;
 assert.match(f.element('nfqFirstRecipeStatus').textContent,/Выбор сохранён в черновике/);
 assert(f.element('nfqFirstRecipeStatus').textContent.includes('Стандартный TLS circular + fastpath auto'));
 assert(f.requests.every(request=>request.path==='/api/v1/nfqws2/first-start-recipe'));
});
for(const [name,alter]of [
 ['future draft',value=>{value.recipe='stock-tls-circular-observe-auto-v2';}],
 ['future applied',value=>{value.applied_recipe='stock-tls-circular-observe-auto-v2';}],
 ['future menu ID',value=>{value.recipes[3].id='stock-tls-circular-observe-auto-v2';}],
 ['missing menu entry',value=>{value.recipes.pop();}],
 ['extra menu entry',value=>{value.recipes.push({id:'future',name:'future'});}],
 ['duplicate menu entry',value=>{value.recipes[3]=value.recipes[2];}],
 ['null menu entry',value=>{value.recipes[3]=null;}],
 ])await test('closed four-recipe snapshot refuses '+name,async()=>{
 const value=snapshot();alter(value);const f=fixture();assert.equal(f.model.validSnapshot(value),false);
 const read=f.click('Read');f.requests[0].resolve(value);await read;
 assert.equal(f.element('nfqFirstRecipeSelect').disabled,true);assert.equal(f.element('nfqFirstRecipeSave').disabled,true);
 assert.equal(f.element('nfqFirstRecipeStatus').role,'alert');assert.equal(f.requests.length,1);
});
await test('lost write reply stays unconfirmed and requires independent read',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('stock-tls-circular-v1');
 const save=f.click('Save');f.requests[1].reject(new TypeError('Failed to fetch'));await save;
 assert.match(f.element('nfqFirstRecipeStatus').textContent,/Нет связи с панелью.*не подтверждён.*Прочитайте настройки/);
 assert.equal(f.element('nfqFirstRecipeStatus').role,'alert');assert.equal(f.element('nfqFirstRecipeSave').disabled,true);await f.click('Save');assert.equal(f.requests.length,2);
 assert.equal(f.published.length,0);
});
await test('confirmed selection requests the core fresh readback for the draft banner',async()=>{
 const f=fixture(true),read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('stock-tls-circular-v1');
 const save=f.click('Save');f.requests[1].resolve(snapshot('stock-tls-circular-v1',5));await save;
 assert.deepEqual(f.readbacks,['fresh-core-readback']);assert.equal(f.requests.length,2);assert.equal(f.published.length,0);
});
await test('revision conflict never overwrites or repeats the selection',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot());await read;f.choose('stock-tls-circular-v1');
 const save=f.click('Save');f.requests[1].reject(Object.assign(new Error('Настройки изменились.'),{status:409}));await save;
 assert.equal(f.element('nfqFirstRecipeSave').disabled,true);assert.match(f.element('nfqFirstRecipeStatus').textContent,/Настройки изменились/);
 const reload=f.click('Read');f.requests[2].resolve(snapshot('',8));await reload;
 f.choose('stock-tls-circular-v1');const next=f.click('Save');assert.equal(JSON.parse(f.requests[3].options.body).expected_revision,8);f.requests[3].resolve(snapshot('stock-tls-circular-v1',9));await next;
});
for(const reply of ['success','abort'])await test('logout fences late recipe '+reply,async()=>{
 const f=fixture(),read=f.click('Read');f.logout();const text=f.element('nfqFirstRecipeStatus').textContent;
 if(reply==='success')f.requests[0].resolve(snapshot('stock-tls-circular-v1'));else f.requests[0].reject(Object.assign(new Error('aborted'),{name:'AuthGenerationChanged'}));
 await read;assert.equal(f.element('nfqFirstRecipeStatus').textContent,text);assert.equal(f.element('nfqFirstRecipeSave').disabled,true);assert.equal(f.element('nfqFirstRecipeSelect').disabled,true);
});
await test('unknown recipe response cannot enable a draft write',async()=>{
 const f=fixture(),read=f.click('Read');f.requests[0].resolve(snapshot('unknown'));await read;
 assert.equal(f.element('nfqFirstRecipeSave').disabled,true);assert.equal(f.element('nfqFirstRecipeSelect').disabled,true);
 assert.match(f.element('nfqFirstRecipeStatus').textContent,/не подтверждён/);
});
const html=readFileSync(new URL('../cmd/razvilka/web/index.html',import.meta.url),'utf8');
assert.match(html,/id="nfqFirstRecipeRead" type="button"/);assert.match(html,/id="nfqFirstRecipeSave" type="button"/);assert.match(html,/nfqws-first-start-ui\.js/);
console.log(JSON.stringify({suite:'nfqws-first-start-ui',tests:passed}));
