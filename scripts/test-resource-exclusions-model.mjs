// Pure presentation checks for CORE's declared persisted schema; no HTTP,
// traffic matching, runtime proof or mutation transport is fabricated here.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),model=require('../cmd/razvilka/web/interface-model.js');
let checks=0;
const check=(name,action)=>{action();checks++;console.log('PASS '+name);};
const saved=()=>({schema:1,revision:3,manual:[{kind:'service',value:'youtube'},{kind:'exact',value:'example.com'},{kind:'suffix',value:'sub.example.com'},{kind:'ip',value:'192.0.2.1'},{kind:'cidr',value:'2001:db8::/48'}],
  russian_snapshot:{catalog_id:'accepted-ru',revision:4,digest:'a'.repeat(64),entries:[{kind:'service',value:'bank'},{kind:'exact',value:'bank.example'}]}});
check('five explicit match kinds retain values and scope',()=>{
  const view=model.resourceExclusionView(saved(),true,[{id:'youtube',name:'YouTube'}]);
  assert.equal(view.available,true);assert.equal(view.revision,3);
  assert.deepEqual(view.manual.map(row=>row.kind),['service','exact','suffix','ip','cidr']);
  assert.equal(view.manual[0].label,'YouTube');assert.equal(view.manual[1].typeLabel,'Точный домен');assert.equal(view.manual[2].typeLabel,'Домен и поддомены');
  assert.equal(view.manual[4].value,'2001:db8::/48');assert(view.manual.every(row=>row.origin==='manual'&&row.activeIntent));
});
check('manual and Russian provenance are separate',()=>{
  const view=model.resourceExclusionView(saved(),true);
  assert.equal(view.manual.length,5);assert.equal(view.russian.rows.length,2);
  assert.equal(view.manual[0].originLabel,'Добавлено вручную');assert.equal(view.russian.rows[0].originLabel,'Российский каталог');
  assert.equal(view.russian.rows[0].reason,'Запись принятого российского каталога');assert.equal(view.russian.catalogID,'accepted-ru');
  assert.equal(view.russian.revision,4);assert.equal(view.russian.digest,'a'.repeat(64));
});
check('disabled Russian catalog retains the accepted snapshot',()=>{
  const view=model.resourceExclusionView(saved(),false);
  assert.equal(view.russian.present,true);assert.equal(view.russian.enabled,false);assert.equal(view.russian.rows.length,2);
  assert(view.russian.rows.every(row=>!row.activeIntent));assert(view.manual.every(row=>row.activeIntent));
});
check('missing optional persisted pointer is distinct from unavailable data',()=>{
  const view=model.resourceExclusionView(null,true);assert.equal(view.available,true);assert.equal(view.declared,false);assert.equal(view.manual.length,0);assert.equal(view.russian.present,false);
});
check('nil manual slice displays empty without generating a clear command',()=>{
  const data=saved();data.manual=null;const view=model.resourceExclusionView(data,true);
  assert.equal(view.available,true);assert.equal(view.manual.length,0);assert.equal(view.russian.rows.length,2);
});
for(const change of [{schema:2},{revision:-1},{revision:1.5},{manual:{}},{manual:[{kind:'tld',value:'ru'}]},{manual:[{kind:'exact',value:''}]}]){
  check('invalid persisted shape is unavailable '+JSON.stringify(change),()=>{
    const view=model.resourceExclusionView({...saved(),...change},true);assert.equal(view.available,false);assert.equal(view.declared,true);
    assert.equal(view.manual.length,0);assert.equal(view.russian.present,false);
  });
}
for(const change of [{entries:[]},{catalog_id:''},{revision:-1},{digest:'untrusted'},{entries:[{kind:'asn',value:'AS1'}]}]){
  check('invalid accepted snapshot is unavailable '+JSON.stringify(change),()=>{
    const data=saved();Object.assign(data.russian_snapshot,change);assert.equal(model.resourceExclusionView(data,true).available,false);
  });
}
check('display copies cannot edit the persisted source',()=>{
  const data=saved(),before=JSON.stringify(data),view=model.resourceExclusionView(data,true);
  view.manual[0].value='other';view.russian.rows[0].value='other';view.russian.rows.push({kind:'ip',value:'192.0.2.2'});
  assert.equal(JSON.stringify(data),before);
});
check('extra labels and health claims cannot override provenance or become proof',()=>{
  const data=saved();Object.assign(data.manual[0],{origin:'russian',reason:'PASS',applied:true,ready:true});
  const row=model.resourceExclusionView(data,true).manual[0];assert.equal(row.origin,'manual');assert.equal(row.reason,'Ручное исключение ресурса');
  assert.equal(Object.hasOwn(row,'applied'),false);assert.equal(Object.hasOwn(row,'ready'),false);
});
check('domain ending in ru does not become a Russian entry',()=>{
  const view=model.resourceExclusionView({schema:1,revision:1,manual:[{kind:'exact',value:'example.ru'}]},true);
  assert.equal(view.manual[0].origin,'manual');assert.equal(view.russian.rows.length,0);
});
check('service display matches exact ID rather than name or domain',()=>{
  const data=saved(),view=model.resourceExclusionView(data,true,[{id:'other',name:'youtube',domains:['youtube']}]);
  assert.equal(view.manual[0].label,'youtube');
});
console.log(JSON.stringify({suite:'resource-exclusions-model',passed:checks}));
