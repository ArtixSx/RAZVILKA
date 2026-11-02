import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source=fs.readFileSync('cmd/razvilka/web/mihomo-node-apply-ui.js','utf8');
const context=vm.createContext({Date});
vm.runInContext(source,context);
const model=context.RazvilkaMihomoNode;
const now=Date.now(), id='node-'+ 'a'.repeat(64), digest='b'.repeat(64);
const good={version:1,ok:true,ready:true,engine:'mihomo',live_applied:false,service_verified:false,review:{engine:'mihomo',node_id:id,service_id:'listed',scope_selection:'selected',review_token:'c'.repeat(64),reviewed_digest:digest,revision:7,generation:1,network_profile:'wan-original',expires_at:new Date(now+60000).toISOString()},transaction:{ready:true,digest,revision:8,network_profile_id:'wan-original'}};
assert.equal(model.canApply(good,id,'listed',now),true);
for(const change of [v=>delete v.ready,v=>v.ready=false,v=>v.service_verified=true,v=>v.live_applied=true,v=>v.engine='sing-box',v=>v.review.engine='xray',v=>v.review.review_token='',v=>v.review.generation=null,v=>v.review.scope_selection='all',v=>v.review.expires_at=new Date(now-1).toISOString(),v=>v.review.expires_at=new Date(now+120001).toISOString(),v=>v.transaction.ready=false,v=>v.transaction.revision=9,v=>v.transaction.digest='d'.repeat(64),v=>v.transaction.network_profile_id='wan-changed']){
 const value=structuredClone(good);change(value);assert.equal(model.canApply(value,id,'listed',now),false);
}
assert.equal(model.canApply(good,'node-'+ 'd'.repeat(64),'listed',now),false);
assert.equal(model.canApply(good,id,'different-service',now),false);
assert.equal(model.canApply({ready:true,node:{health:{verdict:'PASS'}}},id,'listed',now),false);
const selection={version:1,revision:7,services:[{id:'listed',name:'Current catalog service',enabled:true,applied_sources:[]}],runtime_registered:true,live_apply_available:false,live_applied:false,service_verified:false};
assert.equal(model.selection(selection),true);
assert.equal(model.selection({...selection,version:2}),false);
assert.equal(model.selection({...selection,version:undefined}),false);
assert.equal(model.canApply({...good,version:2},id,'listed',now),false);
assert.equal(model.canApply({...good,version:undefined},id,'listed',now),false);
for(const change of [v=>delete v.runtime_registered,v=>v.runtime_registered=null,v=>delete v.live_apply_available,v=>v.live_apply_available='true',v=>v.service_verified=true,v=>{v.runtime_registered=false;v.live_apply_available=true;},v=>v.revision=-1]){
 const value=structuredClone(selection);change(value);assert.equal(model.selection(value),false);
}
assert.match(fs.readFileSync('cmd/razvilka/web/index.html','utf8'),/src="\/mihomo-node-apply-ui\.js/);
assert.match(fs.readFileSync('cmd/razvilka/web/node-browser.js','utf8'),/openMihomoNodeApply\(button\.dataset\.nodeMihomo\)/);
// Execute the actual dialog handlers: a fulfilled earlier preview may not
// re-enable Apply after the user changes scope or loses their session.
class Element {
 constructor(){this.children=[];this.value='';this.disabled=false;this.open=false;this.handlers={};this.parts={};}
 setAttribute(){}
 appendChild(child){this.children.push(child);if(!this.value && child.value)this.value=child.value;}
 querySelector(key){return this.parts[key]??=new Element();}
 addEventListener(key,fn){this.handlers[key]=fn;}
 showModal(){this.open=true;}
 close(){this.open=false;this.handlers.close?.();}
 remove(){}
}
const handlers={},document={last:null,addEventListener:(key,fn)=>handlers[key]=fn,createElement:()=>new Element(),body:{appendChild:el=>document.last=el}};
let pending=[];
const ui=vm.createContext({Date,document,state:{authGeneration:0},api:()=>new Promise(resolve=>pending.push(resolve))});
vm.runInContext(source,ui);
const opening=ui.openMihomoNodeApply(id);
pending.shift()(structuredClone({...selection,live_apply_available:true}));await opening;
const dialog=document.last, preview=dialog.querySelector('[data-mh-preview]'), apply=dialog.querySelector('[data-mh-apply]'), sources=dialog.querySelector('[data-mh-sources]');
sources.value='192.168.1.42/32';sources.oninput();
const first=preview.onclick();
sources.value='192.168.1.43/32';sources.oninput();
pending.shift()(structuredClone(good));await first;
assert.equal(apply.disabled,true,'late earlier-scope preview enabled Apply');
assert.equal(preview.disabled,false,'scope change permanently disabled fresh preview');
const second=preview.onclick();pending.shift()(structuredClone(good));await second;
assert.equal(apply.disabled,false,'exact current preview cannot be confirmed');
const third=preview.onclick();ui.state.authGeneration++;handlers['razvilka:auth-required']();pending.shift()(structuredClone(good));await third;
assert.equal(apply.disabled,true,'late response after auth loss enabled Apply');
assert.equal(dialog.open,false);
console.log('Mihomo manual UI: exact reviewed scope, stale identity and unknown registration tests PASS');
