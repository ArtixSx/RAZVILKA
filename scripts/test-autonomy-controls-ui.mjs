import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../cmd/razvilka/web/console-autonomy.js',import.meta.url),'utf8');
const extract=name=>{const match=source.match(new RegExp(`  (?:async )?function ${name}\\([^]*?\\n  }`));assert(match,name);return match[0];};
function fixture(){
 const elements=new Map(),timers=new Map(),posts=[],notices=[];let next=0;
 const c={root:{},snapshot:{policy:{enabled:true,setup_complete:true,revision:1}},editingPolicy:{revision:1},presentationFresh:true,authGeneration:0,wizardEdit:0,saving:false,pauseRequest:null,activeTab:'setup',step:0,
 document:{activeElement:null,createElement:()=>({setAttribute(){},addEventListener(){}})},
 $:id=>{if(!elements.has(id))elements.set(id,{hidden:false,disabled:false,checked:true,textContent:'',classList:{toggle(){}},appendChild(){},focus(){c.document.activeElement=this;}});return elements.get(id);},$$:()=>[],
 setTimeout:(fn,ms)=>{timers.set(++next,{fn,ms});return next;},clearTimeout:id=>timers.delete(id),clone:structuredClone,
 api:async(...args)=>posts.push(args),refresh:async()=>true,render(){c.$('pauseButton').disabled=!!c.pauseRequest;},renderReview(){},readSources(){},setView(){},validatePolicy:p=>p,policyFromForm:()=>({enabled:true}),policyConsentRequired:()=>false,
 requireGeneration:g=>{if(g!==c.authGeneration)throw Object.assign(Error('old session'),{name:'AuthGenerationChanged'});},reportError:e=>{if(e.name!=='AuthGenerationChanged')notices.push(e.message);}};
 vm.createContext(c);vm.runInContext(source.slice(source.indexOf('  let noticeTimer='),source.indexOf('  function formatDate'))+'\n'+['tab','setStep','saveWizard','toggleAutonomyPause'].map(extract).join('\n'),c);
 return {c,elements,timers,posts,notices};
}
for(const changed of [false,true]){
 const f=fixture();if(changed)f.c.refresh=async()=>{f.c.wizardEdit++;return true;};
 await f.c.saveWizard({preventDefault(){}});assert.equal(f.c.$('notice').hidden,false);assert.equal(f.c.activeTab,changed?'setup':'overview');assert.equal(f.timers.size,1);const timer=[...f.timers.values()][0];assert.equal(timer.ms,6500);timer.fn();assert.equal(f.c.$('notice').hidden,true);
}
{
 const f=fixture();f.c.document.activeElement=f.c.$('nextStep');f.c.setStep(3);assert.equal(f.c.$('nextStep').hidden,true);assert.equal(f.c.document.activeElement,f.c.$('saveWizard'));
 f.c.document.activeElement=f.c.$('scopeMode');f.c.setStep(3);assert.equal(f.c.document.activeElement,f.c.$('scopeMode'),'background render must not steal focus');
}
{
 const f=fixture();let done;f.c.api=(...args)=>{f.posts.push(args);return new Promise(resolve=>done=resolve);};
 const first=f.c.toggleAutonomyPause();await f.c.toggleAutonomyPause();assert.equal(f.posts.length,1);assert.equal(f.c.$('pauseButton').disabled,true);f.c.render();assert.equal(f.c.$('pauseButton').disabled,true);done({});await first;assert.equal(f.c.pauseRequest,null);assert.equal(f.c.$('pauseButton').disabled,false);
}
{
 const f=fixture();let finishOld,finishNew;f.c.api=()=>new Promise(resolve=>{if(!finishOld)finishOld=resolve;else finishNew=resolve;});
 const old=f.c.toggleAutonomyPause();f.c.authGeneration++;f.c.pauseRequest=null;
 const current=f.c.toggleAutonomyPause();const owner=f.c.pauseRequest;finishOld({});await old;
 assert.equal(f.c.pauseRequest,owner);assert.equal(f.c.$('pauseButton').disabled,true);assert.equal(f.c.$('notice').textContent,'');finishNew({});await current;assert.equal(f.c.pauseRequest,null);
}
{
 const f=fixture();f.c.refresh=async()=>false;await f.c.toggleAutonomyPause();assert.match(f.notices[0],/актуальное состояние не получено/);assert.equal(f.c.$('notice').textContent,'');assert.equal(f.c.pauseRequest,null);
}
console.log('PASS autonomy controls: save notification survives navigation; review focus; pause single flight, readback and auth ownership');
