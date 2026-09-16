import fs from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';
const code=fs.readFileSync('cmd/razvilka/web/app-update-ui.js','utf8'),index=fs.readFileSync('cmd/razvilka/web/index.html','utf8');
const el={};let state={status:{},appUpdate:null};const ctx={state,consoleSnapshot:{},$:s=>s==='#maintenanceAddressStatus'?el:null,esc:s=>String(s).replaceAll('<','&lt;'),Date,AbortController,console};vm.createContext(ctx);vm.runInContext(code,ctx);let n=0;
function check(name,fn){fn();n++;console.log('PASS',name)}
check('future proof not current',()=>assert.equal(ctx.appUpdateBadge({state:'current',checked_at:new Date(Date.now()+600000).toISOString()}).label,'Не проверено'));
check('stale metadata never offers prepare',()=>assert.notEqual(ctx.appUpdateBadge({state:'current',metadata_stale:true,update_available:true,can_prepare:true,checked_at:new Date().toISOString()}).kind,'update'));
state.appUpdate={channel:'preview',state:'ahead',installed_version:'0.18.2-rc.10',checked_at:new Date().toISOString()};
check('explicit channel in summary',()=>assert.match(ctx.appUpdateSummaryHTML(),/Предварительные и стабильные/));
check('stable is wizard default',()=>assert.match(index,/<select id="a1-updateChannel"><option value="stable">/));
check('no implicit auto install',()=>assert.doesNotMatch(index,/<option value="install">/));
check('no address result stays unknown',()=>{ctx.renderMaintenanceAddresses();assert.match(el.textContent,/ещё нет/)});
ctx.consoleSnapshot.address_refresh={state:'failed',checked_at:new Date().toISOString()};
check('failed address status not healthy',()=>{ctx.renderMaintenanceAddresses();assert.match(el.textContent,/не завершено/)});
check('mode inputs present once',()=>{for(const id of ['auto3NFQRead','auto3NFQMode','auto3DiscoveryConsent','auto3NFQSave'])assert.equal(index.split('id="'+id+'"').length-1,1)});
check('declaration alone not canary',()=>{const script=fs.readFileSync('cmd/razvilka/web/automation-setup.js','utf8');assert.match(script,/не результат|не доказательство|не подтверждение/)});
console.log(JSON.stringify({suite:'maintenance-ui',passed:n}));
