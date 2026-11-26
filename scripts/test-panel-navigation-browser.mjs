// Presentation-only gate: production assets, synthetic routing and stopped states.
// No server, router, credentials, network access, downloads or API mutations.
// NODE_PATH supplies playwright; RAZVILKA_UI_CHROME an installed Chromium.
// Optional RAZVILKA_UI_ARTIFACTS saves screenshots and the result outside the tree.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync, existsSync, mkdirSync, writeFileSync} from 'node:fs';
import {resolve, extname, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const require=createRequire(import.meta.url), {chromium}=require('playwright');
const model=require('../cmd/razvilka/web/interface-model.js');
const root=fileURLToPath(new URL('../cmd/razvilka/web/',import.meta.url));
const origin='http://razvilka-ui.test';
const output=process.env.RAZVILKA_UI_ARTIFACTS;
if(output)mkdirSync(output,{recursive:true});
assert(process.env.RAZVILKA_UI_CHROME,'Set RAZVILKA_UI_CHROME to an installed browser');
const browser=await chromium.launch({headless:true,executablePath:process.env.RAZVILKA_UI_CHROME});
const errors=[],writes=[],external=[],missing=[],visited=[],reads=[];
const assets={};
const maintenance={mode:'check',start:'02:00',end:'03:00',days:[1]};
const snapshot={policy:{revision:1,setup_complete:true,enabled:false,timezone:'UTC',all_lan:false,default_sources:['192.0.2.1/32'],source_ids:[],protocols:['vless'],preferred_routes:[],reserve_target:2,candidates_per_round:2,check_seconds:300,reserve_seconds:600,application:maintenance,components:maintenance},stopped:true,services:{},runtime:{},applied_services:{},catalog_services:[],source_presets:[]};
let servicesFixture=[], inventoryFixture=null;
const contentTypes={'.html':'text/html','.css':'text/css','.js':'application/javascript','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon','.woff2':'font/woff2'};
try{
 const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.origin!==origin){external.push(req.url());return route.abort();}
  if(req.method()!=='GET'){writes.push(req.method()+' '+url.pathname);return route.abort();}
  if(url.pathname.startsWith('/api/')){
   reads.push(url.pathname+url.search);
   let value;
   if(url.pathname==='/api/v1/auth/status')value={authenticated:true,setup_required:false};
   if(url.pathname==='/api/v1/status')value={authenticated:true,setup_required:false,version:'UI fixture',stopped:snapshot.stopped};
   if(url.pathname==='/api/v1/panel/availability')value={schema:1,name:'RAZVILKA',panel:'responding',dataplane:'not-checked',admission:{state:'idle',active:0,exclusive:false,fenced:false}};
   if(url.pathname==='/api/v1/autonomy')value=snapshot;
   if(url.pathname==='/api/v1/panel/autonomy')value={schema:1,instance_id:'a'.repeat(32),revision:1,dataplane:'not-checked',state:'available',data_age_ms:0,observed_at:new Date().toISOString(),data:{...snapshot,server_time:new Date().toISOString()}};
   if(url.pathname==='/api/v1/panel/inventory' && inventoryFixture)value={schema:1,dataplane:'not-checked',state:'available',revision:1,instance_id:'a'.repeat(32),data_age_ms:0,max_age_seconds:300,observed_at:new Date().toISOString(),data:{components:inventoryFixture,engines:[],system:{}}};
   if(url.pathname==='/api/v1/networkpolicy/scope-options')value={
     schema:1,ok:true,effect_authorized:false,live_applied:false,state:'available',code:'',revision:1,policy_revision:0,
     observed_at:new Date().toISOString(),fresh_until:new Date(Date.now()+60000).toISOString(),
     segments:[{id:'br0',label:'Дом',native_name:'Home',interface:'br0',state:'observed',code:'',selection_candidate:true}],
     devices:[{id:'test-printer',label:'Принтер',segment_id:'br0',state:'observed',code:'',selection_candidate:true}],retained_segment_ids:[],retained_device_ids:[]
   };
   if(url.pathname==='/api/v1/networkpolicy/review')value={revision:1,policy:null,consent:null,live_applied:false};
   if(url.pathname==='/api/v1/services')value=servicesFixture;
   if(['/api/v1/engine-configs','/api/v1/routes/options'].includes(url.pathname))value=[];
   return route.fulfill({status:value?200:503,contentType:'application/json',body:JSON.stringify(value??{error:'Изолированная проверка интерфейса: данные недоступны'})});
  }
  const file=resolve(root,'.'+(url.pathname==='/'?'/index.html':decodeURIComponent(url.pathname)));
  if(!file.startsWith(resolve(root)+sep)||!existsSync(file)){missing.push(url.pathname);return route.fulfill({status:404,body:''});}
  const body=readFileSync(file);assets[url.pathname]=createHash('sha256').update(body).digest('hex');
  await route.fulfill({contentType:contentTypes[extname(file)]??'application/octet-stream',body});
 });
 const page=await context.newPage();
 page.on('pageerror',error=>{if(!errors.includes(error.stack))errors.push(error.stack);});
 await page.goto(origin,{waitUntil:'networkidle'});
 await page.waitForFunction(()=>document.getElementById('authScreen').hidden && typeof setView==='function');
 const capture=async name=>{if(output)await page.screenshot({path:resolve(output,name+'.png'),fullPage:!name.endsWith('-mobile')});};
 const checkView=async view=>{
  await page.waitForFunction(v=>state.currentView===v,view);
  assert(await page.locator('#view-'+view).isVisible(),view+' hidden');
  assert.equal(await page.locator('[data-main-nav][aria-current="page"]').count(),1,view+' current item');
  assert.equal(await page.locator(`[data-main-nav="${view}"]`).getAttribute('aria-current'),'page');
  if(model.taskSections[view].children.length>1)assert(await page.locator('#interfaceSubnav').isVisible(),view+' subnavigation hidden');
  visited.push(view);
 };
 await page.locator('#rzSimpleHome .rz-route-card:visible').waitFor();
 await capture('home-desktop');
 assert.match(await page.locator('#rzSimpleHome').textContent(), /Проект остановлен/);
 const rules = {telegram:{enabled:true,route:'nfqws2',sources:['192.0.2.1/32']},video:{enabled:true,route:'direct'}};
 const engineRows=page.locator('#rzSimpleHome .ui7-engine-row');
 assert.equal(await engineRows.count(),8,'methods missing when component status is unavailable');
 assert.match(await engineRows.first().textContent(),/Состояние неизвестно/);
 snapshot.stopped=false;
 inventoryFixture=[{id:'nfqws2',installed:true,running:true},{id:'wireguard',installed:false,running:false},{id:'usque',installed:true,runtime_observation:'unknown'}];
 snapshot.applied_services=rules;
 servicesFixture=[
  {id:'telegram',name:'Telegram Web',applied_state:rules.telegram,observed_state:{route:'nfqws2',status:'pass',level:'service-confirmed',outcome:'service_accepted',checked_at:new Date(Date.now()-1000).toISOString(),fresh_until:new Date(Date.now()+120000).toISOString()}},
  {id:'video',name:'Видеосервис',applied_state:rules.video}
 ];
 snapshot.catalog_services=servicesFixture.map(({id,name})=>({id,name}));
 await page.reload({waitUntil:'networkidle'});
 const applied=page.locator('#rzSimpleHome .rz-route-table');
 await page.waitForFunction(()=>document.querySelector('#rzSimpleHome .rz-sh-status')?.textContent.includes('1 из 2'));
 assert.equal(await applied.locator('tbody tr').count(),2,'manual rules missing while autopilot is paused');
 assert.match(await applied.textContent(),/192\.0\.2\.1\/32/);
 assert.match(await applied.textContent(),/Прямое подключение/);
 assert.equal(await applied.locator('.verified').count(),1,'unverified route promoted');
 assert.equal(await engineRows.count(),8);
 const nfqws=engineRows.filter({hasText:'NFQWS2'});
 assert.match(await nfqws.textContent(),/Процесс запущен/);
 assert.match(await nfqws.textContent(),/1назначено · 1 проверено/);
 assert.match(await engineRows.locator('[class="ui7-engine-count"]').allTextContents().then(rows=>rows.join(' ')),/0назначено/);
 assert.match(await engineRows.filter({hasText:'WARP · MASQUE'}).textContent(),/Состояние процесса неизвестно/);
 assert.match(await page.locator('#rzSimpleHome [data-console-engine="wireguard"]').textContent(),/Не установлен/);
 await capture('routes-desktop');
 await page.setViewportSize({width:390,height:844});
 await capture('routes-mobile');
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'route table overflows mobile');
 await page.locator('#rzSimpleHome [data-view="exclusions"]').click();
 await page.waitForFunction(()=>state.currentView==='exclusions');
 assert(await page.locator('#pageTitle, #pageSubtitle').evaluateAll(labels=>labels.every(label=>label.scrollWidth<=label.clientWidth+1)),'mobile heading clipped');
 const deviceSection=page.locator('#listScopeContent');
 await page.locator('#view-exclusions [data-exclusion-section="listScopeContent"]').first().click();
 assert(await deviceSection.evaluate(el=>el===document.activeElement));
 assert(!await deviceSection.locator('[data-scope-field="mode"]').count());
 const printer=deviceSection.locator('[data-scope-list="excluded_device_ids"][data-scope-id="test-printer"]');
 await printer.check();
 assert(await printer.isChecked());assert(await deviceSection.locator('[data-scope-save]').isEnabled());
 assert(!await deviceSection.locator('[data-scope-list="device_ids"]').count());
 await printer.uncheck();
 assert(!await printer.isChecked());
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'device exclusions overflow on mobile');
 await capture('exclusions-mobile');
 await page.locator('#view-exclusions [data-exclusion-section="resourceExclusionsContent"]').first().click();
 assert(await page.locator('#resourceExclusionsContent').evaluate(el=>el===document.activeElement));
 const scopeProof=await page.evaluate(()=>{
   const service=state.services.find(entry=>entry.id==='telegram');
   const rule=service.applied_state;
   const summaries=interfaceSummaries();
   return [interfaceHomeProof(service,{...rule,sources:['192.0.2.2/32']},summaries,{}),
     interfaceHomeProof(service,rule,summaries,{telegram:['saved']})?.kind];
 });
 assert.deepEqual(scopeProof,[null,'unknown'],'old device scope or excluded service counted as verified');
 const noticeClear=await page.evaluate(()=>{
   const notice=document.querySelector('#a1-notice'),button=document.querySelector('[data-mobile-nav="overview"]');
   const hidden=notice.hidden;notice.hidden=false;
   try { return notice.getBoundingClientRect().bottom <= button.getBoundingClientRect().top; }
   finally { notice.hidden=hidden; }
 });
 assert(noticeClear,'status notice obscures mobile navigation');
 await page.setViewportSize({width:1440,height:1000});
 snapshot.policy.setup_complete=false;
 const manualRoute='xray:node-'+'a'.repeat(64);
 snapshot.applied_services={telegram:{...rules.telegram,route:manualRoute}};
 servicesFixture=[{id:'telegram',name:'Telegram Web',applied_state:snapshot.applied_services.telegram}];
 await page.reload({waitUntil:'networkidle'});
 const homeStatus=page.locator('#rzSimpleHome .rz-sh-status');
 assert.match(await homeStatus.innerText(),/Маршруты применены/,'first-run prompt hides active manual route');
 assert.doesNotMatch(await homeStatus.innerText(),/Начать настройку/);
 assert.match(await applied.innerText(),/Xray/);
 assert.doesNotMatch(await applied.innerText(),/node-/,'internal route ID shown instead of a connection');
 snapshot.stopped=true;snapshot.applied_services={};snapshot.catalog_services=[];servicesFixture=[];inventoryFixture=null;
 await page.reload({waitUntil:'networkidle'});
 assert.match(await homeStatus.innerText(),/Проект остановлен/);
 assert.doesNotMatch(await homeStatus.innerText(),/Начать настройку/,'stopped route should open the log');
 snapshot.policy.setup_complete=true;
 await page.evaluate(()=>setView('overview'));
 assert.deepEqual(await page.locator('[data-main-nav] use').evaluateAll(items=>items.filter(el=>!document.querySelector(el.getAttribute('href'))).map(el=>el.getAttribute('href'))),[],'missing navigation icons');
 for(const view of Object.keys(model.taskSections)){
  await page.locator(`[data-main-nav="${view}"]`).click();await checkView(view);
  if(['dns','diagnostics','nodes'].includes(view))await capture(view+'-desktop');
  assert.equal(await page.locator('.recovery-tools').isVisible(),view==='diagnostics');
 }
 await page.evaluate(()=>{appUpdateReadAt=0;});
 const updateReads=reads.filter(path=>path==='/api/v1/update').length;
 await page.locator('[data-main-nav="updates"]').click();
 await page.waitForFunction(()=>appUpdateRead===null);
 assert.equal(reads.filter(path=>path==='/api/v1/update').length,updateReads+1,'updates did not refresh cached status');
 assert(!reads.includes('/api/v1/update?refresh=true'),'navigation forced a release check');
 // The sidebar takes the user directly to each section.
 await page.locator('[data-main-nav="dns"]').click();
 assert.equal(await page.locator('#rzSimpleToggle').count(),0);
 await checkView('dns');
 await page.locator('[data-main-nav="settings"]').click();
 await page.getByRole('button',{name:'Изменить пароль',exact:true}).filter({visible:true}).first().click();
 assert(await page.locator('#currentPassword').evaluate(el=>el===document.activeElement),'shortcut did not focus password field');
 assert(await page.locator('#currentPassword').isVisible(),'account settings hidden');
 assert(!await page.locator('#rzSimpleSettings').isVisible(),'basic settings still visible');
 await page.locator('[data-main-nav="overview"]').click();
 assert(await page.locator('#rzSimpleHome').isVisible(),'opening settings changed the home layout');
 await page.locator('[data-main-nav="diagnostics"]').click();
 for(const id of ['hevRecoveryRepair','mihomoRecoveryRepair'])assert(await page.locator('#'+id).isDisabled());
 // Every original deep link, including subordinate pages, still resolves.
 for(const section of Object.values(model.taskSections))for(const [view] of section.children){
  await page.evaluate(v=>setView(v),view);
  assert(await page.locator('#view-'+view).isVisible(),view+' deep link');
  assert.equal(await page.locator('[data-main-nav][aria-current="page"]').getAttribute('data-main-nav'),model.navigation(view).owner);
 }
 await page.evaluate(()=>setView('overview'));
 await page.locator('#consoleTheme').click();await capture('home-light');
 await page.locator('#consoleTheme').click();
 await page.setViewportSize({width:390,height:844});
 await page.locator('#consoleMenu').click();
 await page.keyboard.press('Tab');
 assert(await page.evaluate(()=>!!document.activeElement.closest('.sidebar')),'drawer Tab focus escaped');
 await page.keyboard.press('Escape');
 assert.equal(await page.locator('#consoleMenu').getAttribute('aria-expanded'),'false');
 assert.equal(await page.evaluate(()=>document.activeElement.id),'consoleMenu');
 for(const view of Object.keys(model.taskSections)){
  await page.locator('#consoleMenu').click();
  await page.locator(`[data-main-nav="${view}"]`).click();await checkView(view);
  assert.equal(await page.locator('#consoleMenu').getAttribute('aria-expanded'),'false');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'pageTitle');
  const width=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,viewport:innerWidth}));
  assert(width.scroll<=width.viewport+1,view+' horizontal overflow '+JSON.stringify(width));
 }
 await page.locator('#consoleMenu').click();await capture('menu-mobile');
 await page.locator('[data-main-nav="overview"]').click();await capture('home-mobile');
 for(const saved of ['0','1']){
  await page.evaluate(value=>localStorage.setItem('razvilka.simpleMode',value),saved);
  await page.reload({waitUntil:'networkidle'});
  await page.waitForSelector('#rzSimpleHome',{state:'attached'});
  assert.equal(await page.locator('#rzSimpleHome').isVisible(),saved==='1');
  assert.equal(await page.locator('#rzSimpleToggle').count(),0);
 }
 // The quick and advanced wizards share the same saved service selection.
 snapshot.policy.setup_complete=false;
 snapshot.network_scope_mode='selected_devices';
 snapshot.initial_scope_mode='selected';
 snapshot.catalog_services=[{id:'youtube',name:'YouTube',default_nfqws2:true},{id:'sample-ai',name:'AI fixture',default_nfqws2:false}];
 snapshot.starter={eligible:true,sha256:'a'.repeat(64),items:[{id:'youtube',name:'YouTube',domains:1}],optional_ids:['sample-ai']};
 await page.reload({waitUntil:'networkidle'});
 await page.evaluate(()=>setView('onboard'));
 const quickPicker=page.locator('#a1-quickServices #a1-starterReview');
 await quickPicker.waitFor({state:'visible'});
 assert.equal(await page.locator('[name="quick-scope"], [name="quick-device"]').count(),0);
 assert.match(await page.locator('#a1-quickScopeHint').textContent(),/общей политикой/);
 assert(!await quickPicker.locator('[name="initial-starter"]').isChecked(),'initial services require explicit selection');
 const optionalSettings=page.locator('#a1-quickStart details');
 assert.equal(await optionalSettings.getAttribute('open'),null);
 await optionalSettings.locator('summary').click();
 assert.equal(await optionalSettings.locator('[data-rz-nav="devices"]').count(),0);
 for (const destination of ['exclusions','dns']) {
  await optionalSettings.locator(`[data-rz-nav="${destination}"]`).click();
  await page.waitForFunction(view=>state.currentView===view,destination);
  await page.evaluate(()=>setView('onboard'));
  await quickPicker.waitFor({state:'visible'});
 }
 await quickPicker.locator('[name="initial-extra"]').check();
 await page.locator('#a1-quickAdvanced').click();
 const advancedPicker=page.locator('#a1-wizardLayout #a1-starterReview');
 assert(await advancedPicker.isVisible(),'the first advanced step must show the same services');
 assert(!await page.locator('#a1-scopeMode').isVisible(),'scope picker must stay hidden during initial advanced setup');
 assert(!await advancedPicker.locator('[name="initial-starter"]').isChecked(),'switching setup reset an intentional empty starter selection');
 assert(await advancedPicker.locator('[name="initial-extra"]').isChecked(),'switching setup lost a chosen service');
 snapshot.catalog_services.push({id:'existing-site',name:'Existing site',default_nfqws2:false});
 snapshot.services={'existing-site':{enabled:true,all_lan:true}};
 snapshot.starter={eligible:true,sha256:'b'.repeat(64),items:[],optional_ids:['sample-ai']};
 await page.reload({waitUntil:'networkidle'});
 await page.evaluate(()=>setView('onboard'));
 await quickPicker.waitFor({state:'visible'});
 assert.equal(await quickPicker.locator('[name="initial-starter"]').count(),0);
 assert.equal(await quickPicker.locator('[name="initial-extra"]').count(),1);
 assert.equal(await quickPicker.locator('[name="initial-extra"]').inputValue(),'sample-ai');
 await page.evaluate(()=>setView('overview'));
 await page.locator('#a1-overviewServices .service-card').waitFor({state:'attached'});
 assert.match(await page.locator('#a1-overviewServices').textContent(),/Устройства, разрешённые общей политикой/);
 // Inspect a reviewed custom service while the catalog contains long DNS names.
 const digest='c'.repeat(64), serviceId='review-layout';
 const longName='a'.repeat(63)+'.'+'b'.repeat(63)+'.example.org';
 const review={service_id:serviceId,expected_revision:snapshot.policy.revision,expected_definition:digest,
  domains:[longName,...Array.from({length:32},(_,i)=>'service-'+i+'.example.org')],cidrs:['192.0.2.0/24'],
  probes:[],probe_url:'https://'+longName+'/',strategy:['nfqws2'],source_refs:[]};
 snapshot.catalog_services.push({id:serviceId,name:longName,review_definition:digest});
 snapshot.services[serviceId]={enabled:true,all_lan:true};
 await context.route('**/api/v1/autonomy/services?review='+serviceId,route=>route.fulfill({json:review}));
 for(const [label,width,height] of [['desktop',1440,1000],['mobile',390,844]]){
  await page.setViewportSize({width,height});
  await page.reload({waitUntil:'networkidle'});
  await page.evaluate(()=>setView('managed'));
  const show=page.locator('[data-show-definition="'+serviceId+'"]:visible');
  await show.click();
  const confirm=page.locator('[data-approve-definition="'+serviceId+'"]:visible');
  await confirm.waitFor();
  const card=confirm.locator('xpath=ancestor::article[1]');
  const available=await card.evaluate(el=>{const row=el.parentElement,s=getComputedStyle(row);return row.clientWidth-parseFloat(s.paddingLeft)-parseFloat(s.paddingRight);});
  if(label==='desktop') assert((await card.boundingBox()).width>=available-2,'long review confined to one grid column');
  await card.scrollIntoViewIfNeeded();
  if(output)await page.screenshot({path:resolve(output,'review-'+label+'.png')});
  const overflow=await card.evaluate(el=>[el,...el.querySelectorAll('b,p,button,section')].filter(e=>e.scrollWidth>e.clientWidth+1 && getComputedStyle(e).display!=='inline').map(e=>[e.tagName,e.clientWidth,e.scrollWidth]));
  assert.deepEqual(overflow,[],label+' overflowing definition or action');
  await confirm.focus();
  assert(await confirm.evaluate(el=>el===document.activeElement),'confirmation cannot receive focus');
  await confirm.click({trial:true});
  assert((await confirm.boundingBox()).height>=44,'small confirmation touch target');
  if(output&&label==='mobile')await page.screenshot({path:resolve(output,'review-mobile-action.png')});
 }
 // Exercise the public-profile review at its maximum service count without applying changes.
 await page.reload({waitUntil:'networkidle'});
 await page.evaluate(()=>setView('settings'));
 const allSettings=page.locator('[data-rz-set-advanced]');
 if(await allSettings.isVisible()) await allSettings.click();
 await page.evaluate(() => {
   const host = document.querySelector('#profilePreview');
   for (let p = host.parentElement; p; p = p.parentElement) if (p.tagName === 'DETAILS') p.open = true;
   const changes = Array.from({length:512}, (_, i) => ({id:'service-'+i, action:'change', enabled_before:true,
     enabled_after:true,route_before:'auto',route_after:'auto',sources_before:null,sources_after:['192.0.2.1/32']}));
   changes[511].sources_after = Array.from({length:4096}, (_,i)=>`10.0.${Math.floor(i/256)}.${i%256}/32`);
   state.profilePreview = {valid:true, name:'Pagination fixture',service_changes:changes};
   renderProfilePreview();
 });
 const changesPanel=page.locator('#profilePreview details').first();
 assert.equal(await changesPanel.locator('.profile-change-list > div').count(),0);
 await changesPanel.locator('> summary').click();
 await changesPanel.locator('.profile-change-list > div').first().waitFor();
 assert.equal(await changesPanel.locator('.profile-change-list > div').count(),12);
 const changePages=changesPanel.locator('[data-profile-changes] > nav input');
 await changePages.fill('43'); await changePages.press('Enter');
 const lastService=changesPanel.locator('.profile-change-list > div').filter({has:page.locator('b',{hasText:'service-511'})});
 await lastService.waitFor();
 assert.equal(await changesPanel.locator('.profile-change-list > div').count(),8);
 assert(!(await changesPanel.textContent()).includes('10.0.15.255/32'));
 await lastService.locator('summary').click();
 const addresses=lastService.locator('details [data-rows]');
 await addresses.waitFor();
 assert.match(await addresses.textContent(),/по общей политике LAN/);
 assert.match(await addresses.textContent(),/10\.0\.0\.15\/32/);
 assert(!(await addresses.textContent()).includes('10.0.0.16/32'));
 const addressPage=lastService.locator('nav input');
 await addressPage.fill('256'); await addressPage.press('Enter');
 assert.match(await addresses.textContent(),/10\.0\.15\.255\/32/);
 assert(!(await addresses.textContent()).includes('10.0.0.0/32'));
 await lastService.locator('[data-prev]').click();
 assert.match(await addresses.textContent(),/10\.0\.15\.239\/32/);
 await changePages.fill('1'); await changePages.press('Enter');
 assert.equal(await changesPanel.locator('details[open]').count(),0);
 await changesPanel.locator('> summary').click();
 await page.waitForFunction(()=>!document.querySelector('#profilePreview [data-profile-changes]').childElementCount);
 // Titles are shared by independent definitions. Filtering a managed record
 // out of the enrollment picker must not remove the other record's qualifier.
 const sameName='Telegram <b>Web</b>';
 const definitions=[
  {id:'telegram-web',name:sameName,custom:false},
  {id:'custom-telegram-web',name:sameName,custom:true},
  {id:'custom-telegram-copy',name:sameName,custom:true},
  {id:'video-only',name:'Видео',custom:false}
 ];
 servicesFixture=definitions.map(s=>({...s,category:'Мессенджеры',enabled:true,dirty:true,route:'auto',applied_state:{enabled:false,route:''}}));
 snapshot.policy.setup_complete=true;snapshot.policy.enabled=true;snapshot.stopped=false;
 await page.setViewportSize({width:1440,height:1000});
 snapshot.catalog_services=definitions;snapshot.services={'telegram-web':{enabled:true,all_lan:true}};
 await page.goto(origin,{waitUntil:'networkidle'});
 await page.locator('[data-main-nav="services"]').first().click();
 const titles=[sameName+' · встроенный',sameName+' · пользовательский · custom-telegram-web',sameName+' · пользовательский · custom-telegram-copy','Видео'];
 for(const [i,service] of definitions.entries()){
  const card=page.locator('#ui3ServiceCatalog [data-rz-card="'+service.id+'"]');
  assert.equal(await card.locator('h4').innerText(),titles[i]);
  assert.equal(await card.locator('h4 b').count(),0,'name interpreted as markup');
  assert.equal(await card.locator('.r5-service-description').innerText(),i===0?'Автоподбор включён':'Ручная настройка');
 }
 const options=selector=>page.locator(selector+' option').evaluateAll(rows=>rows.map(o=>[o.value,o.textContent]));
 const entries=definitions.map((s,i)=>[s.id,titles[i]]);
 assert.deepEqual(await options('#serviceAutoPickTarget'),entries);
 await page.locator('#ui3ServiceCatalog [data-rz-inspect="custom-telegram-web"]').first().click();
 assert.equal(await page.locator('#ui3InspectorTitle').innerText(),titles[1]);
 await page.locator('[data-rz-close="ui3ServiceDialog"]').click();
 await page.locator('[data-main-nav="autopilot"]').first().click();
 await page.locator('#view-autopilot [data-tab="services"]:visible').first().click();
 assert.deepEqual(await options('#a1-catalogSelect'),entries.slice(1));
 assert.equal(await page.locator('#a1-serviceRows .service-main b').first().innerText(),titles[0]);
 assert.deepEqual(errors,[],'browser exceptions');
 assert.deepEqual(writes,[],'navigation sent mutations');
 assert.deepEqual(external,[],'external requests');
 assert.deepEqual(missing,[],'missing assets');
 assert(!reads.some(path=>/^\/api\/v1\/components\/(mihomo|hev-socks5-tunnel)\/recovery/.test(path)),'navigation initiated component recovery');
 const report={result:'PASS',boundary:'Synthetic UI transport only; no backend, CI or router/LAN proof',desktop:'1440x1000',mobile:'390x844',navigationVisits:visited.length,deepLinks:Object.values(model.taskSections).flatMap(s=>s.children).length,errors,writes,external,missing,assets};
 if(output)writeFileSync(resolve(output,'report.json'),JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify({...report,assets:Object.keys(assets).length}));
}finally{await browser.close();}
