// Presentation-only gate: production assets, synthetic stopped/empty state.
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
   if(url.pathname==='/api/v1/status')value={authenticated:true,setup_required:false,version:'UI fixture',stopped:true};
   if(url.pathname==='/api/v1/panel/availability')value={schema:1,name:'RAZVILKA',panel:'responding',dataplane:'not-checked',admission:{state:'idle',active:0,exclusive:false,fenced:false}};
   if(url.pathname==='/api/v1/autonomy')value=snapshot;
   if(url.pathname==='/api/v1/panel/autonomy')value={schema:1,instance_id:'a'.repeat(32),revision:1,dataplane:'not-checked',state:'available',data_age_ms:0,observed_at:new Date().toISOString(),data:{...snapshot,server_time:new Date().toISOString()}};
   if(['/api/v1/services','/api/v1/engine-configs','/api/v1/routes/options'].includes(url.pathname))value=[];
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
 const capture=async name=>{if(output)await page.screenshot({path:resolve(output,name+'.png'),fullPage:name!=='menu-mobile'});};
 const checkView=async view=>{
  await page.waitForFunction(v=>state.currentView===v,view);
  assert(await page.locator('#view-'+view).isVisible(),view+' hidden');
  assert.equal(await page.locator('[data-main-nav][aria-current="page"]').count(),1,view+' current item');
  assert.equal(await page.locator(`[data-main-nav="${view}"]`).getAttribute('aria-current'),'page');
  if(model.taskSections[view].children.length>1)assert(await page.locator('#interfaceSubnav').isVisible(),view+' subnavigation hidden');
  visited.push(view);
 };
 await capture('home-desktop');
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
 // Changing presentation must retain the current destination in both directions.
 await page.locator('[data-main-nav="dns"]').click();
 for(let i=0;i<2;i++){await page.locator('#rzSimpleToggle').click();await checkView('dns');}
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
 assert.deepEqual(errors,[],'browser exceptions');
 assert.deepEqual(writes,[],'navigation sent mutations');
 assert.deepEqual(external,[],'external requests');
 assert.deepEqual(missing,[],'missing assets');
 assert(!reads.some(path=>/^\/api\/v1\/components\/(mihomo|hev-socks5-tunnel)\/recovery/.test(path)),'navigation initiated component recovery');
 const report={result:'PASS',boundary:'Synthetic UI transport only; no backend, CI or router/LAN proof',desktop:'1440x1000',mobile:'390x844',navigationVisits:visited.length,deepLinks:Object.values(model.taskSections).flatMap(s=>s.children).length,errors,writes,external,missing,assets};
 if(output)writeFileSync(resolve(output,'report.json'),JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify({...report,assets:Object.keys(assets).length}));
}finally{await browser.close();}
