// Opt-in Windows D01/D12 gate. Real embedded assets, HTTP, cookies and Safe Mode;
// --policy-transport opts into a synthetic policy transport when the Windows
// component-path fence blocks autonomy. Without it, policy tests require backend.
// Build first, then set RAZVILKA_UI_BINARY, RAZVILKA_UI_CHROME and NODE_PATH
// (pointing at an installed playwright). No downloads or shared runtime state.
// RAZVILKA_UI_PORT selects an isolated unprivileged port; default 18851.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {randomBytes, createHash} from 'node:crypto';
import {readFileSync, writeFileSync, mkdirSync, mkdtempSync, existsSync, unlinkSync} from 'node:fs';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {connect} from 'node:net';

assert.equal(process.platform, 'win32', 'Linux native isolation belongs to the coordinator; this runner is Windows-only');
assert(process.env.RAZVILKA_UI_BINARY && process.env.RAZVILKA_UI_CHROME, 'Supply a built binary and installed Chromium executable');
const portText=process.env.RAZVILKA_UI_PORT ?? '18851';
assert(/^[1-9]\d{0,4}$/.test(portText) && Number(portText)>=1024 && Number(portText)<=65535,'RAZVILKA_UI_PORT must be an integer from 1024 to 65535');
const port=Number(portText),listen='127.0.0.1:'+port,origin='http://'+listen;
const {chromium} = createRequire(import.meta.url)('playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const local = join(root, '.review-local');
mkdirSync(local, {recursive:true});
const run = mkdtempSync(join(local, 'ui-http-'));
writeFileSync(join(run, '.gitignore'), '*\n');
const policyTransport = process.argv.includes('--policy-transport');
const authOnly = process.argv.includes('--auth-only');
const policyBoundary = policyTransport ? 'controlled policy transport' : 'real HTTP';
const occupied=await new Promise((resolve,reject)=>{
  const socket=connect({host:'127.0.0.1',port});
  socket.once('connect',()=>{socket.destroy();resolve(true);});
  socket.once('error',error=>{socket.destroy();if(error.code==='ECONNREFUSED')resolve(false);else reject(error);});
  socket.setTimeout(1000,()=>{socket.destroy();reject(new Error('Cannot inspect '+listen));});
});
assert(!occupied,listen+' already occupied');
const paths = {'config':'config.json','catalog':'service-catalog.json','sources':'sources.json','community-catalog':'community-catalog.json',
  'cache':'cache','stage':'stage','backups':'backups','token-file':'admin.token','credentials-file':'admin.credentials.json',
  'custom-services':'custom.json','warp-state':'warp','cloudflare-state':'cloudflare','smart-route-state':'smart-route.json',
  'dataplane-state':'dataplane','devices':'devices.json','metrics-history':'metrics.jsonl','strategy-lab-state':'strategy.json',
  'audit-log':'audit.jsonl','dns-state':'dns/state.json','node-state':'nodes','z2k-root':'absent-z2k',
  'component-state':'components','component-bin':'component-bin','component-init':'component-init','component-repo':'component-repo','component-info':'component-info'};
for (const [source, target] of [['config.example.json','config.json'],['service-catalog.json','service-catalog.json'],['sources.json','sources.json'],['community-catalog.json','community-catalog.json']]) {
  writeFileSync(join(run,target), readFileSync(join(root,'configs',source)));
}
const hashConfig = () => createHash('sha256').update(readFileSync(join(run,'config.json'))).digest('hex');
const configBefore = hashConfig();
const env = {...process.env, GOMAXPROCS:'2', GOFLAGS:'-p=2', RAZVILKA_USQUE_INIT:join(run,'absent-init'),
  RAZVILKA_USQUE_NDMC:join(run,'absent-ndmc'), RAZVILKA_USQUE_SHELL:join(run,'absent-shell'), RAZVILKA_USQUE_REPAIR_STATE:join(run,'usque-repair')};
const server = spawn(resolve(process.env.RAZVILKA_UI_BINARY), ['-listen',listen,...Object.entries(paths).flatMap(([flag,path])=>['-'+flag,join(run,path)])], {cwd:run, env, windowsHide:true, stdio:['ignore','pipe','pipe']});
let serverLog = '';
server.stdout.on('data', chunk=>{serverLog+=chunk;});server.stderr.on('data', chunk=>{serverLog+=chunk;});
let browser, context, page, browserVersion;
const results = [], errors = [], requests = [], screenshots = [];
async function capture(name,source) {
  await page.screenshot({path:join(run,name),fullPage:true,animations:'disabled'});
  screenshots.push({file:name,source,viewport:page.viewportSize()});
}
async function test(name, boundary, action) {
  const start=requests.length, began=performance.now();const checks=await action();
  results.push({name,boundary,wall_ms:Math.round(performance.now()-began),api_requests:requests.length-start,
    methods:requests.slice(start).reduce((counts,request)=>(counts[request.method]=(counts[request.method]||0)+1,counts),{}),...(checks?{checks}: {})});
  console.log('PASS '+boundary+': '+name);
}
function deferred() {let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
try {
  let ready = false;
  for(let i=0;i<120;i++) {
    assert(server.exitCode===null, 'server exited before readiness');
    try {if((await fetch(origin+'/api/v1/auth/status')).ok){ready=true;break;}}catch{}
    await delay(250);
  }
  assert(ready, 'server readiness timed out');
  browser = await chromium.launch({executablePath:process.env.RAZVILKA_UI_CHROME,headless:true});
  browserVersion = browser.version();
  context = await browser.newContext({viewport:{width:1280,height:900}});
  page = await context.newPage();
  page.on('pageerror', error=>errors.push(error.message));
  page.on('request', request=>{if(request.url().startsWith(origin+'/api/'))requests.push({method:request.method(),path:new URL(request.url()).pathname});});
  // Provision only this disposable account; D00's first-login UI is not repeated.
  const password = randomBytes(20).toString('hex');
  const setup = await context.request.post(origin+'/api/v1/auth/setup', {headers:{Authorization:'Bearer '+readFileSync(join(run,'admin.token'),'utf8').trim()},data:{username:'admin',password}});
  assert.equal(setup.status(),200);
  let fixturePolicy;
  const policySnapshot = () => ({policy:structuredClone(fixturePolicy),services:{},runtime:{},catalog_services:[],source_presets:[],safe_mode:true,blocked:false,server_time:new Date().toISOString()});
  const fakeResponse = (status, data) => ({status:()=>status,json:async()=>data});
  const fixturePut = (policy,expected_revision) => {
    if(expected_revision!==fixturePolicy.revision)return fakeResponse(409,{error:'Настройки изменились. Обновите страницу.'});
    fixturePolicy={...structuredClone(policy),revision:expected_revision+1};return fakeResponse(200,policySnapshot());
  };
  if(policyTransport && !authOnly) {
    const unavailable=await context.request.get(origin+'/api/v1/autonomy');assert.equal(unavailable.status(),503,'expected Windows component-path fence changed; run without --policy-transport');
    results.push({name:'autonomy blocked by real component recovery fence',boundary:'real backend 503'});
    const window={mode:'off',start:'03:00',end:'04:00',days:[0,1,2,3,4,5,6]};
    fixturePolicy={schema:1,revision:0,setup_complete:false,enabled:false,inherit_new_services:false,timezone:'UTC',all_lan:false,default_sources:[],source_ids:[],
      protocols:['vless'],preferred_routes:['xray'],check_seconds:120,reserve_seconds:600,reserve_target:3,candidates_per_round:2,failure_confirm_seconds:20,max_switches_per_hour:6,application:window,components:window};
    await context.route('**/api/v1/panel/autonomy',route=>route.fulfill({json:{schema:1,instance_id:'a'.repeat(32),revision:fixturePolicy.revision,observed_at:new Date().toISOString(),data_age_ms:0,state:'available',dataplane:'not-checked',data:policySnapshot()}}));
    await context.route('**/api/v1/autonomy',async route=>{
      if(route.request().method()==='PUT') {const {policy,expected_revision}=route.request().postDataJSON();const response=fixturePut(policy,expected_revision);return route.fulfill({status:response.status(),json:await response.json()});}
      return route.fulfill({json:policySnapshot()});
    });
  }
  const getPolicy = async()=>{if(policyTransport)return policySnapshot();const response=await context.request.get(origin+'/api/v1/autonomy');assert.equal(response.status(),200);return response.json();};
  const putPolicy = async(policy, expected_revision=policy.revision)=>policyTransport?fixturePut(policy,expected_revision):context.request.put(origin+'/api/v1/autonomy',{data:{expected_revision,policy,confirm:'SAVE_AUTONOMY',release_safe_mode:false}});
  const forwardPolicy = async route=>{if(!policyTransport)return route.fetch();const {policy,expected_revision}=route.request().postDataJSON();return fixturePut(policy,expected_revision);};
  const deliverPolicy = async(route,response)=>policyTransport?route.fulfill({status:response.status(),json:await response.json()}):route.fulfill({response});
  if(!authOnly) {
    const initial = await getPolicy();
    const policy = {...initial.policy, setup_complete:true, enabled:false, default_sources:['192.168.1.50/32'], inherit_new_services:false,reserve_seconds:600,
      application:{...initial.policy.application,mode:'off'},components:{...initial.policy.components,mode:'off'}};
    assert.equal((await putPolicy(policy)).status(),200);
  }
  const documentResponse = await page.goto(origin);
  const csp = documentResponse.headers()['content-security-policy'];
  assert(csp?.includes("default-src 'self'") && csp.includes("frame-ancestors 'none'"));
  await page.waitForFunction(()=>state.authenticated && !panelLoad.request);
  const nav = async name=>{await page.locator('.nav[data-view="'+name+'"]').click();await page.waitForFunction(name=>state.currentView===name,name);};
  const quickReady = ()=>page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled);

  await test('fast transitions and repeated refresh retain current workspace', 'real HTTP', async()=>{
    const writes = requests.filter(r=>r.method!=='GET').length;
    await page.evaluate(()=>{for(const name of ['nodes','services','devices','settings','autopilot','overview'])setView(name);for(let i=0;i<4;i++)void refreshAll();});
    await page.waitForFunction(()=>state.currentView==='overview' && !panelLoad.request);
    assert.equal(await page.locator('.view.active').getAttribute('id'),'view-overview');
    assert.equal(requests.filter(r=>r.method!=='GET').length,writes);
    assert.deepEqual(await page.evaluate(()=>state.uiRenderIssues),{});
  });
  if(!authOnly && !policyTransport)await capture('01-home.png','Настоящее локальное приложение; отдельная тестовая копия catalog/config, Safe Mode включён, автоматика выключена, native engines отсутствуют.');

  if(!policyTransport)await test('component recovery is a read-only journal view on navigation', 'real recovery GET', async()=>{
    const start=requests.length;await nav('engines');
    await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Незавершённых обновлений нет'));
    const response=await context.request.get(origin+'/api/v1/components/recovery');assert.equal(response.status(),200);
    assert.equal((await response.json()).recovery_required,false);
    assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0);
    assert.equal(await page.evaluate(()=>componentRecoveryFence()),false);
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
  });
  if(!authOnly && !policyTransport) {
    await test('mobile drawer fits, closes with focus and retains bottom navigation', 'real HTTP and browser layout 390 × 844', async()=>{
    await nav('nodes');await page.waitForFunction(()=>!panelLoad.request);
    await page.setViewportSize({width:390,height:844});
    if(await page.evaluate(()=>document.body.classList.contains('console-menu-open')))await page.locator('#consoleCloseMenu').click();
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    const layout=()=>page.evaluate(()=>{
      const root=document.documentElement,sidebar=document.querySelector('.sidebar'),main=document.querySelector('.main'),nav=document.querySelector('.ui3-mobile-nav');
      const rect=element=>{const r=element.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom};};
      return {scrollWidth:root.scrollWidth,clientWidth:root.clientWidth,bodyScrollWidth:document.body.scrollWidth,sidebar:rect(sidebar),main:rect(main),nav:rect(nav),
        sidebarInert:sidebar.inert,brand:rect(sidebar.querySelector('.brand b')),focus:document.activeElement?.id,
        navVisible:[...nav.querySelectorAll('button')].every(button=>{const r=button.getBoundingClientRect();return r.width>0 && r.height>0 && r.top>=0 && r.bottom<=innerHeight && document.elementFromPoint(r.left+r.width/2,r.top+r.height/2)?.closest('.ui3-mobile-nav')===nav;})};
    });
    const closed=await layout();assert(closed.scrollWidth<=closed.clientWidth);assert(closed.bodyScrollWidth<=closed.clientWidth);
    assert(closed.main.left>=0);assert(closed.main.right<=closed.clientWidth);assert(closed.sidebarInert);assert(closed.navVisible,'closed drawer obscures bottom navigation');
    await capture('03-connections-narrow.png','Настоящий HTTP; пустая библиотека подключений в отдельном тестовом состоянии, экран 390 × 844.');
    await page.locator('#consoleMenu').click();await page.waitForFunction(()=>Math.abs(document.querySelector('.sidebar').getBoundingClientRect().left)<1);
    const open=await layout();assert(open.scrollWidth<=open.clientWidth);assert(open.bodyScrollWidth<=open.clientWidth);
    assert(open.brand.left>=0 && open.brand.right<=open.sidebar.right,'drawer clips the brand');assert(!open.sidebarInert);assert.equal(open.focus,'consoleCloseMenu');
    assert(open.navVisible,'open drawer obscures bottom navigation');
    await capture('04-mobile-drawer-open.png','Настоящий HTTP; открытое меню над пустой библиотекой, экран 390 × 844.');
    await page.keyboard.press('Escape');await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert.equal((await layout()).focus,'consoleMenu');assert.equal(await page.locator('#consoleMenu').getAttribute('aria-expanded'),'false');
    await page.locator('#consoleMenu').click();await page.locator('#consoleCloseMenu').click();
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);assert.equal((await layout()).focus,'consoleMenu');
    await page.locator('#consoleMenu').click();await page.locator('#consoleMenuBackdrop').click({position:{x:375,y:300}});
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);assert.equal((await layout()).focus,'consoleMenu');
    await page.locator('#consoleMenu').click();await page.locator('.sidebar .nav[data-view="settings"]').click();
    await page.waitForFunction(()=>state.currentView==='settings' && document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert.equal((await layout()).focus,'pageTitle','drawer navigation left focus in the hidden sidebar');
    await page.locator('#consoleMenu').click();await page.locator('.ui3-mobile-nav [data-mobile-nav="nodes"]').click();
    await page.waitForFunction(()=>state.currentView==='nodes' && document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert((await layout()).navVisible);
    await page.setViewportSize({width:1280,height:900});
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
    return {closed,open,closeMethods:['Escape','close button','backdrop','drawer destination','bottom destination']};
    });
  }

  if(!authOnly) {
  await nav('autopilot');await quickReady();
  await test('duplicate Save sends one PUT with independent readback', policyBoundary, async()=>{
    await page.locator('#autoQuickCheck').fill('180');
    const start=requests.length;
    await page.evaluate(()=>{const form=document.getElementById('autoQuickForm');form.requestSubmit();form.requestSubmit();});
    await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled && !document.getElementById('autoQuickRevision').textContent.includes('есть правки'));
    assert.equal(requests.slice(start).filter(r=>r.path==='/api/v1/autonomy'&&r.method==='PUT').length,1);
    assert.equal((await getPolicy()).policy.check_seconds,180);
  });

  await test('CAS conflict keeps draft until explicit reset', policyTransport?'controlled policy transport 409':'real backend 409', async()=>{
    await page.locator('#autoQuickCheck').fill('240');
    // A second authenticated HTTP writer commits immediately before forwarding
    // the browser's stale PUT. The server, not the transport, emits the 409.
    let status;
    await page.route('**/api/v1/autonomy', async route=>{
      if(route.request().method()!=='PUT')return route.continue();
      const current=await getPolicy();assert.equal((await putPolicy({...current.policy,check_seconds:300})).status(),200);
      const response=await forwardPolicy(route);status=response.status();await deliverPolicy(route,response);
    });
    await page.locator('#autoQuickSave').click();
    await page.waitForFunction(()=>document.getElementById('autoQuickMessage').textContent.includes('изменились'));
    assert.equal(status,409);
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'240');
    await page.unroute('**/api/v1/autonomy');
    await page.locator('#autoQuickRefresh').click();
    await page.waitForFunction(()=>document.getElementById('autoQuickSave').disabled && document.getElementById('autoQuickMessage').textContent.includes('Ваши поля сохранены'));
    await page.locator('#autoQuickReset').click();await quickReady();
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'300');
  });

  await test('500 after committed write fences replay and preserves fields', 'controlled transport 500', async()=>{
    await page.locator('#autoQuickCheck').fill('360');let writes=0;
    await page.route('**/api/v1/autonomy',async route=>{
      if(route.request().method()!=='PUT')return route.continue();
      writes++;const response=await forwardPolicy(route);assert.equal(response.status(),200);
      await route.fulfill({status:500,contentType:'application/json',body:JSON.stringify({error:'test response lost after commit'})});
    });
    await page.locator('#autoQuickSave').click();
    await page.waitForFunction(()=>document.getElementById('autoQuickSave').disabled && !document.getElementById('autoQuickCheck').disabled);
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'360');
    await page.evaluate(()=>document.getElementById('autoQuickForm').requestSubmit());
    assert.equal(writes,1);
    await page.unroute('**/api/v1/autonomy');
    await page.locator('#autoQuickRefresh').click();
    await page.waitForFunction(()=>document.getElementById('autoQuickMessage').textContent.includes('Ваши поля сохранены'));
    await page.locator('#autoQuickReset').click();await quickReady();
    assert.equal((await getPolicy()).policy.check_seconds,360);
  });

  await test('read errors retain data and do not pull hidden workspace', 'controlled transport 409/500', async()=>{
    await nav('services');await page.waitForFunction(()=>!panelLoad.request);
    const ids=await page.evaluate(()=>state.services.map(s=>s.id).sort());
    for(const status of [409,500]) {
      await page.route('**/api/v1/services',route=>route.fulfill({status,contentType:'application/json',body:JSON.stringify({error:'test read fault',...(status===409?{code:'RESTORE_OPERATION_BUSY'}:{})})}));
      await page.evaluate(()=>refreshAfterMutation());
      assert.deepEqual(await page.evaluate(()=>state.services.map(s=>s.id).sort()),ids);
      assert(['busy','error'].includes(await page.evaluate(()=>state.dataLoad.services.phase)),'read fault incorrectly marked ready');
      assert.equal(await page.evaluate(()=>state.loadIssues.find(issue=>issue.section==='services')?.busy),status===409);
      await page.unroute('**/api/v1/services');
    }
    const start=requests.length;await nav('settings');
    await page.waitForFunction(()=>!panelLoad.request && state.dataLoad.sessions?.phase==='ready');
    assert(!requests.slice(start).some(r=>['/api/v1/engine-configs','/api/v1/dns','/api/v1/strategy-lab'].includes(r.path)));
    await page.evaluate(()=>refreshAll(true));
    assert(!requests.slice(start).some(r=>r.path==='/api/v1/services'));
  });
  }

  if(!authOnly && !policyTransport) {
    // Only the disposable journal is a fixture. The embedded UI, decoder,
    // recovery GET, authority rejection and corrupt-journal 503 are real.
    // No package, runtime or acceptance proof is fabricated by these tests.
    const journalDir=join(run,paths['component-state'],'update-journal');mkdirSync(journalDir,{recursive:true});
    const journalPath=join(journalDir,'current.json');
    const journal={schema_version:1,transaction_id:'c'.repeat(32),component:'xray',phase:'prepared',before_version:'1.0',after_version:'2.0',
      updated_at:new Date().toISOString(),package:'xray',package_file:'xray_1.0_all.ipk',package_sha256:'d'.repeat(64),configs:[]};
    try {
      await test('pending journal stays fenced and Safe Mode rejects matching recovery', 'real recovery HTTP + disposable journal fixture', async()=>{
        writeFileSync(journalPath,JSON.stringify(journal));await nav('engines');
        await page.evaluate(()=>refreshComponentRecovery());
        const panel=page.locator('#view-engines [data-component-recovery-panel]');
        await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Подготовлено'));
        assert.equal(await panel.locator('[data-component-repair]').count(),0,'Safe Mode capabilities exposed repair');
        assert.equal(await page.evaluate(()=>state.status.safe_mode),true);
        const observed=await context.request.get(origin+'/api/v1/components/recovery');assert.equal(observed.status(),200);
        const body=await observed.json();assert.equal(body.recovery_required,true);
        assert.deepEqual(body.capabilities.available_actions,[]);
        const before=readFileSync(journalPath,'utf8');
        const rejected=await context.request.post(origin+'/api/v1/components/recovery',{data:{transaction_id:journal.transaction_id,component:journal.component,
          action:'abandon-prepared',expected_revision:body.revision,confirm:'REPAIR_COMPONENT_TRANSACTION'}});
        assert.equal(rejected.status(),409);assert.equal((await rejected.json()).code,'COMPONENT_AUTHORITY_CHANGED');
        assert.equal(readFileSync(journalPath,'utf8'),before,'Safe Mode repair changed the journal');
        journal.schema_version=2;journal.phase='upgrade-started';writeFileSync(journalPath,JSON.stringify(journal));
        const start=requests.length;await panel.locator('[data-component-recovery-read]').click();
        await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Исход установки неизвестен'));
        assert.equal(await panel.locator('[data-component-repair]').count(),0);
        assert.equal(await page.evaluate(()=>componentRecoveryFence()),true);
        assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0);
        const schema2=await context.request.get(origin+'/api/v1/components/recovery');assert.equal(schema2.status(),200);
        assert.equal((await schema2.json()).transaction.schema_version,2);
        await capture('02-component-recovery.png','Настоящий HTTP и интерфейс; только pending upgrade-started журнал — заготовка в собственном одноразовом каталоге. Не доказательство native установки.');
      });
      await test('schema 2 idle terminal read stays neutral without guessed actions', 'real recovery GET + disposable idle journal fixture', async()=>{
        journal.phase='accepted-installed-idle';journal.candidate_snapshot=true;journal.candidate_configs=[];
        writeFileSync(journalPath,JSON.stringify(journal));const start=requests.length;
        const panel=page.locator('#view-engines [data-component-recovery-panel]');await panel.locator('[data-component-recovery-read]').click();
        await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Неактивная версия принята по журналу'));
        assert.equal(await page.evaluate(()=>componentRecoveryFence()),false);
        assert.equal(await page.evaluate(()=>componentRecoverySummary('xray').tone),'unknown');
        assert.equal(await panel.locator('[data-component-repair]').count(),0);
        assert.match(await panel.textContent(),/доступ сервисов ещё не подтверждены/);
        assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0);
      });
      await test('corrupt journal reports real 503 and readback remains available', 'real recovery 503 + disposable corrupt fixture', async()=>{
        writeFileSync(journalPath,'{"schema_version":');
        const response=await context.request.get(origin+'/api/v1/components/recovery');assert.equal(response.status(),503);
        assert.equal((await response.json()).code,'COMPONENT_JOURNAL_UNAVAILABLE');
        const panel=page.locator('#view-engines [data-component-recovery-panel]');
        await panel.locator('[data-component-recovery-read]').click();
        await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Журнал обновления не читается'));
        assert.equal(await panel.locator('[data-component-repair]').count(),0);
        assert.equal(await panel.locator('[data-component-recovery-read]').isEnabled(),true);
        assert.equal(await page.evaluate(()=>componentRecoveryFence()),true);
      });
    } finally {
      if(existsSync(journalPath))unlinkSync(journalPath);
      await page.evaluate(()=>refreshComponentRecovery());
    }
    await page.waitForFunction(()=>!componentRecoveryFence());
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
  }

  await test(authOnly?'session revocation returns real 401':'session revocation during dirty form returns real 401', 'real backend 401', async()=>{
    if(!authOnly){await nav('autopilot');await quickReady();await page.locator('#autoQuickCheck').fill('420');}
    assert.equal((await context.request.post(origin+'/api/v1/auth/logout',{data:{}})).status(),200);
    await page.evaluate(()=>refreshAll());
    await page.waitForFunction(()=>!state.authenticated && !document.getElementById('authScreen').hidden);
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'');
    const response=await context.request.get(origin+'/api/v1/autonomy');assert.equal(response.status(),401);
  });

  // Pending login has a real server response. Delay only delivery to the UI.
  await test('duplicate login is single-flight and late response cannot reopen session', 'delayed real HTTP response', async()=>{
    await page.locator('#loginPassword').fill(password);
    const release=deferred(),received=deferred();let posts=0;
    await page.route('**/api/v1/auth/login',async route=>{
      posts++;const response=await route.fetch();assert.equal(response.status(),200);received.resolve();await release.promise;await route.fulfill({response});
    });
    await page.evaluate(()=>{document.getElementById('loginForm').requestSubmit();document.getElementById('loginForm').requestSubmit();});
    await received.promise;
    // The application receives an auth lifecycle transition while old login
    // delivery is pending; no old callback may hide the current auth form.
    await page.evaluate(()=>showAuth({authenticated:false},'test new auth generation'));
    release.resolve();await page.unroute('**/api/v1/auth/login',{behavior:'wait'});
    await page.waitForFunction(()=>document.getElementById('authMessage').textContent!=='test new auth generation' || !state.authenticated);
    await delay(250);
    assert.equal(posts,1,'duplicate form submitted two authentication POSTs');
    assert.equal(await page.evaluate(()=>state.authenticated),false,'old login response reopened the application');
  });
  await test('late real 401 from revoked session cannot close a new login', 'delayed real backend 401', async()=>{
    await page.locator('#loginPassword').fill(password);await page.locator('#loginForm button[type="submit"]').click();
    await page.waitForFunction(()=>state.authenticated && !state.authAction);
    const received=deferred(),fetchOld=deferred(),responseReady=deferred(),release=deferred();
    let held=false;
    await page.route('**/api/v1/services',async route=>{
      if(held)return route.continue();held=true;received.resolve();await fetchOld.promise;
      const response=await route.fetch();assert.equal(response.status(),401);responseReady.resolve();await release.promise;
      await route.fulfill({response});
    });
    await page.evaluate(()=>{setView('services');});await received.promise;
    assert.equal((await context.request.post(origin+'/api/v1/auth/logout',{data:{}})).status(),200);
    fetchOld.resolve();await responseReady.promise;
    await page.evaluate(()=>showAuth({authenticated:false}));
    await page.locator('#loginPassword').fill(password);await page.locator('#loginForm button[type="submit"]').click();
    await page.waitForFunction(()=>state.authenticated && !state.authAction);
    release.resolve();await page.unroute('**/api/v1/services',{behavior:'wait'});await delay(250);
    assert.equal(await page.evaluate(()=>state.authenticated),true);
    assert.equal(await page.locator('#authScreen').isVisible(),false);
  });
  await test('logout status failure leaves local panel closed without an exception', 'real logout + controlled status failure', async()=>{
    const forbidden=await context.request.put(origin+'/api/v1/autonomy',{headers:{Origin:'http://untrusted.invalid'},data:{}});
    assert.equal(forbidden.status(),403,'CSRF guard was bypassed');
    let expired=false;
    await page.route('**/api/v1/auth/status',route=>expired?route.fulfill({status:500,json:{error:'test status fault'}}):route.continue());
    await page.route('**/api/v1/auth/logout',async route=>{const response=await route.fetch();assert.equal(response.status(),200);expired=true;await route.fulfill({response});});
    await page.locator('#logoutButton').click();
    await page.waitForFunction(()=>!state.authenticated && !state.authAction);
    assert.equal(await page.locator('.app-shell').evaluate(element=>element.inert),true);
    assert.equal(await page.locator('#loginForm button[type="submit"]').isEnabled(),true);
    assert.match(await page.locator('#authMessage').textContent(),/Вы вышли/);
    await page.unroute('**/api/v1/auth/status');await page.unroute('**/api/v1/auth/logout');
    assert.equal((await context.request.get(origin+'/api/v1/autonomy')).status(),401);
  });
  assert.deepEqual(errors,[],'uncaught browser exception');
  assert.equal(hashConfig(),configBefore,'network configuration changed during UI gate');
  assert.equal(JSON.parse(readFileSync(join(run,'config.json'),'utf8')).safe_mode,true);
} finally {
  if(page && !page.isClosed())writeFileSync(join(run,'ui-state.json'),JSON.stringify(await page.evaluate(()=>({view:state.currentView,authenticated:state.authenticated,dataLoad:state.dataLoad,issues:state.uiRenderIssues,quick:{message:document.getElementById('autoQuickMessage').textContent,revision:document.getElementById('autoQuickRevision').textContent,value:document.getElementById('autoQuickCheck').value,disabled:document.getElementById('autoQuickSave').disabled}})),null,2));
  if(browser)await browser.close();
  server.kill();
  await Promise.race([new Promise(r=>server.once('exit',r)),delay(5000)]);
  writeFileSync(join(run,'server.log'),serverLog);
  writeFileSync(join(run,'result.json'),JSON.stringify({browserVersion,origin,port,policyTransport,authOnly,results,errors,requests,screenshots,configUnchanged:hashConfig()===configBefore},null,2));
  console.log('Local artifacts: '+run);
}
