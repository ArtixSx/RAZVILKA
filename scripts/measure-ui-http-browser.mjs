// Opt-in measurements against an EXISTING HTTP server. Never starts a server,
// seeds a fixture, runs probes, or submits configuration/package actions.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,mkdtempSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function settings(env){
  assert(env.RAZVILKA_PERF_URL,'Supply RAZVILKA_PERF_URL for an existing isolated server');
  const url=new URL(env.RAZVILKA_PERF_URL);
  assert(['http:','https:'].includes(url.protocol)&&!url.username&&!url.password&&!url.search&&!url.hash&&url.pathname==='/','Use an HTTP(S) origin without credentials, path or query');
  assert(['empty','loaded'].includes(env.RAZVILKA_PERF_PROFILE),'Declare RAZVILKA_PERF_PROFILE=empty or loaded; the runner never seeds data');
  assert(env.RAZVILKA_PERF_CHROME,'Supply an installed Chromium executable; no browser downloads');
  const session=env.RAZVILKA_PERF_SESSION;
  const credentials=!!env.RAZVILKA_PERF_USERNAME&&!!env.RAZVILKA_PERF_PASSWORD;
  assert(!!session!==credentials,'Supply either an existing session file or username/password via env');
  assert(session||credentials,'Supply authentication for the existing server');
  const number=(key,fallback,min,max)=>{const text=env[key]??String(fallback);assert(/^\d+$/.test(text)&&Number(text)>=min&&Number(text)<=max,key+' is outside its allowed range');return Number(text);};
  return {origin:url.origin,profile:env.RAZVILKA_PERF_PROFILE,chrome:resolve(env.RAZVILKA_PERF_CHROME),session:session?resolve(session):null,
    username:env.RAZVILKA_PERF_USERNAME,password:env.RAZVILKA_PERF_PASSWORD,
    dwellMs:number('RAZVILKA_PERF_DWELL_MS',2000,250,30000),idleMs:number('RAZVILKA_PERF_IDLE_MS',16000,1000,60000),timeoutMs:number('RAZVILKA_PERF_TIMEOUT_MS',45000,5000,120000),
    output:env.RAZVILKA_PERF_OUTPUT?resolve(env.RAZVILKA_PERF_OUTPUT):null};
}

export function readOnlyDecision(origin,url,method){
  const target=new URL(url);
  if(target.origin!==origin)return 'external-blocked';
  if(!['GET','HEAD','OPTIONS'].includes(method))return 'mutation-blocked';
  if(target.searchParams.get('refresh')==='true'||target.searchParams.get('force')==='true')return 'forced-read-blocked';
  return 'read';
}

export function requestSummary(records,expected=[]){
  const counts={},statuses={},other={};
  for(const r of records){
    const key=r.method+' '+r.path;counts[key]=(counts[key]||0)+1;
    const status=r.blocked?'blocked':r.status==null?r.failed?'failed':'pending':String(r.status);statuses[status]=(statuses[status]||0)+1;
    if(r.api&&!expected.includes(r.path))other[key]=(other[key]||0)+1;
  }
  const api=records.filter(r=>r.api),stream=records.filter(r=>r.resource_type==='eventsource');
  return {attempts:records.length,forwarded:records.filter(r=>!r.blocked).length,api_attempts:api.length,api_forwarded:api.filter(r=>!r.blocked).length,
    methods:records.reduce((out,r)=>(out[r.method]=(out[r.method]||0)+1,out),{}),by_path:counts,statuses,
    unfinished_non_stream:records.filter(r=>!r.finished&&!r.blocked&&r.resource_type!=='eventsource').length,streams:stream.length,other_api_paths:other};
}

const durationKeys=['TaskDuration','ScriptDuration','LayoutDuration','RecalcStyleDuration'];
const countKeys=['LayoutCount','RecalcStyleCount'];
export function metricDelta(before,after){
  const result={};
  for(const key of [...durationKeys,...countKeys]){
    result[key]=Number.isFinite(after[key])&&(!before||Number.isFinite(before[key]))?after[key]-(before?.[key]||0):null;
    if(result[key]<0)result[key]=null; // A renderer reset is unavailable, never zero work.
  }
  return {duration_ms:Object.fromEntries(durationKeys.map(key=>[key,result[key]===null?null:Number((result[key]*1000).toFixed(3))])),
    counts:Object.fromEntries(countKeys.map(key=>[key,result[key]])),
    end:Object.fromEntries(['Nodes','Documents','JSEventListeners','JSHeapUsedSize'].map(key=>[key,Number.isFinite(after[key])?after[key]:null]))};
}

export function fixtureMatches(profile,counts){
  const required=['nodes','groups','catalog_services','enabled_services','applied_services'];
  if(!counts||required.some(key=>!Number.isSafeInteger(counts[key])||counts[key]<0))return false;
  const populated=counts.nodes+counts.groups+counts.enabled_services+counts.applied_services>0;
  return profile==='empty'?!populated:profile==='loaded'&&populated;
}

async function run(config){
  const {chromium}=createRequire(import.meta.url)('playwright');
  const local=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');
  mkdirSync(local,{recursive:true});const directory=mkdtempSync(join(local,'ui-perf-'));writeFileSync(join(directory,'.gitignore'),'*\n');
  const report={schema:1,started_at:new Date().toISOString(),origin:config.origin,fixture:{declared:config.profile,verified:false,definition:'user library: nodes, groups, enabled/applied services; devices and installed inventory are separate observations'},
    environment:{node:process.version,platform:process.platform,arch:process.arch,browser:null},
    configuration:{viewport:{width:1280,height:900},dwell_ms:config.dwellMs,idle_ms:config.idleMs,timeout_ms:config.timeoutMs,browser_cache:'disabled by the request safety fence'},
    boundaries:{server:'existing HTTP only',device_cpu_rss:'not collected; coordinator measures separately',native_acceptance:false,
      content:'no response bodies, request bodies, headers, query strings, cookies, profiles, DOM text or screenshots saved'},
    authentication:{mode:config.session?'existing-session':'env-login',requests:[]},scenarios:[],requests:[],blocked:[],browser_errors:[],failure:null};
  const save=()=>writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));
  let browser,page,context,cdp,stage='authentication';const known=new Map();let next=0;
  const metrics=async()=>Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(item=>[item.name,item.value]));
  const guard=()=>assert.equal(report.blocked.length,0,'The page attempted an action outside the read-only measurement boundary');
  try{
    browser=await chromium.launch({executablePath:config.chrome,headless:true});report.environment.browser=browser.version();
    context=await browser.newContext({viewport:report.configuration.viewport,serviceWorkers:'block',...(config.session?{storageState:config.session}:{})});
    await context.route('**/*',async route=>{
      const request=route.request(),decision=readOnlyDecision(config.origin,request.url(),request.method());
      if(decision==='read')return route.continue();
      const record=known.get(request);if(record)record.blocked=decision;
      report.blocked.push({stage,method:request.method(),path:new URL(request.url()).pathname,reason:decision});
      await route.abort('blockedbyclient');
    });
    // The sole explicit POST is authentication, outside all timing scenarios.
    // APIRequestContext has no arbitrary mutation helper in this runner.
    if(!config.session){
      const response=await context.request.post(config.origin+'/api/v1/auth/login',{data:{username:config.username,password:config.password},timeout:config.timeoutMs});
      report.authentication.requests.push({method:'POST',path:'/api/v1/auth/login',status:response.status()});
      assert.equal(response.status(),200,'Authentication failed; no setup/reset/recovery action is attempted');
    }
    await context.addInitScript(()=>{
      window.__razvilkaPerf={longTasks:[],supported:PerformanceObserver.supportedEntryTypes.includes('longtask')};
      if(window.__razvilkaPerf.supported)new PerformanceObserver(list=>{for(const entry of list.getEntries())window.__razvilkaPerf.longTasks.push({start:entry.startTime,duration:entry.duration});}).observe({type:'longtask',buffered:false});
    });
    page=await context.newPage();page.setDefaultTimeout(config.timeoutMs);
    page.on('pageerror',error=>report.browser_errors.push({stage,name:error.name}));
    page.on('request',request=>{
      const url=new URL(request.url());
      const record={id:++next,stage,method:request.method(),path:url.pathname,api:url.origin===config.origin&&url.pathname.startsWith('/api/'),
        resource_type:request.resourceType(),started_at:new Date().toISOString(),status:null,finished:false};
      known.set(request,record);report.requests.push(record);
    });
    page.on('response',response=>{const record=known.get(response.request());if(record)record.status=response.status();});
    page.on('requestfinished',request=>{const record=known.get(request);if(record){record.finished=true;record.finished_at=new Date().toISOString();}});
    page.on('requestfailed',request=>{const record=known.get(request);if(record){record.finished=true;record.failed=true;record.finished_at=new Date().toISOString();}});
    cdp=await context.newCDPSession(page);await cdp.send('Performance.enable');
    const settled=async()=>{
      await page.waitForFunction(()=>typeof state!=='undefined'&&state.authenticated&&typeof panelLoad!=='undefined'&&!panelLoad.request,null,{timeout:config.timeoutMs});
      guard();
    };
    const navigate=async view=>{
      await page.locator('.nav[data-view="'+view+'"]').click();await page.waitForFunction(view=>state.currentView===view,view);await settled();
    };
    async function measure(name,view,action,dwell=config.dwellMs,cold=false){
      stage=name;const start=report.requests.length,startedAt=new Date().toISOString(),began=performance.now();
      const before=cold?null:await metrics();
      const mark=cold?0:await page.evaluate(()=>performance.now());
      console.log('START '+startedAt+' '+name);
      await action();await page.waitForTimeout(dwell);guard();
      const after=await metrics(),elapsed=performance.now()-began;
      const layout=await page.evaluate(mark=>{
        const active=document.querySelector('.view.active'),root=document.documentElement,visible=element=>!!element?.getClientRects().length;
        const rect=element=>{if(!visible(element))return null;const r=element.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
        const tasks=(window.__razvilkaPerf?.longTasks||[]).filter(task=>task.start>=mark);
        const expected=typeof panelViewRequests==='function'?panelViewRequests().map(([,path])=>new URL(path,location.href).pathname):[];
        const shared=['/api/v1/auth/status','/api/v1/panel/snapshot','/api/v1/panel/autonomy','/api/v1/panel/availability','/api/v1/service-control','/api/v1/service-control/current','/api/v1/node-checks/current','/api/v1/node-autofallback','/api/v1/update','/api/v1/plan','/api/v1/connections/stream'];
        return {view:state.currentView,visibility:document.visibilityState,dom:{total:document.getElementsByTagName('*').length,active_view:active?active.getElementsByTagName('*').length:0,
          hidden_views:[...document.querySelectorAll('.view:not(.active)')].map(element=>({id:element.id,nodes:element.getElementsByTagName('*').length}))},
          geometry:{viewport:{width:innerWidth,height:innerHeight},document_width:root.clientWidth,scroll_width:root.scrollWidth,horizontal_overflow_px:Math.max(0,root.scrollWidth-root.clientWidth),
            active_view:rect(active),main:rect(document.querySelector('.main')),mobile_nav:rect(document.querySelector('.ui3-mobile-nav'))},
          read_state:Object.fromEntries(Object.entries(state.dataLoad||{}).map(([key,value])=>[key,{loaded:value.loaded===true,phase:value.phase}])),
          expected_panel_paths:expected,shared_paths:shared,
          long_tasks:{supported:window.__razvilkaPerf?.supported===true,count:tasks.length,total_ms:tasks.reduce((sum,task)=>sum+task.duration,0),max_ms:tasks.reduce((max,task)=>Math.max(max,task.duration),0)}};
      },mark);
      assert.equal(layout.view,view,'Navigation did not retain the requested view');
      const records=report.requests.slice(start),requestCounts=requestSummary(records,[...layout.expected_panel_paths,...layout.shared_paths]);
      report.scenarios.push({name,started_at:startedAt,finished_at:new Date().toISOString(),wall_ms:Math.round(elapsed),dwell_ms:dwell,request_ids:records.map(record=>record.id),
        requests:requestCounts,browser:metricDelta(before,after),...layout});
      save();console.log('END '+name+' '+requestCounts.api_forwarded+' API requests; task '+report.scenarios.at(-1).browser.duration_ms.TaskDuration+' ms');
    }
    await measure('cold-authenticated-open','overview',async()=>{await page.goto(config.origin+'/',{waitUntil:'domcontentloaded',timeout:config.timeoutMs});await settled();},config.dwellMs,true);
    for(const view of ['autopilot','services','nodes','engines','devices','activity','settings'])await measure('enter-'+view,view,()=>navigate(view));
    await measure('return-home-hidden-sections','overview',()=>navigate('overview'),config.idleMs);
    await measure('rapid-tabs-return-home','overview',async()=>{
      // The production navigation controller is exercised in one event turn.
      await page.evaluate(()=>{for(const view of ['engines','nodes','settings','services','devices','overview'])setView(view);});await settled();
    });
    await measure('return-nodes','nodes',()=>navigate('nodes'),config.idleMs);
    await measure('mobile-nodes','nodes',async()=>{await page.setViewportSize({width:390,height:844});await settled();});
    await measure('mobile-engines','engines',async()=>{await page.evaluate(()=>setView('engines'));await settled();});
    await page.setViewportSize({width:1280,height:900});await navigate('overview');
    await measure('explicit-readback-home','overview',async()=>{await page.locator('#refreshAll').click();await settled();});
    // Headless Chromium may leave both tabs visible. Report that limitation,
    // instead of simulating visibility with document.hidden overrides.
    const cover=await context.newPage();await cover.goto('about:blank');await cover.bringToFront();
    const visibility=await page.evaluate(()=>document.visibilityState);
    if(visibility==='hidden')await measure('background-home','overview',async()=>{},config.idleMs);
    else report.scenarios.push({name:'background-home',skipped:true,reason:'Chromium did not expose a hidden document',observed_visibility:visibility});
    await cover.close();await page.bringToFront();
    if(visibility==='hidden')await measure('foreground-return-home','overview',settled);
    stage='fixture-inspection';
    // Explicit read-only inspection is separate from measured UI requests.
    const read=async path=>{const response=await context.request.get(config.origin+path,{timeout:config.timeoutMs});report.fixture.requests||=[];report.fixture.requests.push({method:'GET',path:path.split('?')[0],status:response.status()});assert.equal(response.status(),200,'Fixture inspection unavailable');return response.json();};
    const nodes=await read('/api/v1/nodes'),services=await read('/api/v1/services'),devices=await read('/api/v1/devices?view=status');
    const list=(value,key)=>{assert(Object.hasOwn(value,key)&&(value[key]===null||Array.isArray(value[key])),'Incomplete fixture metadata');return value[key]||[];};
    assert(Array.isArray(services),'Incomplete service metadata');
    const deviceList=Array.isArray(devices)?devices:list(devices,'devices');
    report.fixture.counts={nodes:list(nodes,'nodes').length,groups:list(nodes,'groups').length,catalog_services:services.length,
      enabled_services:services.filter(service=>service.enabled===true).length,applied_services:services.filter(service=>service.applied_enabled===true).length,devices:deviceList.length,
      discovered_devices:deviceList.filter(device=>device.discovered===true).length,not_discovered_devices:deviceList.filter(device=>device.discovered===false).length,
      discovery_unknown_devices:deviceList.filter(device=>typeof device.discovered!=='boolean').length,
      device_policy_assignments:deviceList.every(device=>Object.hasOwn(device,'policies')&&(device.policies===null||Array.isArray(device.policies)))?deviceList.reduce((sum,device)=>sum+(device.policies?.length||0),0):null};
    report.fixture.verified=fixtureMatches(config.profile,report.fixture.counts);
    assert(report.fixture.verified,'Declared empty/loaded fixture does not match observed data');
    guard();assert.equal(report.browser_errors.length,0,'Uncaught browser error during measurements');
  }catch(error){report.failure={stage,name:error.name,code:error.code||null};throw error;}
  finally{if(browser)await browser.close();report.finished_at=new Date().toISOString();save();console.log('Measurement artifacts: '+directory);}
}

const invoked=process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url);
if(invoked){
  if(process.argv.includes('--help'))console.log('Set RAZVILKA_PERF_URL, PROFILE=empty|loaded, CHROME, and SESSION or USERNAME/PASSWORD. Optional DWELL_MS, IDLE_MS, TIMEOUT_MS, OUTPUT use the same RAZVILKA_PERF_ prefix. See UI_RU.md for boundaries.');
  else try{await run(settings(process.env));}catch(error){console.error('Measurement stopped: '+error.name);process.exitCode=1;}
}
