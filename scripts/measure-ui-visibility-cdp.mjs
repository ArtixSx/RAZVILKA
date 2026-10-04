// Opt-in against an existing isolated HTTP fixture. Never starts or seeds it.
// Use the same RAZVILKA_PERF_URL/CHROME/PROFILE and SESSION or USERNAME/PASSWORD
// environment as measure-ui-http-browser.mjs. The sole POST is login before
// observations. A fresh, owned Chrome profile uses raw CDP, no Playwright browser
// connection, focus emulation, visibility overrides or frozen lifecycle state.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdirSync,mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {settings,readOnlyDecision} from './measure-ui-http-browser.mjs';

const checks=Object.freeze({chrome_start:'Owned Chrome did not expose CDP',cdp:'Owned CDP command failed',
  authentication:'Fixture authentication failed',readiness:'UI did not become ready',
  initial_visible:'Initial document did not become visible',hidden:'Minimized document did not become hidden',
  hidden_changed:'Document did not remain hidden',hidden_reads:'UI issued background API reads',
  resumed_visible:'Restored document did not become visible',resume_reads:'No completed fresh service-control read after restore',
  boundary:'Page attempted an action outside the read-only boundary',browser_error:'Browser reported an uncaught exception'});
const ownedErrors=new WeakMap();
function check(condition,code){if(condition)return;const error=new Error(checks[code]);ownedErrors.set(error,code);throw error;}
const views=new Set(['overview','autopilot','services','nodes','providers','subscription-settings','engines','engineconfig','devices','exclusions','activity','settings','dns','strategylab','testlab','diagnostics','onboard','managed','updates','connections','sources']);
export function visibilitySettings(env){
  const config=settings(env);
  // A full workspace observer interval is 15s. Shorter samples are not proof.
  check(config.idleMs>=16000,'hidden');
  return config;
}
export function ownedProfilePath(directory,profile){
  const base=resolve(directory),target=resolve(profile);
  return target===join(base,'chrome-profile')&&target.startsWith(base+sep);
}

async function run(config){
  const base=config.output||join(fileURLToPath(new URL('../',import.meta.url)),'.review-local');
  mkdirSync(base,{recursive:true});const directory=mkdtempSync(join(base,'ui-visibility-cdp-'));
  writeFileSync(join(directory,'.gitignore'),'*\n');const profile=join(directory,'chrome-profile');mkdirSync(profile);
  const report={schema:1,started_at:new Date().toISOString(),origin:config.origin,declared_fixture:config.profile,
    boundaries:{server:'existing isolated HTTP fixture',browser:'owned standalone Chrome; raw CDP only',native_acceptance:false,
      content:'no response/request bodies, headers, cookies, query strings, profiles, DOM text or screenshots saved',
      emulation:false,lifecycle_overrides:false},configuration:{hidden_ms:config.idleMs,resume_timeout_ms:config.timeoutMs},
    authentication:{mode:config.session?'existing-session':'env-login',requests:[]},observations:[],requests:[],blocked:[],
    browser_errors:[],hidden_api_requests:null,resume_fresh_reads:[],cycle_confirmed:false,failure:null};
  let stage='authentication',chrome,socket,client,call;
  const save=()=>writeFileSync(join(directory,'result.json'),JSON.stringify(report,null,2));
  try{
    let cookies;
    if(config.session)cookies=JSON.parse(readFileSync(config.session,'utf8')).cookies;
    else{
      const {request}=createRequire(import.meta.url)('playwright');
      client=await request.newContext({baseURL:config.origin});
      const response=await client.post('/api/v1/auth/login',{data:{username:config.username,password:config.password},timeout:config.timeoutMs});
      report.authentication.requests.push({method:'POST',path:'/api/v1/auth/login',status:response.status()});
      check(response.status()===200,'authentication');cookies=(await client.storageState()).cookies;
    }
    const host=new URL(config.origin).hostname;
    check(Array.isArray(cookies),'authentication');
    cookies=cookies.filter(cookie=>cookie.domain?.replace(/^\./,'')===host).map(cookie=>({name:cookie.name,value:cookie.value,domain:cookie.domain,
      path:cookie.path,secure:cookie.secure,httpOnly:cookie.httpOnly,sameSite:cookie.sameSite,...(cookie.expires>0?{expires:cookie.expires}:{})}));
    check(cookies.length>0,'authentication');
    stage='chrome-start';
    chrome=spawn(config.chrome,['--remote-debugging-port=0','--user-data-dir='+profile,'--no-first-run','--no-default-browser-check',
      '--disable-background-networking','--new-window','about:blank'],{windowsHide:false,stdio:'ignore'});
    chrome.on('error',()=>{});
    let address;
    for(let i=0;i<100;i++){
      try{const [port,path]=readFileSync(join(profile,'DevToolsActivePort'),'utf8').trim().split(/\r?\n/);address='ws://127.0.0.1:'+port+path;break;}catch{}
      if(chrome.exitCode!==null)break;await delay(100);
    }
    check(address,'chrome_start');socket=new WebSocket(address);
    await new Promise((done,fail)=>{const timer=setTimeout(()=>fail(new Error()),5000);socket.addEventListener('open',()=>{clearTimeout(timer);done();},{once:true});socket.addEventListener('error',()=>{clearTimeout(timer);fail(new Error());},{once:true});});
    let next=0;const pending=new Map(),listeners=new Set();
    socket.addEventListener('message',event=>{
      const message=JSON.parse(event.data);
      if(message.id){const ticket=pending.get(message.id);if(ticket){pending.delete(message.id);message.error?ticket.reject():ticket.resolve(message.result);}}
      else for(const listener of listeners)listener(message);
    });
    call=(method,params={},sessionId)=>new Promise((done,fail)=>{
      const id=++next,timer=setTimeout(()=>{pending.delete(id);try{check(false,'cdp');}catch(error){fail(error);}},5000);
      pending.set(id,{resolve:value=>{clearTimeout(timer);done(value);},reject:()=>{clearTimeout(timer);try{check(false,'cdp');}catch(error){fail(error);}}});
      socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
    });
    report.browser=(await call('Browser.getVersion')).product;
    // Use the page in the window created by this exact Chrome process. Creating
    // a second window during startup can race native window activation.
    const targets=(await call('Target.getTargets')).targetInfos.filter(item=>item.type==='page'&&item.url==='about:blank');
    check(targets.length===1,'chrome_start');const target=targets[0].targetId;
    const session=(await call('Target.attachToTarget',{targetId:target,flatten:true})).sessionId;
    const window=await call('Browser.getWindowForTarget',{targetId:target});
    const targetInfo=(await call('Target.getTargetInfo',{targetId:target})).targetInfo;
    const contexts=(await call('Target.getBrowserContexts')).browserContextIds;
    report.target={target_id:target,window_id:window.windowId,page:true,default_context:!contexts.includes(targetInfo.browserContextId),
      explicit_context_count:contexts.length,owned_window:true};
    const network=new Map();
    listeners.add(message=>{
      if(message.sessionId!==session)return;
      if(message.method==='Runtime.exceptionThrown')report.browser_errors.push({stage,kind:'uncaught-exception'});
      if(message.method==='Fetch.requestPaused'){
        const {request,requestId,networkId}=message.params,decision=readOnlyDecision(config.origin,request.url,request.method);
        const record={stage,method:request.method,path:new URL(request.url).pathname,api:new URL(request.url).pathname.startsWith('/api/'),status:null,finished:false};
        report.requests.push(record);if(networkId)network.set(networkId,record);
        if(decision!=='read'){record.blocked=true;report.blocked.push({stage,method:request.method,path:record.path,reason:decision});}
        void call(decision==='read'?'Fetch.continueRequest':'Fetch.failRequest',decision==='read'?{requestId}:{requestId,errorReason:'BlockedByClient'},session).catch(()=>{});
      }
      if(message.method==='Network.responseReceived'){const record=network.get(message.params.requestId);if(record)record.status=message.params.response.status;}
      if(['Network.loadingFinished','Network.loadingFailed'].includes(message.method)){const record=network.get(message.params.requestId);if(record){record.finished=true;if(message.method==='Network.loadingFailed')record.failed=true;}}
    });
    await call('Network.enable',{},session);await call('Network.setCookies',{cookies},session);cookies=null;
    await call('Page.enable',{},session);await call('Runtime.enable',{},session);
    await call('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},session);
    await call('Page.addScriptToEvaluateOnNewDocument',{source:"window.__razvilkaVisibilityCDP=[];document.addEventListener('visibilitychange',()=>{window.__razvilkaVisibilityCDP.push({state:document.visibilityState,at_ms:performance.now()});if(window.__razvilkaVisibilityCDP.length>128)window.__razvilkaVisibilityCDP.shift();});"},session);
    const evaluate=async expression=>{const value=await call('Runtime.evaluate',{expression,returnByValue:true},session);check(!value.exceptionDetails,'readiness');return value.result.value;};
    const state=()=>evaluate("({visibility:document.visibilityState,hidden:document.hidden,focused:document.hasFocus(),ready:typeof state!=='undefined'&&state.authenticated&&typeof panelLoad!=='undefined'&&!panelLoad.request,view:typeof state!=='undefined'?state.currentView:'unknown'})");
    const observe=async name=>{
      const value=await state();value.view=views.has(value.view)?value.view:'unknown';
      const row={name,window:(await call('Browser.getWindowBounds',{windowId:window.windowId})).bounds.windowState,...value};report.observations.push(row);return row;
    };
    const until=async (predicate,timeout,code)=>{const deadline=Date.now()+timeout;do{if(await predicate())return;await delay(200);}while(Date.now()<deadline);check(false,code);};
    stage='initial-visible';await call('Page.navigate',{url:config.origin},session);await call('Page.bringToFront',{},session);
    await until(async()=>Boolean((await state()).ready),config.timeoutMs,'readiness');
    await until(async()=>(await state()).visibility==='visible',5000,'initial_visible');
    await until(async()=>report.requests.every(row=>row.finished||row.blocked),5000,'readiness');await delay(config.dwellMs);await observe('initial-visible');
    stage='hide';await call('Browser.setWindowBounds',{windowId:window.windowId,bounds:{windowState:'minimized'}});
    await until(async()=>(await state()).hidden===true,5000,'hidden');await observe('minimized-hidden');
    stage='hidden-drain';await delay(1000);const mark=await evaluate('performance.now()');
    stage='hidden-idle';const start=report.requests.length;await delay(config.idleMs);const hidden=await observe('hidden-after-idle');
    const visibility=await evaluate('window.__razvilkaVisibilityCDP');
    report.visibility_transitions=visibility.map(row=>({state:['visible','hidden'].includes(row.state)?row.state:'unknown',at_ms:Math.round(row.at_ms)}));
    report.hidden_api_requests=report.requests.slice(start).filter(row=>row.api).length;
    check(hidden.hidden&&Array.isArray(visibility)&&!visibility.some(row=>row.at_ms>=mark&&row.state!=='hidden'),'hidden_changed');
    check(report.hidden_api_requests===0,'hidden_reads');
    stage='restore';const resume=report.requests.length;
    await call('Browser.setWindowBounds',{windowId:window.windowId,bounds:{windowState:'normal'}});await call('Page.bringToFront',{},session);
    await until(async()=>(await state()).visibility==='visible',5000,'resumed_visible');await observe('restored-visible');
    await until(async()=>report.requests.slice(resume).some(row=>row.path==='/api/v1/service-control'&&row.method==='GET'&&row.status===200&&row.finished&&!row.failed),config.timeoutMs,'resume_reads');
    await delay(config.dwellMs);const final=await observe('resume-fresh-reads');check(final.visibility==='visible','resumed_visible');
    report.resume_fresh_reads=report.requests.slice(resume).filter(row=>row.api&&row.finished&&row.status===200&&!row.failed).map(({method,path,status})=>({method,path,status}));
    report.visibility_transitions=(await evaluate('window.__razvilkaVisibilityCDP')).map(row=>({state:['visible','hidden'].includes(row.state)?row.state:'unknown',at_ms:Math.round(row.at_ms)}));
    check(report.blocked.length===0,'boundary');check(report.browser_errors.length===0,'browser_error');report.cycle_confirmed=true;
  }catch(error){const code=ownedErrors.get(error)||'unclassified';report.failure={stage,diagnostic_code:code,message:checks[code]||'Private exception details omitted'};process.exitCode=1;}
  finally{
    if(call&&socket?.readyState===WebSocket.OPEN)await call('Browser.close').catch(()=>{});socket?.close();
    if(chrome){if(chrome.exitCode===null)await Promise.race([new Promise(done=>chrome.once('exit',done)),delay(3000)]);if(chrome.exitCode===null)chrome.kill();}
    if(client)await client.dispose();
    assert(ownedProfilePath(directory,profile),'Owned profile path mismatch');
    try{rmSync(profile,{recursive:true,force:true,maxRetries:5,retryDelay:200});report.profile_cleaned=true;}catch{report.profile_cleaned=false;process.exitCode=1;}
    report.finished_at=new Date().toISOString();save();
    console.log(JSON.stringify({artifact:join(directory,'result.json'),cycle_confirmed:report.cycle_confirmed,hidden_api_requests:report.hidden_api_requests,
      fresh_read_count:report.resume_fresh_reads.length,failure:report.failure,profile_cleaned:report.profile_cleaned}));
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{await run(visibilitySettings(process.env));}catch{console.error('Supply the isolated-server RAZVILKA_PERF environment; private details omitted');process.exitCode=1;}
}
