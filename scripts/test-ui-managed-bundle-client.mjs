// Pure runner admission, request boundary, trace ordering and public projection
// checks. These fixtures never reach HTTP and do not mock the genuine runner's
// producer, managed plan, browser, source or original instance identity.
import assert from 'node:assert/strict';
import {managedUISettings,managedBrowserDecision,managedPublicPath,managedPublicCode,managedTraceFacts,managedUnreviewedPlan,managedSourceAbsent,managedReadSequence} from './test-ui-managed-bundle-browser.mjs';
import {realHTTPFailure} from './test-ui-real-http-browser.mjs';
const env={RAZVILKA_QA_UI_FIXTURE:'disposable-linux',RAZVILKA_QA_UI_URL:'http://127.0.0.1:19001/',RAZVILKA_QA_UI_INSTANCE:'a'.repeat(32),RAZVILKA_QA_UI_CHROME:'installed-chrome',RAZVILKA_QA_UI_SESSION:'private-session.json'};
const origin='http://127.0.0.1:19001',base='/api/v1/components/nfqws2/managed-bundle',flag='--managed-bundle-amd64-read-only';
let checks=0;const check=(name,action)=>{action();checks++;console.log('PASS '+name);};
const reject=(action,code)=>{try{action();assert.fail('expected refusal');}catch(error){assert.equal(realHTTPFailure(error,'admission').code,code);}};
check('dedicated read-only opt-in retains original settings',()=>{const value=managedUISettings(env,[flag]);assert.equal(value.managedAMD64ReadOnly,true);assert.equal(value.setupAccount,false);assert.equal(value.preparePolicy,false);assert.equal(value.draftMutations,false);});
for(const args of [[],[flag,flag],[flag,'--setup-account'],[flag,'--draft-mutations'],[flag,'--prepare-policy'],['--unbounded']])check('missing or broadened flags refused '+checks,()=>reject(()=>managedUISettings(env,args),'MANAGED_READ_ONLY_OPT_IN_REQUIRED'));
for(const [change,code] of [
  [{RAZVILKA_QA_UI_FIXTURE:'router'},'QA_FIXTURE_REQUIRED'],[{RAZVILKA_QA_UI_INSTANCE:''},'QA_INSTANCE_REQUIRED'],
  [{RAZVILKA_QA_UI_URL:origin+'/private?token=PRIVATE'},'INVALID_QA_ORIGIN'],[{RAZVILKA_QA_UI_CHROME:''},'CHROME_REQUIRED'],
  [{RAZVILKA_QA_UI_SESSION:'',RAZVILKA_QA_UI_USERNAME:'user'},'QA_AUTH_REQUIRED'],[{RAZVILKA_QA_UI_SETUP_TOKEN:'private-token-file'},'QA_SETUP_TOKEN_REQUIRED']
])check('original instance and private auth guard '+code,()=>reject(()=>managedUISettings({...env,...change},[flag]),code));
check('original credential login mode remains available',()=>{const value=managedUISettings({...env,RAZVILKA_QA_UI_SESSION:'',RAZVILKA_QA_UI_USERNAME:'private-user',RAZVILKA_QA_UI_PASSWORD:'private-password'},[flag]);assert.equal(value.setupAccount,false);assert.equal(value.session,null);});
for(const path of [base+'/plan',base+'/installed','/api/v1/status','/api/v1/components/recovery','/api/v1/networkpolicy/review','/managed-nfq-bundle-ui.js?v=0.19.3'])check('declared same-origin GET '+path,()=>assert.equal(managedBrowserDecision(origin,origin+path,'GET'),null));
for(const [path,method] of [[base+'/install','POST'],[base+'/plan','POST'],[base+'/installed','PUT'],['/api/v1/components/nfqws2/recovery','POST'],['/api/v1/auth/login','POST'],['/api/v1/apply','POST'],['/api/v1/autonomy','PUT'],['/api/v1/networkpolicy/review','POST'],['/api/v1/auth/setup','POST']])check('no browser writer '+method+' '+path,()=>assert(managedBrowserDecision(origin,origin+path,method)));
for(const url of [origin+base+'/plan?refresh=true',origin+base+'/installed?source=PRIVATE',origin+base+'/install',origin+'/api/v1/components?refresh=true',origin+'/api/v1/diagnostics/domain?q=PRIVATE','https://private.invalid'+base+'/plan'])check('unknown queries/native/foreign reads refused '+checks,()=>assert(managedBrowserDecision(origin,url,'GET')));
const plan=()=>({revision:0,ready:false,code:'MANAGED_NFQWS_PLATFORM_UNREVIEWED',reason:'Для этой платформы ещё нет проверенного пакета управляемого NFQWS2.',installed_idle:false,compatibility_ready:false,working_routes_changed:false});
check('unreviewed actual producer shape includes config revision zero',()=>managedUnreviewedPlan(plan(),0));
for(const change of [{revision:1},{ready:true},{bundle:null},{bundle:{architecture:'arm64'}},{installed_idle:true},{compatibility_ready:true},{working_routes_changed:true},{reason:'PRIVATE substitute'},{code:'MANAGED_NFQWS_INSTALL_READY'}])check('contradictory AMD64 plan is refused '+Object.keys(change)[0],()=>reject(()=>managedUnreviewedPlan({...plan(),...change},0),'AMD64_UNREVIEWED_PLAN_REQUIRED'));
const absent={code:'MANAGED_NFQWS_SOURCE_UNAVAILABLE',installed_idle:false,working_routes_changed:false};
check('independent unavailable installed response is accepted as absence',()=>managedSourceAbsent(absent));
for(const change of [{code:'PRIVATE error'},{installed_idle:true},{working_routes_changed:true}])check('installed response cannot become positive '+Object.keys(change)[0],()=>reject(()=>managedSourceAbsent({...absent,...change}),'MANAGED_SOURCE_ABSENT_REQUIRED'));
const sequence=()=>[base+'/plan',base+'/installed','/api/v1/status'].map((path,index)=>({path,method:'GET',status:[200,503,200][index],start:index*2+1,finished:index*2+2,failed:false,managed_caller:true}));
check('completed genuine caller order is exported as bounded public facts',()=>{const value=managedReadSequence(sequence());assert.equal(value.sequential,true);assert.equal(value.reads.length,3);assert.deepEqual(Object.keys(value.reads[0]),['method','path','status','started_event','finished_event','managed_caller']);});
check('unrelated background status does not replace or disturb caller order',()=>{const rows=sequence();rows.splice(1,0,{path:'/api/v1/status',method:'GET',start:2,finished:8,status:200,managed_caller:false});assert.equal(managedReadSequence(rows).sequential,true);});
for(const mutate of [rows=>rows[1].start=1,rows=>rows[2].start=4,rows=>rows[0].finished=null,rows=>rows[1].failed=true,rows=>rows[1].status=200,rows=>rows[2].method='POST',rows=>rows[0].start=-1,rows=>rows[2].path=base+'/plan'])check('overlap/incomplete/changed actual caller trace refused '+checks,()=>{const rows=sequence();mutate(rows);reject(()=>managedReadSequence(rows),'MANAGED_READS_NOT_SEQUENTIAL');});
for(const mutate of [rows=>rows.pop(),rows=>rows.push({...rows[0]}),rows=>rows[2].managed_caller=false])check('missing/repeated/unattributed caller request refused '+checks,()=>{const rows=sequence();mutate(rows);reject(()=>managedReadSequence(rows),'MANAGED_CALLER_READ_COUNT');});
check('public path and code never contain private URLs, query or arbitrary DTO text',()=>{
  assert.equal(managedPublicPath(origin,origin+base+'/plan?token=PRIVATE'),base+'/plan');
  assert.equal(managedPublicPath(origin,origin+'/api/v1/private/PRIVATE?secret=PRIVATE'),'/api/unknown');
  assert.equal(managedPublicPath(origin,'https://private.invalid/PRIVATE'),'foreign');
  assert.equal(managedPublicCode('PRIVATE secret'),'UNKNOWN_TYPED_CODE');assert.equal(managedPublicCode(absent.code),absent.code);
});
check('private exceptions remain outside public failure report',()=>{
  const value=realHTTPFailure(new Error('PRIVATE credentials source path'), 'verify-private-amd64-fixture');
  assert.deepEqual(value,{stage:'verify-private-amd64-fixture',status:'failed',code:'CLIENT_FAILED'});assert(!JSON.stringify(value).includes('PRIVATE'));
});
check('failed trace projection has no private initiator, request ID, URL, headers or error',()=>{
  const value=managedTraceFacts({method:'PRIVATE',path:'/PRIVATE',status:'PRIVATE',start:-1,finished:null,failed:true,managed_caller:false,
    requestId:'PRIVATE',url:'https://PRIVATE.invalid',headers:{authorization:'PRIVATE'},initiator:{stack:'PRIVATE'},error:'PRIVATE'});
  assert.deepEqual(value,{method:'OTHER',path:'/api/unknown',status:null,started_event:null,finished_event:null,failed:true,managed_caller:false});
  assert(!JSON.stringify(value).includes('PRIVATE'));
});
console.log(JSON.stringify({suite:'managed-amd64-client-admission',mode:'pure-no-http',passed:checks}));
