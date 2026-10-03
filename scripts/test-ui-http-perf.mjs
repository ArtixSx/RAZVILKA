import assert from 'node:assert/strict';
import {settings,readOnlyDecision,requestSummary,metricDelta,fixtureMatches} from './measure-ui-http-browser.mjs';
const origin='http://127.0.0.1:18851',env={RAZVILKA_PERF_URL:origin,RAZVILKA_PERF_PROFILE:'empty',RAZVILKA_PERF_CHROME:'browser',RAZVILKA_PERF_SESSION:'session.json'};
let passed=0;function test(name,action){action();passed++;console.log('PASS '+name);}
test('mutation fence applies even to login, probes, Stop, recovery and Apply',()=>{
  for(const path of ['/api/v1/auth/login','/api/v1/node-checks','/api/v1/components/recovery','/api/v1/engine-configs/xray/apply','/api/v1/service-control/current'])
    for(const method of ['POST','PUT','PATCH','DELETE'])assert.equal(readOnlyDecision(origin,origin+path,method),'mutation-blocked');
});
test('same-origin reads only, forced refresh and foreign origins blocked',()=>{
  assert.equal(readOnlyDecision(origin,origin+'/api/v1/components/recovery','GET'),'read');
  assert.equal(readOnlyDecision(origin,origin+'/api/v1/update?refresh=true','GET'),'forced-read-blocked');
  assert.equal(readOnlyDecision(origin,origin+'/api/v1/status?force=true','GET'),'forced-read-blocked');
  assert.equal(readOnlyDecision(origin,'http://127.0.0.1:18852/api/v1/status','GET'),'external-blocked');
  assert.equal(readOnlyDecision(origin,'https://untrusted.invalid/','GET'),'external-blocked');
});
test('credential URL, ambiguous auth and unspecified fixture rejected',()=>{
  for(const changed of [{RAZVILKA_PERF_URL:'http://secret:password@localhost/'},{RAZVILKA_PERF_URL:origin+'/?token=secret'},
    {RAZVILKA_PERF_PROFILE:''},{RAZVILKA_PERF_SESSION:''},{RAZVILKA_PERF_USERNAME:'admin',RAZVILKA_PERF_PASSWORD:'secret'},{RAZVILKA_PERF_IDLE_MS:'0'}])assert.throws(()=>settings({...env,...changed}));
  assert.equal(settings({...env,RAZVILKA_PERF_SESSION:'',RAZVILKA_PERF_USERNAME:'admin',RAZVILKA_PERF_PASSWORD:'secret'}).session,null);
});
test('pending streams, aborted writes and cross-view API paths counted distinctly',()=>{
  const result=requestSummary([{method:'GET',path:'/api/v1/status',api:true,status:200,finished:true},{method:'GET',path:'/api/v1/connections/stream',api:true,resource_type:'eventsource',status:200},
    {method:'POST',path:'/api/v1/node-checks',api:true,blocked:'mutation-blocked'},{method:'GET',path:'/api/v1/nodes',api:true,status:null,finished:true,failed:true}],['/api/v1/status','/api/v1/connections/stream']);
  assert.equal(result.attempts,4);assert.equal(result.forwarded,3);assert.equal(result.streams,1);assert.equal(result.unfinished_non_stream,0);
  assert.equal(result.statuses.blocked,1);assert.equal(result.statuses.failed,1);assert.equal(result.other_api_paths['GET /api/v1/nodes'],1);
});
test('headed visibility measurement is explicit opt-in and defaults to headless',()=>{
  assert.equal(settings(env).headed,false);assert.equal(settings({...env,RAZVILKA_PERF_HEADED:'0'}).headed,false);
  assert.equal(settings({...env,RAZVILKA_PERF_HEADED:'1'}).headed,true);
  for(const value of ['true','yes','2',''])assert.throws(()=>settings({...env,RAZVILKA_PERF_HEADED:value}));
});
test('renderer reset and missing metrics stay unavailable',()=>{
  const result=metricDelta({TaskDuration:3,ScriptDuration:1,LayoutCount:2},{TaskDuration:2,ScriptDuration:1.2,LayoutCount:5,Nodes:123});
  assert.equal(result.duration_ms.TaskDuration,null);assert.equal(result.duration_ms.ScriptDuration,200);assert.equal(result.duration_ms.LayoutDuration,null);
  assert.equal(result.counts.LayoutCount,3);assert.equal(result.end.Nodes,123);assert.equal(result.end.JSHeapUsedSize,null);
});
test('stock catalog is not a loaded fixture and unread metadata is not empty',()=>{
  const empty={nodes:0,groups:0,catalog_services:9,enabled_services:0,applied_services:0,devices:0};
  assert(fixtureMatches('empty',empty));assert(!fixtureMatches('loaded',empty));assert(!fixtureMatches('empty',null));assert(!fixtureMatches('empty',{...empty,nodes:null}));
  assert(fixtureMatches('loaded',{...empty,nodes:83}));assert(!fixtureMatches('empty',{...empty,enabled_services:1}));
});
test('LAN discovery and device policies are observations outside the user library',()=>{
  const discovered={nodes:0,groups:0,catalog_services:6,enabled_services:0,applied_services:0,devices:12,discovered_devices:12,device_policy_assignments:0};
  assert(fixtureMatches('empty',discovered));assert(!fixtureMatches('loaded',discovered));
  assert(fixtureMatches('empty',{...discovered,device_policy_assignments:3,discovery_unknown_devices:2}));
  assert(fixtureMatches('loaded',{...discovered,nodes:4}));assert(!fixtureMatches('empty',{...discovered,nodes:4}));
});
console.log(JSON.stringify({suite:'ui-http-perf-boundaries',passed}));
