import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(process.argv[2]||'cmd/razvilka/web/node-browser.js','utf8');
const start=source.indexOf('// BEGIN NODE MEASUREMENT MODEL'),end=source.indexOf('// END NODE MEASUREMENT MODEL');
assert.ok(start>=0&&end>start,'actual browser must load the measurement model');
const context=vm.createContext({Date,Promise,Object,Number,Array,Infinity});
vm.runInContext(source.slice(start,end)+'\nglobalThis.model=nodeMeasurementModel;',context);
const m=context.model,now=Date.now(),at=new Date(now-1000).toISOString(),expires=new Date(now+60000).toISOString();
const check={probe_id:'p-one',service_id:'telegram',network_profile:'wan-one',route_path_id:'sing-box:node-a',checked_at:at,expires_at:expires,verdict:'PASS',test_level:'service',state:'available',latency_ms:9500};
const node={id:'node-a',state:'available',health:{history:[check]}};
const metric={version:1,node_id:node.id,service_id:'telegram',network_profile:'wan-one',route_path_id:check.route_path_id,probe_id:check.probe_id,checked_at:at,expires_at:expires,tcp_connect_ms:0,proxy_response_ms:75,total_check_ms:9500};
let passed=0;function test(name,fn){fn();console.log('PASS',name);passed++;}
function get(n=node,r=metric){return m.measurement(n,'telegram','wan-one',[r],now)}
test('real response is not total check duration',()=>{assert.equal(get().proxy_response_ms,75);assert.equal(get().total_check_ms,9500)});
test('zero is measured <1ms; missing is not fake zero',()=>{assert.equal(m.label(0),'<1 мс');assert.equal(m.label(null),'—');assert.equal(m.label(undefined),'—')});
test('legacy-only history never fabricates response ping',()=>assert.equal(m.measurement(node,'telegram','wan-one',[],now),null));
test('wrong service',()=>assert.equal(get(node,{...metric,service_id:'youtube'}),null));
test('wrong network',()=>assert.equal(get(node,{...metric,network_profile:'wan-two'}),null));
test('wrong executor',()=>assert.equal(get(node,{...metric,route_path_id:'xray:node-a'}),null));
test('wrong exact check',()=>assert.equal(get(node,{...metric,probe_id:'another'}),null));
test('expired measurement',()=>assert.equal(get(node,{...metric,expires_at:new Date(now).toISOString()}),null));
test('future measurement',()=>assert.equal(get(node,{...metric,checked_at:new Date(now+5000).toISOString()}),null));
test('no extension of proof expiry',()=>assert.equal(get(node,{...metric,expires_at:new Date(now+120000).toISOString()}),null));
test('newer check invalidates old timing',()=>assert.equal(get({...node,health:{history:[{...check,probe_id:'p-new',checked_at:new Date(now-500).toISOString()},check]}}),null));
test('disabled node',()=>assert.equal(get({...node,disabled:true}),null));
test('expired node',()=>assert.equal(get({...node,state:'expired'}),null));
test('failed check does not show positive proxy latency',()=>assert.equal(get({...node,health:{history:[{...check,verdict:'ERROR',state:'unavailable'}]}}).proxy_response_ms,null));
test('direct leak does not show positive proxy latency',()=>assert.equal(get({...node,health:{history:[{...check,direct_leak:true}]}}).proxy_response_ms,null));
test('malformed metric numbers rejected',()=>{for(const n of ['75',-1,Infinity,NaN,600001,1.1])assert.equal(get(node,{...metric,proxy_response_ms:n}).proxy_response_ms,null)});
test('TCP result available from automatic service check',()=>{const tcp=m.tcp(node.id,'wan-one',[],get(),now);assert.equal(tcp.reachable,true);assert.equal(tcp.latency_ms,0)});
test('newer explicit negative TCP beats old success',()=>{const p={node_id:node.id,network_profile:'wan-one',checked_at:new Date(now-100).toISOString(),reachable:false};assert.equal(m.tcp(node.id,'wan-one',[p],get(),now).reachable,false)});
test('expired separate ping is not shown',()=>{const p={node_id:node.id,network_profile:'wan-one',checked_at:new Date(now-600001).toISOString(),reachable:true,latency_ms:2};assert.equal(m.tcp(node.id,'wan-one',[p],null,now),null)});
test('metric helpers do not mutate input',()=>{const before=JSON.stringify([node,metric]);get();assert.equal(JSON.stringify([node,metric]),before)});
async function asyncTest(name,fn){await fn();console.log('PASS',name);passed++;}
await asyncTest('secondary API error does not discard node checks',async()=>{const r=await m.readStatus(async path=>{if(path.includes('autofallback'))throw new Error('busy');return {pings:[1],node_measurements:[2]}});assert.equal(r.response.pings[0],1);assert.equal(r.partial,true);assert.equal(r.fallback,null)});
await asyncTest('auth error in either reader still logs out',async()=>{for(const failing of ['current','autofallback'])await assert.rejects(m.readStatus(async path=>{if(path.includes(failing)){const e=new Error('auth');e.status=401;throw e;}return {}}),/auth/)});
await asyncTest('primary API error is not hidden by fallback success',async()=>await assert.rejects(m.readStatus(async path=>{if(path.endsWith('current'))throw new Error('primary');return {active:false}}),/primary/));
console.log(`Node measurement UI: ${passed} cases passed`);
