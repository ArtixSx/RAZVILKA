import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../cmd/razvilka/web/app.js',import.meta.url),'utf8');
const extract=name=>{const match=source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));assert(match,name);return match[0]};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}};
const rows=()=>({connections:[{id:'private'}],active:1,live:true});
const streams=[],elements=new Map();let renders=0,handler;
class Stream{constructor(){streams.push(this)}addEventListener(name,fn){this[name]=fn}close(){this.closed=true}}
const ctx={state:{authenticated:true,connections:{connections:[]}},connectionObservation:{epoch:0,request:0},window:{EventSource:Stream},EventSource:Stream,
 api:()=>handler(),renderConnections(){renders++},$:id=>{if(!elements.has(id))elements.set(id,{textContent:''});return elements.get(id)},showAuth(){ctx.clearConnectionObservation()}};
vm.createContext(ctx);vm.runInContext(['clearConnectionObservation','refreshConnections','startConnectionStream'].map(extract).join('\n'),ctx);
assert.match(source,/addEventListener\('razvilka:auth-required', clearConnectionObservation\)/);
let late=deferred();handler=()=>late.promise;
const pending=ctx.refreshConnections();ctx.startConnectionStream();const old=streams[0];
ctx.clearConnectionObservation();assert(old.closed);assert.equal(ctx.state.connections.connections.length,0);
ctx.state.authenticated=true;ctx.startConnectionStream();const fresh=streams[1];
late.resolve(rows());await pending;assert.equal(ctx.state.connections.connections.length,0,'late REST crossed login');
old.connections({data:JSON.stringify(rows())});old.onerror();assert.equal(ctx.state.connections.connections.length,0,'old SSE crossed login');
fresh.connections({data:JSON.stringify(rows())});assert.equal(ctx.state.connections.connections.length,1);
ctx.clearConnectionObservation();assert.equal(ctx.state.connections.connections.length,0);
const before=streams.length;ctx.startConnectionStream();assert.equal(streams.length,before,'anonymous stream started');
ctx.state.authenticated=true;const first=deferred(),second=deferred();handler=()=>first.promise;const one=ctx.refreshConnections();handler=()=>second.promise;const two=ctx.refreshConnections();
second.resolve({connections:[{id:'newer'}]});await two;first.resolve(rows());await one;
assert.equal(ctx.state.connections.connections[0].id,'newer','out-of-order REST replaced newer observation');
handler=()=>Promise.reject(Object.assign(new Error('expired'),{status:401}));await ctx.refreshConnections();assert.equal(ctx.state.authenticated,false);assert.equal(ctx.state.connections.connections.length,0);
console.log('PASS connection session lifecycle: logout, late REST/SSE, re-login, ordering, 401');
