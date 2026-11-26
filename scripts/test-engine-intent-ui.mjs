import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const names = ['captureEngineEditorContext', 'engineEditorContextCurrent', 'engineIntentCurrent', 'updateEngineEditorActions', 'markEngineEditorDirty', 'invalidateEngineEditorContext', 'beginEngineIntent', 'finishEngineIntent', 'cancelEngineIntent', 'handleEngineEditorLifecycle', 'saveEngineDraft', 'applyEngineConfig', 'applyDraft', 'planWithRetainedNodeCheck', 'retainedNodeDependency', 'checkRetainedNodeRoute', 'showRouteDependencyNotice', 'returnServiceToNFQWS2', 'validateEngineFile', 'loadEngineFile', 'loadEngineGuided', 'selectEngine', 'selectEngineFile', 'switchEngineMode', 'handleEngineImport', 'discardEngineConfigDraft', 'refreshEngineConfigs'];
const functions = names.map(name => {
  const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name); return match[0];
}).join('\n');
const elements = new Map();
let reviewClose;
const $ = id => {
  if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', hidden: true, disabled: false, open: false,
    close() { this.open = false; reviewClose?.(false); }, classList: { toggle() {} } });
  return elements.get(id);
};
const state = {};
const calls = [], messages = [];
let handler, staged, reviewHandler;
const configs = () => [{ id: 'sing-box', name: 'Sing-box', files: [{ id: 'main', staged, exists: true }] }, { id: 'usque', name: 'WARP', files: [{ id: 'main', staged: false }] }];
const selectedEngineView = () => state.engineConfigs.find(engine => engine.id === state.selectedEngine);
const selectedEngineFile = () => selectedEngineView()?.files.find(file => file.id === state.selectedEngineFile);
const preview = { review: { expected_revision: 12, reviewed_digest: 'bound-to-exact-stage-files' }, transaction: { digest: 'ordinary-digest-is-not-the-review', blockers: [] } };
const context = vm.createContext({ state, $, $$: selector => selector === '[data-guided-field]' ? [{ dataset: { guidedField: 'server' }, value: 'visible-server' }] : [],
  AbortController, Date, Number, JSON, Object, Promise, encodeURIComponent, selectedEngineView, selectedEngineFile, esc: String,
  api: async (url, options = {}) => { calls.push({ url, options }); return handler(url, options); },
  renderStatus() {}, renderEngineControl() {}, renderGuidedEditor() {}, switchEngineTab() {},
  refreshCoreAfterEdit: async () => {}, showPlan: async () => {}, needsApplyReview: () => true,
  reviewApplyPlan: async value => reviewHandler(value), askConfirmation: async () => true, fallbackLabels: {},
  showNotice: (...args) => messages.push(args), showDetails: (...args) => messages.push(args), hideNotice() {},
});
vm.runInContext(functions, context);
const normal = async (url, options) => {
  if (options.method === 'PUT') { staged = true; return { engine_id: 'sing-box', file_id: 'main', source: 'staged', content: 'saved' }; }
  if (url === '/api/v1/engine-configs') return configs();
  if (url === '/api/v1/status') return { revision: 12, routing_pending_changes: true };
  if (url.includes('/validate?')) return { engine_id: 'sing-box', file_id: 'main', ok: true };
  if (url.startsWith('/api/v1/plan?')) return preview;
  if (url.startsWith('/api/v1/apply?')) { staged = false; return { live_applied: true }; }
  throw new Error(`unexpected ${url}`);
};
const reset = () => {
  staged = false; calls.length = 0; messages.length = 0; elements.clear(); reviewClose = null;
  Object.assign(state, { selectedEngine: 'sing-box', selectedEngineFile: 'main', engineMode: 'expert', engineEditorDirty: false, engineEditorVersion: 0, engineEditorEpoch: 0, engineIntent: null, engineGuidedLoading: false, engineGuidedRequest: null, engineLoaded: null, engineGuided: null, engineConfigs: configs(), currentView: 'engineconfig', status: { revision: 12, routing_pending_changes: true } });
  $('#authScreen').hidden = true; $('#engineEditor').value = 'visible-original-config'; handler = normal; reviewHandler = async () => true;
  context.markEngineEditorDirty();
};
const appliedCalls = () => calls.filter(call => call.url.startsWith('/api/v1/apply?'));

reset();
assert.equal($('#engineApplyConfig').disabled, false, 'first edit requires a separate save before primary action');
await context.applyEngineConfig();
assert.equal(calls.filter(call => call.options.method === 'PUT').length, 1);
assert.deepEqual(JSON.parse(calls[0].options.body), { content: 'visible-original-config' });
assert.equal(appliedCalls().length, 1);
assert.equal(appliedCalls()[0].url, '/api/v1/apply?scope=engine&engine=sing-box', 'engine action broadened its ownership to generic Apply');
assert.deepEqual(JSON.parse(appliedCalls()[0].options.body), preview.review, 'apply omitted exact reviewed file/config guard');
assert.equal(state.engineIntent, null); assert.equal($('#engineApplyConfig').disabled, true);

for (const failAt of ['save', 'refresh', 'validation', 'identity', 'review-missing']) {
  reset(); staged = true; state.engineConfigs = configs();
  handler = async (url, options) => {
    if (failAt === 'save' && options.method === 'PUT') throw new Error('save refused');
    if (failAt === 'refresh' && url === '/api/v1/engine-configs') throw new Error('refresh failed after uncertain save');
    if (failAt === 'validation' && url.includes('/validate?')) return { engine_id: 'sing-box', file_id: 'main', ok: false, output: 'invalid settings' };
    if (failAt === 'identity' && options.method === 'PUT') return { engine_id: 'usque', file_id: 'main', source: 'staged' };
    if (failAt === 'review-missing' && url.startsWith('/api/v1/plan?')) return { transaction: preview.transaction };
    return normal(url, options);
  };
  await context.applyEngineConfig();
  assert.equal(appliedCalls().length, 0, `${failAt} failure applied an older staged configuration`);
  if (failAt === 'save' || failAt === 'identity') assert.equal(calls.length, 1, 'failed save continued to validation');
}

// An applied node route of another service blocks the plan in a new network:
// the panel re-checks only that node, then continues the same reviewed apply.
for (const checkPasses of [true, false]) {
  reset(); staged = true; state.engineConfigs = configs();
  state.services = [{ id: 'discord', name: 'Discord', enabled: true, route: 'sing-box:node-abc', applied_enabled: true, applied_route: 'sing-box:node-abc' }];
  let blocked = true;
  handler = async (url, options) => {
    if (url.startsWith('/api/v1/plan?') && blocked) {
      throw Object.assign(new Error('dependency'), { payload: { code: 'NODE_ROUTE_DEPENDENCY', service_id: 'discord', retained: true, cause: 'check-required' } });
    }
    if (url === '/api/v1/nodes/node-abc/check') {
      blocked = !checkPasses;
      return { ok: true, result: { available: checkPasses, service_id: 'discord', node_id: 'node-abc', message: checkPasses ? '' : 'Нет ответа.' } };
    }
    return normal(url, options);
  };
  await context.applyEngineConfig();
  const checks = calls.filter(call => call.url === '/api/v1/nodes/node-abc/check');
  assert.equal(checks.length, 1, 'retained node was not checked exactly once');
  assert.deepEqual(JSON.parse(checks[0].options.body), { service_id: 'discord', confirm: 'CHECK_NODE' });
  assert.equal(appliedCalls().length, checkPasses ? 1 : 0, 'retained check outcome did not gate apply');
  if (!checkPasses) assert.ok(messages.some(args => String(args[1]).includes('Discord') && args[5]?.label), 'failed check hid the blocking service');
}
reset(); staged = true; state.engineConfigs = configs();
handler = async (url, options) => {
  if (url.startsWith('/api/v1/plan?')) throw Object.assign(new Error('dependency'), { payload: { code: 'NODE_ROUTE_DEPENDENCY', service_id: 'discord', retained: false, cause: 'check-required' } });
  return normal(url, options);
};
await context.applyEngineConfig();
assert.equal(calls.filter(call => call.url.includes('/nodes/')).length, 0, 'an unapplied node selection was checked without review');
assert.equal(appliedCalls().length, 0);

// A service of the NFQWS2 list whose node is gone is offered its standard route.
reset(); messages.length = 0;
state.services = [{ id: 'discord', name: 'Discord', standard_route: 'nfqws2', route: 'sing-box:node-a', applied_route: 'sing-box:node-a', applied_enabled: true }];
context.showRouteDependencyNotice(Object.assign(new Error('dependency'), { payload: { code: 'NODE_ROUTE_DEPENDENCY', service_id: 'discord', retained: true, cause: 'node-unavailable' } }));
const standardAction = messages.at(-1)[5];
assert.equal(standardAction.label, 'Вернуть «Discord» на NFQWS2');
handler = normal;
await standardAction.run();
const restored = calls.find(call => call.url === '/api/v1/services/discord');
assert.deepEqual(JSON.parse(restored.options.body), { enabled: true, route: 'nfqws2', sources: [] });
assert.equal(appliedCalls().length, 0, 'returning to NFQWS2 applied without the owner');
state.services = [{ id: 'telegram', name: 'Telegram', route: 'sing-box:node-a' }];
context.showRouteDependencyNotice(Object.assign(new Error('dependency'), { payload: { code: 'NODE_ROUTE_DEPENDENCY', service_id: 'telegram', retained: true, cause: 'node-unavailable' } }));
assert.equal(messages.at(-1)[5].label, 'Открыть «Telegram»', 'a service outside the NFQWS2 list was moved to NFQWS2');
state.services = [];

reset(); state.engineMode = 'guided';
await context.applyEngineConfig();
assert.match(calls[0].url, /\/guided\?/);
assert.deepEqual(JSON.parse(calls[0].options.body), { values: { server: 'visible-server' } });

for (const phase of ['save', 'validate', 'plan']) {
  for (const stop of ['cancel', 'auth', 'view', 'selection']) {
    reset(); let finish;
    handler = async (url, options) => {
      const pause = phase === 'save' ? options.method === 'PUT' : phase === 'validate' ? url.includes('/validate?') : url.startsWith('/api/v1/plan?');
      if (pause) return new Promise(resolve => { finish = () => resolve(phase === 'save' ? { engine_id: 'sing-box', file_id: 'main', source: 'staged' } : phase === 'validate' ? { engine_id: 'sing-box', file_id: 'main', ok: true } : preview); });
      return normal(url, options);
    };
    const running = context.applyEngineConfig();
    while (!finish) await new Promise(resolve => setImmediate(resolve));
    await context.applyEngineConfig();
    await context.selectEngine('usque'); assert.equal(state.selectedEngine, 'sing-box', 'busy editor switched selection');
    if (stop === 'cancel') context.cancelEngineIntent();
    else if (stop === 'auth') { context.handleEngineEditorLifecycle({ type: 'razvilka:auth-required' }); $('#authScreen').hidden = false; }
    else if (stop === 'view') { context.handleEngineEditorLifecycle({ type: 'razvilka:view-change', detail: 'services' }); state.currentView = 'services'; }
    else state.selectedEngine = 'usque';
    finish(); await running;
    assert.equal(appliedCalls().length, 0, `late ${phase} ${stop} gained apply authority`);
    assert.equal(state.engineIntent, null);
    if (stop === 'auth') assert.equal($('#engineEditor').value, '', 'late response restored private editor after logout');
  }
}

reset();
reviewHandler = () => { $('#applyReviewDialog').open = true; return new Promise(resolve => { reviewClose = resolve; }); };
const awaiting = context.applyEngineConfig();
while (!reviewClose) await new Promise(resolve => setImmediate(resolve));
context.cancelEngineIntent(); await awaiting;
assert.equal($('#applyReviewDialog').open, false);
assert.equal(appliedCalls().length, 0, 'canceled modal confirmation gained apply authority');

reset(); state.engineEditorDirty = false;
let finishLoad;
handler = () => new Promise(resolve => { finishLoad = resolve; });
const loading = context.loadEngineFile();
$('#engineEditor').value = 'new unsaved edit'; context.markEngineEditorDirty();
finishLoad({ engine_id: 'sing-box', file_id: 'main', source: 'live', content: 'old response' }); await loading;
assert.equal($('#engineEditor').value, 'new unsaved edit', 'late load erased a newer edit');

reset(); state.engineEditorDirty = false; state.engineMode = 'guided';
const loadingGuided = context.loadEngineGuided();
context.handleEngineEditorLifecycle({ type: 'razvilka:auth-required' }); $('#authScreen').hidden = false;
finishLoad({ engine_id: 'sing-box', file_id: 'main', source: 'live', supported: true, values: { private: 'old secret' } }); await loadingGuided;
assert.equal(state.engineGuided, null, 'late guided response repopulated secret state after auth loss');

reset();
await context.discardEngineConfigDraft();
assert.equal(state.engineEditorDirty, false, 'local-only changes cannot be canceled');
assert.equal(calls.some(call => call.url.includes('/discard?')), false, 'canceling local-only editor touched server staging');
reset();
handler=async()=>{throw new Error('panel reader busy');};
await context.discardEngineConfigDraft();
assert.equal(state.engineEditorDirty,false,'a failed reread resurrected discarded local edits');
assert.equal(state.engineIntent,null);
assert.equal(calls.some(call=>call.options?.method&&call.options.method!=='GET'),false,'local discard started a write');
assert.equal(messages.length,0,'a completed local discard opened a misleading failure drawer');
assert.match($('#engineEditorMessage').textContent,/Изменения отменены/);
console.log('Engine single-action staging, reviewed file guards, failed-save stop, local editing, cancellation/auth and late-response fences passed');

reset();state.engineEditorDirty=false;state.engineMode='guided';
const previousGuided={engine_id:'sing-box',file_id:'main',source:'live',values:{server:'last-valid'}};
state.engineGuided=previousGuided;
handler=async()=>{throw new Error('read timed out');};
await context.loadEngineGuided(true);
assert.equal(state.engineGuided,previousGuided,'failed read erased last valid settings');
assert.equal(state.engineGuidedLoading,false,'failed read stayed busy forever');
assert.equal(state.engineReadError,'read timed out');
assert.match($('#guidedEditor').innerHTML,/Не удалось прочитать/);
handler=async()=>({...previousGuided,values:{server:'fresh'}});
await context.loadEngineGuided(true);
assert.equal(state.engineReadError,'');assert.equal(state.engineGuided.values.server,'fresh');
console.log('Guided read failure preserves settings, ends loading and supports explicit retry');

// Exercise the real renderer and the actual save payload for multiline NFQWS
// strategies, including leading newlines and text that resembles HTML.
reset(); state.engineMode = 'guided';
const multiline = '\n--filter-tcp=443\n--dpi-desync=fake,multisplit\n--comment="</textarea><script>alert(1)</script>&"';
const fieldID = 'args" data-injected="yes';
const controls = [{ dataset: { guidedField: fieldID }, value: multiline, addEventListener() {} }];
context.$$ = selector => selector === '[data-guided-field]' ? controls : [];
state.engineGuided = { supported: true, fields: [{ id: fieldID, type: 'arguments', label: 'Strategy', required: true, placeholder: '"<hint>' }], values: { [fieldID]: multiline } };
for (const name of ['esc', 'renderGuidedEditor']) {
  const match = source.match(new RegExp(`function ${name}\\([^]*?\\n}\\n`));
  assert.ok(match, name); vm.runInContext(match[0], context);
}
context.renderGuidedEditor();
const markup = $('#guidedEditor').innerHTML;
assert.match(markup, /<textarea[^>]*rows="6"[^>]*required>/);
assert.doesNotMatch(markup, /<input|<script|data-injected="yes/);
assert.equal((markup.match(/<\/textarea>/g) || []).length, 1, 'strategy escaped out of its control');
assert.match(markup, /data-guided-field="args&quot; data-injected=&quot;yes"/);
assert.match(markup, />\n\n--filter-tcp=443\n--dpi-desync=fake,multisplit\n--comment=&quot;&lt;\/textarea&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;&amp;&quot;<\/textarea>/, 'textarea lost leading/newline text or HTML escaping');
const multilineIntent = context.beginEngineIntent();
assert.equal(JSON.parse(JSON.stringify(multilineIntent.body)).values[fieldID], multiline, 'guided save flattened the multiline strategy');
context.finishEngineIntent(multilineIntent);
console.log('Guided arguments use escaped multiline textarea and preserve the complete save payload');

for (const value of ['', 'legacy"<&', '$MODE_AUTO']) {
  reset(); state.engineMode = 'guided';
  state.engineGuided = { supported: true, fields: [{ id: 'NFQWS_EXTRA_ARGS', type: 'select', options: [{ value: '$MODE_AUTO', label: 'Auto' }, { value: '$MODE_LIST', label: 'List' }] }], values: { NFQWS_EXTRA_ARGS: value } };
  context.$$ = selector => selector === '[data-guided-field]' ? [{ dataset: { guidedField: 'NFQWS_EXTRA_ARGS' }, value, addEventListener() {} }] : [];
  context.renderGuidedEditor();
  const html = $('#guidedEditor').innerHTML;
  const selected = [...html.matchAll(/<option value="([^"]*)" selected>([^]*?)<\/option>/g)];
  assert.equal(selected.length, 1, 'browser would choose the first option instead of the original source value');
  assert.equal(selected[0][1], context.esc(value));
  assert.equal(selected[0][2], value === '' ? 'Не задано' : value === '$MODE_AUTO' ? 'Auto' : 'Текущее значение: legacy&quot;&lt;&amp;');
  assert.equal((html.match(/<option /g) || []).length, value === '$MODE_AUTO' ? 2 : 3, 'known enum gained a redundant placeholder');
  const intent = context.beginEngineIntent();
  assert.equal(intent.body.values.NFQWS_EXTRA_ARGS, value, 'unchanged enum did not retain its original value');
  context.finishEngineIntent(intent);
}
console.log('Guided empty and unknown enum values remain selected instead of becoming the first option');

// Exercise receipts through the actual Stage/Validate/reviewed Apply/probe
// handlers, then render the production card. DTOs model public API responses;
// they do not claim a native router or real network test.
const interfaceSource = readFileSync(new URL('../cmd/razvilka/web/interface.js', import.meta.url), 'utf8');
const consoleSource = readFileSync(new URL('../cmd/razvilka/web/console.js', import.meta.url), 'utf8');
const workflowSource = readFileSync(new URL('../cmd/razvilka/web/workflow-actions.js', import.meta.url), 'utf8');
const section = (code, start, end) => code.slice(code.indexOf(start), code.indexOf(end, code.indexOf(start) + start.length));
context.consoleEngineMeta = {'sing-box':{name:'Sing-box',tone:'mint',icon:'layers'}};
context.consoleDate = String; context.ci = () => '';
context.serviceDashboardApplied = service => service.applied_state || {};
context.workflowState = {epoch:1,probe:null};
context.workspaceControl = {stopReceipt:null};
context.interfaceState = {authRevoked:false};
context.workflowSession = epoch => epoch === context.workflowState.epoch && $('#authScreen').hidden;
context.workflowRequest = (path, options) => context.api(path, options);
context.renderWorkflowControls = () => {};
context.routeLabel = String; context.workflowError = error => error.message;
vm.runInContext(section(consoleSource, 'function consoleEngineState(', 'function consoleNavigate('), context);
vm.runInContext(section(interfaceSource, 'const engineProgressEvidence =', 'function renderInterfaceEngines('), context);
const runProbe = workflowSource.match(/async function workflowRunProbe\([^]*?\n}\n/);
assert.ok(runProbe); vm.runInContext(runProbe[0], context);
let liveHash, stagedHash, resultOverride;
const hashA = 'a'.repeat(64), hashB = 'b'.repeat(64);
const receiptConfigs = () => [{id:'sing-box',name:'Sing-box',installed:true,files:[{id:'main',exists:true,staged,sha256:liveHash,staged_at:'draft-generation',modified_at:liveHash}]}];
const receiptPreview = {review:{expected_revision:12,reviewed_digest:'review-digest'},transaction:{digest:'review-digest',revision:12,plan_id:'plan-1',adapters:['sing-box'],routes:[{service_id:'telegram',resolved:'sing-box'}],blockers:[]}};
const probeResult = () => {
  const now = new Date().toISOString();
  return {results:[{service_id:'telegram',route:'sing-box',network_profile_id:'network-a',status:'pass',verdict:'PASS',route_confirmed:true,evidence_level:'service-confirmed',outcome:'service_accepted',checked_at:now,evidence_fresh_until:new Date(Date.now()+60000).toISOString(),
    evidence_v2:{schema_version:2,probe_id:'probe-1',service:'telegram',engine:'sing-box',network_profile:'network-a',route_path_id:'isolated:sing-box',verdict:'PASS',outcome:'service_accepted',started_at:now,finished_at:now}}]};
};
const resetReceipts = () => {
  reset(); context.invalidateEngineProgress();
  liveHash = hashA; stagedHash = hashB; resultOverride = null;
  Object.assign(state,{authenticated:true,authGeneration:3,nodes:{generation:8,network_profile:'network-a'},dataLoad:{},services:[{id:'telegram',name:'Telegram',applied_state:{enabled:true,route:'sing-box'}}],serviceControl:{config_revision:12,runtime_state:'running'},components:[{id:'sing-box',installed:true,installed_version:'1.0'}],engines:[{id:'sing-box',installed:true,binary_path:'/opt/bin/sing-box'}],engineConfigs:receiptConfigs()});
  context.workflowState.probe = null; context.workspaceControl.stopReceipt = null; context.interfaceState.authRevoked = false;
  $('#r4ProbeService').value = 'telegram'; $('#r4ProbeResults').replaceChildren = () => {};
  handler = async (url, options) => {
    if (options.method === 'PUT') { staged = true; return {engine_id:'sing-box',file_id:'main',source:'staged',sha256:stagedHash}; }
    if (url === '/api/v1/engine-configs') return receiptConfigs();
    if (url === '/api/v1/status') return {revision:12,dataplane_state:'committed',live_active:true};
    if (url.includes('/validate?')) return {engine_id:'sing-box',file_id:'main',ok:true,native:true};
    if (url.startsWith('/api/v1/plan?')) return receiptPreview;
    if (url.startsWith('/api/v1/apply?')) {
      staged = false; liveHash = stagedHash;
      const now = new Date().toISOString();
      const result = {ok:true,live_applied:true,scope_pending_changes:false,transaction:receiptPreview.transaction,execution:{plan_id:'plan-1',digest:'review-digest',state:'committed',started_at:now,finished_at:now}};
      return resultOverride ? resultOverride(result) : result;
    }
    if (url === '/api/v1/testlab/routes') return resultOverride ? resultOverride(probeResult()) : probeResult();
    throw new Error('unexpected '+url);
  };
};
const progress = () => JSON.parse(JSON.stringify(context.engineProgressView('sing-box')));
const renderReceiptCard = () => context.interfaceEngineCard('sing-box', context.consoleEngineMeta['sing-box']);
const complete = async () => {
  resetReceipts(); await context.applyEngineConfig(); await context.workflowRunProbe();
  assert.deepEqual(progress(),{format:true,service:true,apply:true,native:true});
};

resetReceipts();
assert.equal(context.engineWorkflowPresentation('sing-box').next,'profile','unsaved profile went directly to a service probe');
await context.validateEngineFile();
assert.equal(progress().format,true); assert.equal(progress().service,false); assert.equal(progress().apply,false);
assert.equal(appliedCalls().length,0,'format validation initiated Apply');
assert.equal(calls.some(call=>call.url.includes('/testlab/')),false,'format validation initiated a network test');
assert.equal(context.engineWorkflowPresentation('sing-box').next,'apply','validated staged profile was held behind a live-profile service probe');
assert.equal(context.engineWorkflowPresentation('sing-box').complete.check,false);
assert.match(context.engineWorkflowSummary('sing-box'),/Сервис: проверяется после применения/);
// A previous observed service PASS cannot complete a new Apply's check step.
state.services[0].observed_state = {level:'service-confirmed',outcome:'service_accepted',status:'pass',route:'sing-box',checked_at:new Date(Date.now()-5000).toISOString(),fresh_until:new Date(Date.now()+60000).toISOString()};
await context.applyEngineConfig();
assert.equal(progress().format,true,'matching candidate-to-live commit lost the format receipt');
assert.equal(progress().apply,true); assert.equal(progress().service,false,'Apply borrowed an old service test');
assert.equal(context.engineWorkflowPresentation('sing-box').next,'check','committed profile skipped its fresh service test');
assert.deepEqual(JSON.parse(appliedCalls()[0].options.body),receiptPreview.review);
await context.workflowRunProbe();
assert.deepEqual(progress(),{format:true,service:true,apply:true,native:true});
const fullCard = renderReceiptCard();
for (const step of ['install','profile','check','apply']) assert.match(fullCard,new RegExp(`data-engine-progress="${step}" data-completed="true"`));
const workspaceSummary=context.engineWorkflowSummary('sing-box');
for (const step of ['install','profile','check','apply']) assert.match(workspaceSummary,new RegExp(`data-engine-workspace-progress="${step}" class="confirmed"`));
assert.doesNotMatch(workspaceSummary,/>Процесс<|>Маршруты</,'workspace retained the unrelated legacy progress strip');
state.currentView='engines';assert.equal(context.engineWorkflowPresentation('sing-box').complete.check,true,'return to cards lost the selected-file receipt');state.currentView='engineconfig';
assert.match(fullCard,/Проверка и применение подтверждены/);
assert.equal(appliedCalls().length,1,'fresh service probe repeated Apply');
assert.deepEqual(JSON.parse(calls.find(call=>call.url==='/api/v1/testlab/routes').options.body),{services:['telegram'],routes:['sing-box']});

for (const [name, change] of [
  ['hash',()=>state.engineConfigs[0].files[0].sha256=hashA],
  ['revision',()=>state.status.revision++], ['generation',()=>state.nodes.generation++],
  ['network',()=>state.nodes.network_profile='network-b'], ['auth',()=>state.authGeneration++],
  ['binary',()=>state.engines[0].binary_path='/changed/bin'],
  ['staged',()=>state.engineConfigs[0].files[0].staged=true],
  ['Stop',()=>context.workspaceControl.stopReceipt={accepted:true}],
  ['negative Apply',()=>state.status.last_apply_failure='failed'],
  ['new negative probe',()=>state.services[0].observed_state={route:'sing-box',status:'fail',checked_at:new Date().toISOString()}],
  ['read error',()=>state.dataLoad.status={phase:'error'}],
]) {
  await complete(); change();
  assert.deepEqual(progress(),{format:false,service:false,apply:false},name+' retained completed receipts');
  assert.doesNotMatch(renderReceiptCard(),/Проверка и применение подтверждены/,name+' rendered success');
}
for (const change of [()=>state.engineIntent={engineID:'sing-box'},()=>context.workflowState.probe={engine:'sing-box'},()=>state.dataLoad.status={phase:'busy'},()=>state.serviceControl.durable_jobs=[{mode:'service-stop',state:'queued'}]]) {
  await complete(); change(); assert.deepEqual(progress(),{format:false,service:false,apply:false},'pending operation showed completed steps');
}
for (const [name, tamper] of [
  ['unconfirmed',result=>({...result,live_applied:false})],
  ['safe mode',result=>({...result,safe_mode:true})],
  ['digest',result=>({...result,execution:{...result.execution,digest:'other'}})],
  ['plan',result=>({...result,execution:{...result.execution,plan_id:'other'}})],
  ['revision',result=>({...result,transaction:{...result.transaction,revision:13}})],
  ['pending',result=>({...result,scope_pending_changes:true})],
  ['failed',result=>({...result,execution:{...result.execution,state:'failed'}})],
]) {
  resetReceipts(); resultOverride=tamper; await context.applyEngineConfig();
  assert.equal(progress().apply,false,name+' committed a mismatched receipt');
}
for (const [name, tamper] of [
  ['wrong service',row=>row.service_id='other'],['wrong engine',row=>row.evidence_v2.engine='other'],
  ['wrong network',row=>row.evidence_v2.network_profile='other'],
  ['path mismatch',row=>{row.expected_route_path_id='expected';row.observed_route_path_id='foreign';}],
  ['negative control',row=>row.evidence_v2.negative_control_matched=true],
  ['old test',row=>{row.checked_at=new Date(Date.now()-10000).toISOString();row.evidence_v2.started_at=row.checked_at;row.evidence_v2.finished_at=row.checked_at;}],
  ['expiry',row=>row.evidence_fresh_until=new Date(Date.now()-1000).toISOString()],
  ['runtime only',row=>row.evidence_level='runtime'],
]) {
  resetReceipts(); await context.applyEngineConfig(); resultOverride=result=>{tamper(result.results[0]);return result;};
  await context.workflowRunProbe(); assert.equal(progress().service,false,name+' completed the service check');
}
resetReceipts();state.engineEditorDirty=false;state.engineConfigs[0].files[0].sha256='';
assert.equal(context.engineProgressBinding('sing-box'),null,'redacted profile acquired invented identity');
resetReceipts();staged=true;state.engineConfigs=receiptConfigs();state.engineLoaded={engine_id:'sing-box',file_id:'main',source:'live',sha256:hashA};
assert.equal(context.engineProgressBinding('sing-box'),null,'draft used the live FileView hash');
await complete();state.services[0].applied_state.route='direct';
assert.equal(progress().apply,false,'receipt survived removal of its applied service route');
await complete();const clockNow=Date.now();
context.Date=class extends Date {static now(){return clockNow+121000;}};
assert.deepEqual(progress(),{format:false,service:false,apply:false,native:false},'expired evidence remained complete');
context.Date=Date;
console.log('Engine progress completes actual reviewed Apply + fresh typed probe and clears on profile/revision/generation/negative/Stop changes');
await complete();state.engineConfigs[0].files.push({id:'aux',exists:true,staged:false,sha256:'c'.repeat(64)});state.selectedEngineFile='aux';
const otherFile=context.engineWorkflowPresentation('sing-box');assert.equal(otherFile.file.id,'aux');assert.equal(otherFile.complete.profile,false);assert.equal(otherFile.complete.check,false);assert.equal(otherFile.complete.apply,false);
state.currentView='engines';assert.equal(context.engineWorkflowPresentation('sing-box').file.id,'aux','card silently replaced the selected file with main');state.currentView='engineconfig';
assert.doesNotMatch(context.engineWorkflowSummary('sing-box'),/data-engine-workspace-progress="(?:profile|check|apply)" class="confirmed"/,'another file borrowed the previous profile receipts');
resetReceipts();state.engineEditorDirty=false;state.engines[0].running=true;state.services[0].observed_state={status:'pass',level:'service-confirmed',outcome:'service_accepted'};
assert.equal(context.engineWorkflowPresentation('sing-box').complete.check,false,'running process and saved route became service proof');
assert.doesNotMatch(context.engineWorkflowSummary('sing-box'),/data-engine-workspace-progress="(?:profile|check|apply)" class="confirmed"/);
console.log('PASS one engine workflow: staged format→Apply→fresh service test, matching card/workspace receipts, selected-file isolation and no legacy process/route PASS');
resetReceipts();state.engineEditorDirty=false;state.status.revision=0;state.serviceControl.config_revision=0;
const initialBinding=context.engineProgressBinding('sing-box');assert.equal(initialBinding.revision,0,'explicit observed config revision zero was discarded');
context.engineProgressFormat(initialBinding,{engine_id:'sing-box',file_id:'main',ok:true,native:true});
assert.deepEqual(progress(),{format:true,service:false,apply:false,native:true},'format at revision zero became service or Apply proof');
for(const [status,control] of [[{},{}],[{revision:-1},{}],[{revision:0},{config_revision:-1}],[{revision:'0'},{config_revision:0}],[{revision:0.5},{}]]){
  state.status=status;state.serviceControl=control;assert.equal(context.engineProgressBinding('sing-box'),null,'missing/invalid revision acquired an invented binding');
}
for(const [status,control] of [[{revision:0},{}],[{},{config_revision:0}]]){
  state.status=status;state.serviceControl=control;assert.equal(context.engineProgressBinding('sing-box').revision,0,'a genuine observed zero was treated as absent');
}
resetReceipts();state.engines[0].binary_path='';
const packageOnly=context.engineWorkflowPresentation('sing-box');assert.equal(packageOnly.complete.install,false);assert.equal(packageOnly.next,'install','package metadata skipped unresolved binary detection');
const packageCard=context.interfaceEngineCard('sing-box',context.consoleEngineMeta['sing-box']);assert.match(packageCard,/data-component-refresh="sing-box"[^>]*>Уточнить установку/);assert.doesNotMatch(packageCard,/data-component-action="install"/,'installed package offered another install instead of a read');
resetReceipts();context.inventoryObservationStale=()=>true;
assert.equal(context.engineWorkflowPresentation('sing-box').next,'install','stale binary observation skipped installation readback');delete context.inventoryObservationStale;
console.log('PASS explicit cfg0 format binding without missing-revision proof; unresolved/stale binary keeps installation first with a real metadata read CTA');
