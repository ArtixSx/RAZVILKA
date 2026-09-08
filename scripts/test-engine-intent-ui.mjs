import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const names = ['captureEngineEditorContext', 'engineEditorContextCurrent', 'engineIntentCurrent', 'updateEngineEditorActions', 'markEngineEditorDirty', 'invalidateEngineEditorContext', 'beginEngineIntent', 'finishEngineIntent', 'cancelEngineIntent', 'handleEngineEditorLifecycle', 'saveEngineDraft', 'applyEngineConfig', 'applyDraft', 'validateEngineFile', 'loadEngineFile', 'loadEngineGuided', 'selectEngine', 'selectEngineFile', 'switchEngineMode', 'handleEngineImport', 'discardEngineConfigDraft', 'refreshEngineConfigs'];
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
  showNotice: (...args) => messages.push(args), showDetails: (...args) => messages.push(args),
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
console.log('Engine single-action staging, reviewed file guards, failed-save stop, local editing, cancellation/auth and late-response fences passed');
