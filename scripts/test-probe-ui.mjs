import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../cmd/razvilka/web/app.js', import.meta.url), 'utf8');
const context = vm.createContext({
  evidenceAtLeast: (level, required) => level === required,
  testStatusLabel: (status) => status,
});
// Run the actual UI functions, without bootstrapping a browser or network.
for (const name of ['probeVerdict', 'probeStatusLabel']) {
  const functionSource = source.match(new RegExp(`function ${name}\\([^]*?\\n}\\n`));
  assert.ok(functionSource, `${name} must remain testable`);
  vm.runInContext(functionSource[0], context);
}
const verified = { status: 'pass', verdict: 'PASS', http_status: 204, route_confirmed: true, evidence_level: 'service-confirmed' };
assert.equal(context.probeVerdict(verified).tone, 'pass');
assert.notEqual(context.probeVerdict({ ...verified, route_confirmed: false }).tone, 'pass');
assert.notEqual(context.probeVerdict({ ...verified, evidence_level: 'runtime' }).tone, 'pass');
for (const verdict of ['MISROUTED', 'BLOCKED', 'INCONCLUSIVE', 'ERROR', 'PARTIAL']) {
  assert.notEqual(context.probeVerdict({ ...verified, verdict }).tone, 'pass');
}
for (const errorCode of ['route-receipt-missing', 'route-direct-outbound', 'route-runtime-changed', 'route-outbound-unsupported']) {
  for (const proof of [{ route_proof_error: errorCode }, { evidence_v2: { route_proof_error: errorCode } }]) {
    const result = { ...verified, ...proof };
    assert.equal(context.probeVerdict(result).tone, 'warn');
    assert.equal(context.probeStatusLabel(result), 'Путь не подтверждён');
  }
}
assert.equal(context.probeStatusLabel({ verdict: 'BLOCKED', error_code: 'timeout' }), 'Нет ответа');
assert.equal(context.probeStatusLabel({ verdict: 'BLOCKED', error_code: 'tls-certificate-mismatch' }), 'TLS не подтверждён');
console.log('Probe UI verdict checks passed');
