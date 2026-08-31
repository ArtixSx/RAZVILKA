// Run with a POSIX shell: node scripts/test-restore-busy-supervision.mjs [sh]
// Exercises production supervision branches with stubs: no router/process/file
// changes. This is NOT the full Linux/Entware installation regression.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const shell = process.argv[2] || 'sh';
const init = readFileSync(new URL('./S99razvilka', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const upgrade = readFileSync(new URL('./upgrade-entware.sh', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
function fn(source, name) {
  const start = source.indexOf(`${name}() {\n`);
  assert(start >= 0, name);
  const end = source.indexOf('\n}\n', start);
  assert(end > start, name);
  return source.slice(start, end + 3);
}
function run(script, status, match) {
  const result = spawnSync(shell, ['-s'], { input: `set -eu\n${script}\n`, encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, status, result.stderr || result.stdout);
  assert.match(result.stdout + result.stderr, match);
  assert.doesNotMatch(result.stdout + result.stderr, /UNEXPECTED_/);
}
// Start only its production health wait/decision tail, without spawning a daemon.
const start = fn(init, 'start_process');
const wait = start.indexOf('\n  WAIT=0\n');
assert(wait >= 0);
const startHealth = `start_process() {${start.slice(wait)}`;
for (const mode of [0, 1, 75]) {
  const stubs = `
HEALTH_RETRIES=1
LAN_IP=127.0.0.1
PORT=8787
health() { return ${mode}; }
sleep() { :; }
running_pid() { printf '1234'; }
detect_lan_ip() { printf '127.0.0.1'; }
clear_failure() { :; }
record_failure() { printf 'recorded-failure\\n'; }
stop_process() { ${mode === 75 ? "echo UNEXPECTED_STOP >&2" : ':'}; }
`;
  run(`${stubs}\n${startHealth}\nstart_process`, mode, mode === 75 ? /Process kept/ : mode === 0 ? /healthy/ : /recorded-failure/);
  run(`${stubs}\n${fn(init, 'status_process')}\nstatus_process`, mode, mode === 75 ? /Do not restart/ : mode === 0 ? /healthy/ : /health check failed/);
}
run(`
BACKUP=synthetic-snapshot
CURRENT_BACKUP=/dev/null
ROLLBACK=must-not-run
chmod() { :; }
sh() { echo UNEXPECTED_ROLLBACK >&2; return 1; }
${fn(upgrade, 'rollback_on_error')}
rollback_on_error 75
`, 75, /readiness not confirmed.*Process kept/);

// Migration and normal boot must bind the same files even with RAZVILKA_BASE.
const migration = upgrade.slice(upgrade.indexOf('"$BINDIR/razvilka" -migrate-config'), upgrade.indexOf('# Quiesce only'));
for (const option of ['-config "$APPDIR/config.json"', '-custom-services "$APPDIR/custom-services.json"', '-devices "$APPDIR/devices.json"', '-stage "$STATEDIR/staging"']) {
  assert(migration.includes(option), option);
  assert(start.includes(option), `boot ${option}`);
}
console.log('Restore busy supervision branches and migration layout checks passed');
