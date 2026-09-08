// Run with a POSIX shell: node scripts/test-restore-busy-supervision.mjs [sh]
// Exercises production supervision branches with stubs: no router/process/file
// changes. This is NOT the full Linux/Entware installation regression.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const shell = process.argv[2] || 'sh';
const init = readFileSync(new URL('./S99razvilka', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const upgrade = readFileSync(new URL('./upgrade-entware.sh', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const rollback = readFileSync(new URL('./rollback-entware.sh', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
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
for (const option of ['-config "$APPDIR/config.json"', '-custom-services "$APPDIR/custom-services.json"', '-devices "$APPDIR/devices.json"', '-stage "$STATEDIR/staging"', '-warp-state "$STATEDIR/warp"', '-cloudflare-state "$APPDIR/cloudflare-private"']) {
  assert(migration.includes(option), option);
  assert(start.includes(option), `boot ${option}`);
}
for (const option of ['-node-state "$APPDIR/nodes-private"', '-metrics-history "$STATEDIR/metrics/history.jsonl"', '-strategy-lab-state "$STATEDIR/strategy-lab.json"', '-audit-log "$STATEDIR/audit/events.jsonl"', '-dns-state "$STATEDIR/dns/state.json"']) {
  assert(start.includes(option), `isolated boot ${option}`);
}
assert(start.includes('export RAZVILKA_USQUE_REPAIR_STATE="$STATEDIR/usque-repair"'));
assert(rollback.includes('-warp-state "$STATEDIR/warp"'));

// Upgrade and rollback must settle the private journal only while the server is
// stopped, and a backup becomes valid only after all directory images exist.
const stopAt = upgrade.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
const recoverAt = upgrade.indexOf('$BIN_SOURCE -recover-private-restore');
const backupAt = upgrade.indexOf('BACKUP="$BACKUPROOT/$STAMP"');
const manifestAt = upgrade.indexOf('mv "$BACKUP/manifest.tmp" "$BACKUP/manifest"');
assert(stopAt >= 0 && stopAt < recoverAt && recoverAt < backupAt && backupAt < manifestAt);
assert(upgrade.includes('STAGING_PRESENT=$STAGING_PRESENT'));
assert(upgrade.includes('CLOUDFLARE_PRIVATE_PRESENT=$CLOUDFLARE_PRIVATE_PRESENT'));

assert(!rollback.includes('"$RAZ_INIT" stop || true'));
const rollbackStopAt = rollback.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
const rollbackRecoverAt = rollback.indexOf('"$BINDIR/razvilka" -recover-private-restore');
const rollbackWriteAt = rollback.indexOf('restore_or_remove "$RAZ_BINARY_PRESENT"');
assert(rollbackStopAt >= 0 && rollbackStopAt < rollbackRecoverAt && rollbackRecoverAt < rollbackWriteAt);
assert(rollback.includes('restore_dir "$STAGING_PRESENT" staging "$STATEDIR/staging"'));
assert(rollback.includes('restore_dir "$CLOUDFLARE_PRIVATE_PRESENT" cloudflare-private "$APPDIR/cloudflare-private"'));
assert(!rollback.includes('restore_dir "$PRIVATE_RESTORE'));

console.log('Restore busy supervision, private recovery and migration layout checks passed');
