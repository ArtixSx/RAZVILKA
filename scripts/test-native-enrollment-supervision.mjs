// Execute both production schema gates without starting an app or router command.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-native-schema-'));
const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
try {
  mkdirSync(join(root, 'warp'));
  mkdirSync(join(root, 'warp', 'native-enrollment'));
  mkdirSync(join(root, 'config', 'private-restore-native-v1'), {recursive: true});
  mkdirSync(join(root, 'config', 'private-restore-feeds-v1'), {recursive: true});
  mkdirSync(join(root, 'config', 'subscriptions-private'), {recursive: true});
  for (const name of ['upgrade-entware.sh', 'rollback-entware.sh']) {
    const source = readFileSync(new URL(name, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
    const start = source.indexOf('require_native_enrollment_schema() {\n');
    const end = source.indexOf('\n}\n', start);
    assert(start >= 0 && end > start);
    const gate = source.slice(start, end + 3);
    const call = source.indexOf('require_native_enrollment_schema "', end);
    const stop = source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
    assert(call > end && call < stop, `${name}: refusal must precede stop`);
    const stoppedCall = source.indexOf('require_native_enrollment_schema "', stop);
    const recovery = source.indexOf(' -recover-private-restore', stop);
    assert(stoppedCall > stop && stoppedCall < recovery, `${name}: recheck must follow stop and precede recovery`);
    if (name === 'rollback-entware.sh') {
      const recoveredCall = source.indexOf('require_native_enrollment_schema "', recovery);
      const deactivate = source.indexOf(' -deactivate-dataplane', recovery);
      assert(recoveredCall > recovery && recoveredCall < deactivate, 'Recovered native image must precede target replacement');
    }
    const run = (body, expected) => {
      const result = spawnSync(process.argv[2] || 'sh', ['-s'], {
        input: `set -eu\nSTATEDIR=${quote(root.replaceAll('\\', '/'))}\nAPPDIR="$STATEDIR/config"\n${gate}\n${body}\n`,
        encoding: 'utf8', timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, expected, result.stderr + result.stdout);
      return result;
    };
    run('old_binary() { echo UNEXPECTED_CALL >&2; return 2; }\nrequire_native_enrollment_schema old_binary', 0);
    const state = join(root, 'warp', 'native-enrollment.private.json');
    writeFileSync(state, 'opaque-pending-checkpoint');
    const refused = run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary', 1);
    assert.match(refused.stderr, /cannot preserve native WARP/);
    run('other_schema() { printf "2\\n"; }\nrequire_native_enrollment_schema other_schema', 1);
    run('native_binary() { [ "$1" = -native-enrollment-schema ]; printf "1\\n"; }\nrequire_native_enrollment_schema native_binary', 0);
    assert.equal(readFileSync(state, 'utf8'), 'opaque-pending-checkpoint');
    rmSync(state);
    for (const marker of [join(root,'config','subscriptions-private','subscriptions.private.json'),join(root,'config','private-restore-feeds-v1','restore.private.json')]) {
      writeFileSync(marker,'private-feed-state');
      const refusedFeed=run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary',1);
      assert.match(refusedFeed.stderr,/cannot preserve private subscriptions/);
      run('feed_binary() { [ "$1" = -subscription-schema ]; printf "1\\n"; }\nrequire_native_enrollment_schema feed_binary',0);
      assert.equal(readFileSync(marker,'utf8'),'private-feed-state');
      rmSync(marker);
    }
    for (const marker of [join(root, 'warp', 'native-enrollment', 'current.json'), join(root, 'warp', 'native-enrollment', 'pending.json'), join(root, 'config', 'private-restore-native-v1', 'restore.private.json')]) {
      writeFileSync(marker, 'retained-protocol-state');
      run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary', 1);
      assert.equal(readFileSync(marker, 'utf8'), 'retained-protocol-state');
      rmSync(marker);
    }
    // A request may checkpoint after the read-only check but before stop.
    const late = run(`old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary\nprintf 'late-pending' > "$STATEDIR/warp/native-enrollment.private.json"\nrequire_native_enrollment_schema old_binary`, 1);
    assert.match(late.stderr, /cannot preserve native WARP/);
    assert.equal(readFileSync(state, 'utf8'), 'late-pending');
    rmSync(state);
  }
} finally {
  rmSync(root, {recursive: true, force: true});
}
console.log('Native enrollment upgrade/rollback compatibility gates: PASS');
