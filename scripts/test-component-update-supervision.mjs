// Test real installer guard functions without invoking package/service actions.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-component-schema-'));
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
try {
  const directory = join(root, 'components', 'update-journal');
  const journal = join(directory, 'current.json');
  mkdirSync(directory, {recursive: true});
  for (const name of ['upgrade-entware.sh', 'rollback-entware.sh']) {
    const source = readFileSync(new URL(name, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
    const start = source.indexOf('require_native_enrollment_schema() {\n');
    const end = source.indexOf('\n}\n', start);
    assert(start >= 0 && end > start);
    const gate = source.slice(start, end + 3);
    assert(gate.includes('-component-update-schema'));
    const stop = source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
    const firstCheck = source.indexOf('require_native_enrollment_schema "', end);
    const recheck = source.indexOf('require_native_enrollment_schema "', stop);
    assert(firstCheck < stop && recheck > stop, 'gate must run before and after quiescence');
    const run = (body, expected) => {
      const result = spawnSync(process.argv[2] || 'sh', ['-s'], {
        input: `set -eu\nSTATEDIR=${quote(root.replaceAll('\\', '/'))}\nAPPDIR="$STATEDIR/config"\nAUTONOMY_STATE_PRESENT=skip\n${gate}\n${body}\n`,
        encoding: 'utf8', timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, expected, result.stderr + result.stdout);
      return result;
    };
    run('old_binary() { echo unexpected >&2; return 2; }\nrequire_native_enrollment_schema old_binary', 0);
    writeFileSync(journal, '{"schema_version":1,"phase":"rollback-started","private":"retained"}\n');
    const before = readFileSync(journal);
    assert.match(run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary', 1).stderr, /cannot preserve component update recovery/);
    run('wrong_schema() { printf "2\\n"; }\nrequire_native_enrollment_schema wrong_schema', 1);
    run('new_binary() { [ "$1" = -component-update-schema ]; printf "1\\n"; }\nrequire_native_enrollment_schema new_binary', 0);
    assert.deepEqual(readFileSync(journal), before, 'compatibility probe must not consume pending receipt');
    rmSync(journal);
    mkdirSync(journal);
    assert.match(run('new_binary() { printf "1\\n"; }\nrequire_native_enrollment_schema new_binary', 1).stderr, /journal is unsafe/);
    rmSync(journal, {recursive:true});
    run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary\nprintf pending > "$STATEDIR/components/update-journal/current.json"\nrequire_native_enrollment_schema old_binary', 1);
    assert.equal(readFileSync(journal, 'utf8'), 'pending');
    rmSync(journal);
  }
} finally {
  rmSync(root, {recursive:true, force:true});
}
console.log('Component update upgrade/rollback schema gates: PASS');
