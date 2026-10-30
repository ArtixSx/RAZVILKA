// Exercise the actual shell compatibility gates without launching services.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-self-update-schema-'));
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
try {
  for (const name of ['upgrade-entware.sh', 'rollback-entware.sh']) {
    const source = readFileSync(new URL(name, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
    const start = source.indexOf('require_native_enrollment_schema() {\n');
    const end = source.indexOf('\n}\n', start);
    assert(start >= 0 && end > start);
    const gate = source.slice(start, end + 3);
    assert(gate.includes('-self-update-schema'));
    const stop = source.indexOf('RAZVILKA_BASE="$BASE" sh "$RAZ_INIT" stop');
    assert(source.indexOf('require_native_enrollment_schema "', end) < stop);
    assert(source.indexOf('require_native_enrollment_schema "', stop) > stop);
    const run = (body, expected) => {
      const result = spawnSync(process.argv[2] || 'sh', ['-s'], {
        input: `set -eu\nSTATEDIR=${quote(root.replaceAll('\\', '/'))}\nAPPDIR="$STATEDIR/config"\nAUTONOMY_STATE_PRESENT=skip\n${gate}\n${body}\n`,
        encoding: 'utf8', timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, expected, result.stderr + result.stdout);
      return result;
    };
    for (const directory of ['self-update', 'self-update-files']) {
      mkdirSync(join(root, directory), {recursive: true});
      const receipt = join(root, directory, 'current.json');
      run('old_binary() { echo unexpected >&2; return 2; }\nrequire_native_enrollment_schema old_binary', 0);
      for (const phase of ['command-started', 'accepted', 'rolled-back', 'corrupt-retained']) {
        writeFileSync(receipt, `{"schema":1,"phase":"${phase}"}\n`);
        const before = readFileSync(receipt);
        assert.match(run('old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary', 1).stderr, /cannot preserve self update recovery/);
        run('wrong_schema() { printf "1\\n"; }\nrequire_native_enrollment_schema wrong_schema', 1);
        run('new_binary() { [ "$1" = -self-update-schema ]; printf "2\\n"; }\nrequire_native_enrollment_schema new_binary', 0);
        assert.deepEqual(readFileSync(receipt), before, 'probe consumed a retained receipt');
      }
      rmSync(receipt);
      mkdirSync(receipt);
      assert.match(run('new_binary() { printf "1\\n"; }\nrequire_native_enrollment_schema new_binary', 1).stderr, /receipt is unsafe/);
      rmSync(receipt, {recursive: true});
      run(`old_binary() { return 2; }\nrequire_native_enrollment_schema old_binary\nprintf pending > "$STATEDIR/${directory}/current.json"\nrequire_native_enrollment_schema old_binary`, 1);
      assert.equal(readFileSync(receipt, 'utf8'), 'pending');
      rmSync(receipt);
    }
  }
} finally {
  rmSync(root, {recursive: true, force: true});
}
console.log('Self update retained receipt upgrade/rollback schema gates: PASS');
