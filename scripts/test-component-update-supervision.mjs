// Exercise the real bounded installer readers without package/service actions.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-component-schema-'));
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
try {
  const directory = join(root, 'components', 'update-journal');
  const journal = join(directory, 'current.json');
  const binary = join(root, 'reader');
  const calls = join(root, 'calls');
  mkdirSync(directory, {recursive: true});
  for (const name of ['upgrade-entware.sh', 'rollback-entware.sh']) {
    const source = readFileSync(new URL(name, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
    const start = source.indexOf('require_native_enrollment_schema() {\n');
    const end = source.indexOf('\n}\n', start);
    const probeStart = source.indexOf('probe_self_update_metadata() (\n');
    const probeEnd = source.indexOf('\n)\n', probeStart);
    assert(start >= 0 && end > start && probeStart >= 0 && probeEnd > probeStart);
    const gate = source.slice(start, end + 3);
    const probe = source.slice(probeStart, probeEnd + 3);
    const stop = source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
    const firstCheck = source.indexOf('require_native_enrollment_schema "', end);
    const recheck = source.indexOf('require_native_enrollment_schema "', stop);
    assert(firstCheck < stop && recheck > stop, 'gate must run before and after quiescence');
    const shellPath = (value) => value.replaceAll('\\', '/');
    const run = (body, expected) => {
      const result = spawnSync(process.argv[2] || 'sh', ['-s'], {
        input: `set -eu\nBASE="$(CDPATH= cd -- /opt && pwd -P)"\nSTATEDIR=${quote(shellPath(root))}\nAPPDIR="$STATEDIR/config"\nAUTONOMY_STATE_PRESENT=skip\n${probe}\n${gate}\n${body}\n`,
        encoding: 'utf8', timeout: 8000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, expected, name + ': ' + result.stderr + result.stdout);
      return result;
    };
    const candidate = (schemaBody, stateBody) => {
      writeFileSync(calls, '');
      writeFileSync(binary, `#!/bin/sh\nset -eu\n[ "$#" = 1 ] || exit 90\nprintf '%s\\n' "$1" >> ${quote(shellPath(calls))}\ncase "$1" in\n-component-update-schema) ${schemaBody} ;;\n-check-component-update-state) ${stateBody} ;;\n*) exit 91 ;;\nesac\n`);
      chmodSync(binary, 0o700);
    };
    const check = `require_native_enrollment_schema ${quote(shellPath(binary))}`;
    candidate('exit 2', 'exit 2');
    run(check, 0); // No retained receipt does not require this ABI.
    assert.equal(readFileSync(calls, 'utf8'), '');
    writeFileSync(journal, '{"schema_version":2,"phase":"rollback-started","private":"retained"}\n');
    const before = readFileSync(journal);
    assert.match(run(check, 1).stderr, /cannot preserve component update recovery/);
    for (const version of [2, 3, 4]) {
      candidate(`printf '${version}\\n'`, `printf '{"ok":true}\\n'`);
      run(check, 0);
      assert.equal(readFileSync(calls, 'utf8'), '-component-update-schema\n-check-component-update-state\n', 'only exact standalone metadata flags may execute');
      assert.deepEqual(readFileSync(journal), before, 'successful reader must not consume pending receipt');
      candidate(`printf '${version}\\n'`, 'exit 3');
      assert.match(run(check, 1).stderr, /cannot read retained component update state/);
    }
    for (const schema of ['1', '5', 'unknown', '4 extra', '4\\n4']) {
      candidate(`printf '${schema}\\n'`, `printf '{"ok":true}\\n'`);
      run(check, 1);
      assert.equal(readFileSync(calls, 'utf8'), '-component-update-schema\n', 'unknown or malformed schema must not admit a state probe');
    }
    for (const response of [`printf '{"ok":false}\\n'`, `printf '{"ok":true}\\nextra\\n'`, `printf '{"ok":true}'`, `printf '{"ok":true}\\n'; echo private >&2`, `yes invalid | head -c 70000`]) {
      candidate('printf "4\\n"', response);
      const result = run(check, 1);
      assert(!result.stderr.includes('private'), 'candidate diagnostics must not escape the bounded reader');
    }
    candidate('printf "4\\n"', `printf '{"ok":true}\\n'`);
    run(`BASE=/alternate\n${check}`, 1);
    assert.equal(readFileSync(calls, 'utf8'), '', 'fixed-root reader must never admit alternate retained installation');
    assert.deepEqual(readFileSync(journal), before, 'all refused probes must preserve pending receipt');
    rmSync(journal);
    mkdirSync(journal);
    assert.match(run(check, 1).stderr, /journal is unsafe/);
    rmSync(journal, {recursive:true});
    candidate('exit 2', 'exit 2');
    run(`${check}\nprintf pending > "$STATEDIR/components/update-journal/current.json"\n${check}`, 1);
    assert.equal(readFileSync(journal, 'utf8'), 'pending', 'quiescence recheck must see a newly retained receipt');
    rmSync(journal);
  }
} finally {
  rmSync(root, {recursive:true, force:true});
}
console.log('Component update upgrade/rollback schema gates: PASS');
