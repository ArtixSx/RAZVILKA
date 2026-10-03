// Launcher contract only: no Go suite, package manager, VM or service is run.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-native-runner-'));
const posix = value => value.replaceAll('\\', '/').replace(/^([A-Za-z]):\//, (_, drive) => `/${drive.toLowerCase()}/`);
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
try {
  const bin = join(root, 'bin');
  const runtime = join(root, 'pinned runtime');
  mkdirSync(bin);
  mkdirSync(runtime);
  for (const [name, content] of Object.entries({
    uname: '#!/bin/sh\nprintf "Linux\\n"\n',
    opkg: '#!/bin/sh\nexit 99\n',
    ar: '#!/bin/sh\nexit 99\n',
  })) writeFileSync(join(bin, name), content, {mode: 0o755});
  const capture = join(root, 'capture');
  const go = join(runtime, 'go');
  writeFileSync(go, `#!/bin/sh\n{ printf '%s\\n' "$GOTOOLCHAIN" "$GOMAXPROCS" "$GOFLAGS" "$RAZVILKA_NATIVE_OPKG_TEST" "$RAZVILKA_TEST_OPKG"; printf '%s\\n' "$@"; } > ${quote(posix(capture))}\nexit 0\n`, {mode: 0o755});
  const run = (extra = {}) => spawnSync(process.argv[2] || 'sh', ['-s'], {
    input: `PATH=${quote(posix(bin))}:"$PATH"\nexport PATH\nexec sh scripts/test-component-update-native.sh\n`,
    env: {...process.env, GO: posix(go), RAZVILKA_TEST_OPKG: posix(join(bin, 'opkg')), GOMAXPROCS: '', GOFLAGS: '', ...extra},
    encoding: 'utf8', timeout: 5000,
  });
  let result = run();
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.deepEqual(readFileSync(capture, 'utf8').trim().split('\n'), [
    'local', '2', '-p=2', '1', posix(join(bin, 'opkg')),
    'test', './internal/components', '-run', '^TestNativeOpkgManagedUpdateJournal$', '-count=1', '-timeout=3m', '-v',
  ]);
  rmSync(capture);
  result = run({RAZVILKA_TEST_OPKG: posix(join(bin, 'missing-opkg'))});
  assert.ifError(result.error);
  assert.equal(result.status, 2, result.stderr + result.stdout);
  assert.throws(() => readFileSync(capture), /ENOENT/);
} finally {
  rmSync(root, {recursive: true, force: true});
}
console.log('Native opkg launcher pinned runtime/offline opt-in contract: PASS (stubs only)');
