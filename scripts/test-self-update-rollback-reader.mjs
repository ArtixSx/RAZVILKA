// Actual rollback shell gates with inert metadata binaries; no daemon or network.
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, rmdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, dirname, basename, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'razvilka-rollback-reader-'));
const shell = process.argv[2] || 'sh';
const fileLimit = spawnSync(shell, ['-c', 'ulimit -f 128'], {encoding: 'utf8', timeout: 5000});
assert.ifError(fileLimit.error);
const limitModel = fileLimit.status === 0 ? '' : 'ulimit() { return 0; }\n';
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
const source = readFileSync(new URL('./rollback-entware.sh', import.meta.url), 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('probe_self_update_metadata() (\n');
const end = source.indexOf('require_node_history_compatibility() {\n', start);
assert(start >= 0 && end > start);
const gates = source.slice(start, end);
const stop = source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
const recovery = source.indexOf(' -recover-private-restore', stop);
const deactivate = source.indexOf(' -deactivate-dataplane', recovery);
const first = source.indexOf('require_target_self_update_compatibility "$BACKUP/razvilka.bin"', end);
const second = source.indexOf('require_target_self_update_compatibility "$BACKUP/razvilka.bin"', stop);
const third = source.indexOf('require_target_self_update_compatibility "$BACKUP/razvilka.bin"', recovery);
assert(first > end && first < stop && second > stop && second < recovery && third > recovery && third < deactivate);
assert(!gates.includes('WithSelfUpdateEffectAdmission'));

mkdirSync(join(root, 'bin'));
const binary = join(root, 'bin', 'razvilka');
const legacy = "printf 'flag provided but not defined: %s\\n' \"$1\" >&2; exit 2";
const fixture = (reader, schema = "printf '0\\n'", scanner = "printf '{\"ok\":true}\\n'") => {
  writeFileSync(binary, '#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 99\ncase "$1" in\n' +
    '-self-update-read-version) ' + reader + ' ;;\n' +
    '-self-update-schema) ' + schema + ' ;;\n' +
    '-check-self-update-state) printf scan >> "$CASE_ROOT/scans"; ' + scanner + ' ;;\n' +
    '*) exit 99 ;;\nesac\n', {mode: 0o700});
};
const run = (body, expected, model = limitModel) => {
  const prefix = 'set -eu\numask 077\nSTATEDIR=' + quote(root.replaceAll('\\', '/')) + '\nBINDIR="$STATEDIR/bin"\n' +
    'CASE_ROOT="$STATEDIR"\nexport CASE_ROOT\n' + model + gates + '\n';
  const result = spawnSync(shell, ['-s'], {
    input: prefix + body + '\n', encoding: 'utf8', timeout: 10000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, expected, result.stdout + result.stderr);
  assert(!readdirSync(root).some(name => name.startsWith('.rollback-reader.')), 'metadata probe left temporary files');
  return result;
};

try {
  fixture(legacy);
  if (fileLimit.status !== 0) run('require_legacy_file_protocol_free', 1, '');
  run('ulimit() { return 1; }\nrequire_legacy_file_protocol_free', 1);
  run('require_legacy_file_protocol_free', 0);
  fixture("printf 'flag provided but not defined: -self-update-read-version\\nUsage of old controller:\\n' >&2; awk 'BEGIN {for(i=0;i<16000;i++) printf \"x\"; printf \"\\n\"}' >&2; exit 2");
  run('require_legacy_file_protocol_free', 0);
  for (const reader of [
    "awk 'BEGIN {for(i=0;i<65537;i++) printf \"x\"}'",
    "printf 'flag provided but not defined: -self-update-read-version\\n' >&2; awk 'BEGIN {for(i=0;i<65537;i++) printf \"x\"}' >&2; exit 2",
  ]) {
    fixture(reader);
    run('require_legacy_file_protocol_free', 1);
  }
  fixture(legacy, legacy);
  run('require_legacy_file_protocol_free', 0);
  fixture(legacy, "printf '1\\n'");
  run('require_legacy_file_protocol_free', 0);
  fixture(legacy, "printf '2\\n'");
  run('require_legacy_file_protocol_free', 1);
  for (const reader of [
    "printf '3\\n'", "printf '2\\n'", "printf '4\\n'", "printf '0\\n'", "printf '03\\n'",
    "printf ' 3\\n'", "printf '3'", "printf '3\\n\\n'", "printf 'garbage\\n'", 'exit 0',
    "printf '3\\n'; printf warning >&2", 'exit 99',
    "printf 'flag provided but not defined: -self-update-read-version' >&2; exit 2",
    "printf noise; " + legacy,
  ]) {
    fixture(reader);
    run('require_legacy_file_protocol_free', 1);
  }
  assert(!readdirSync(root).includes('scans'), 'installed reader3 unexpectedly scanned or granted raw replacement');
  fixture(legacy, 'exit 99');
  run('require_legacy_file_protocol_free', 1);
  fixture(legacy, "printf '0' ");
  run('require_legacy_file_protocol_free', 1);
  fixture('sleep 20');
  const began = Date.now();
  run('require_legacy_file_protocol_free', 1);
  assert(Date.now() - began < 9000, 'metadata timeout did not bound refusal');

  fixture(legacy);
  for (const directory of ['self-update', 'self-update-files']) {
    mkdirSync(join(root, directory));
    run('require_legacy_file_protocol_free', 0); // Empty roots carry no protocol data.
    run('ls() { return 1; }\nrequire_legacy_file_protocol_free', 1);
    for (const entry of ['retained-job', '.hidden-receipt']) {
      const path = join(root, directory, entry);
      writeFileSync(path, 'preserve-retained-reader3');
      run('require_legacy_file_protocol_free', 1);
      assert.equal(readFileSync(path, 'utf8'), 'preserve-retained-reader3');
      rmSync(path);
    }
    rmdirSync(join(root, directory));
  }
  run('require_legacy_file_protocol_free\nmkdir "$STATEDIR/self-update-files"\nprintf late > "$STATEDIR/self-update-files/job"\nrequire_legacy_file_protocol_free', 1);
  assert.equal(readFileSync(join(root, 'self-update-files', 'job'), 'utf8'), 'late');
  rmSync(join(root, 'self-update-files', 'job'));
  rmdirSync(join(root, 'self-update-files'));

  fixture("printf '3\\n'");
  run('require_target_self_update_compatibility "$BINDIR/razvilka"', 0);
  assert.equal(readFileSync(join(root, 'scans'), 'utf8'), 'scan');
  for (const scanner of ["printf '{\"ok\":false}\\n'; exit 1", "printf '{\"ok\":true}'", "printf '{\"ok\":true}\\n'; printf warning >&2", legacy]) {
    fixture("printf '3\\n'", "printf '0\\n'", scanner);
    run('require_target_self_update_compatibility "$BINDIR/razvilka"', 1);
  }
  fixture(legacy);
  const scans = readFileSync(join(root, 'scans'), 'utf8');
  run('require_target_self_update_compatibility "$BINDIR/razvilka"', 0);
  assert.equal(readFileSync(join(root, 'scans'), 'utf8'), scans, 'legacy flag absence was promoted to a scanner');
  fixture("printf '3\\n'", "printf '0\\n'", "if [ -e \"$CASE_ROOT/late\" ]; then exit 1; fi; printf '{\"ok\":true}\\n'");
  run('require_target_self_update_compatibility "$BINDIR/razvilka"\nprintf changed > "$STATEDIR/late"\nrequire_target_self_update_compatibility "$BINDIR/razvilka"', 1);
  assert.equal(readFileSync(join(root, 'late'), 'utf8'), 'changed');
} finally {
  assert.equal(dirname(resolve(root)), resolve(tmpdir()));
  assert(basename(root).startsWith('razvilka-rollback-reader-'));
  rmSync(root, {recursive: true, force: true});
}
console.log('Rollback immutable reader3 fence, strict bounded metadata and retained rechecks: PASS' + (fileLimit.status === 0 ? '' : ' (successful RLIMIT capture modeled; actual unavailable limit refuses)'));
