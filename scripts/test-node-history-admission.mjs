import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

for (const name of ['upgrade-entware.sh', 'rollback-entware.sh']) {
  const source = readFileSync(new URL(name, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
  const start = source.indexOf('require_node_history_compatibility() {\n');
  const end = source.indexOf('\n}\n', start);
  assert(start >= 0 && end > start);
  const gate = source.slice(start, end + 3);
  const stop = source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
  const firstCall = source.indexOf('require_node_history_compatibility "', end);
  const lastCall = source.lastIndexOf('require_node_history_compatibility "');
  assert(firstCall < stop && lastCall > stop, 'target compatibility must precede and follow stop');
  assert(lastCall < source.indexOf('restore_or_remove()', stop) || name === 'upgrade-entware.sh');
  const run = (body, expected) => {
    const result = spawnSync(process.argv[2] || 'sh', ['-s'], {
      input: 'set -eu\nAPPDIR=/trusted/config\nSTATEDIR=/trusted/state\n' + gate + '\n' + body + '\n',
      encoding: 'utf8', timeout: 5000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, expected, result.stderr + result.stdout);
    return result;
  };
  run('old_binary() { return 2; }\nrequire_node_history_compatibility old_binary', 1);
  run('version_flag_only() { printf "2\\n"; }\nrequire_node_history_compatibility version_flag_only', 1);
  run('unreadable_history() { printf \'{"ok":false}\\n\'; }\nrequire_node_history_compatibility unreadable_history', 1);
  run('target() { [ "$1" = -check-node-history-state ] && [ "$2" = -node-history-config-root ] && [ "$3" = "$APPDIR" ] && [ "$4" = -node-history-state-root ] && [ "$5" = "$STATEDIR" ] || return 2; printf \'{"ok":true}\\n\'; }\nrequire_node_history_compatibility target', 0);
  run('target() { [ "$READABLE" = yes ] || return 2; printf \'{"ok":true}\\n\'; }\nREADABLE=yes\nrequire_node_history_compatibility target\nREADABLE=no\nrequire_node_history_compatibility target', 1);
}
console.log('Retained node history target downgrade consumers before/after Stop: PASS');
