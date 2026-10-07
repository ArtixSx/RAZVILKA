#!/bin/sh
# Real rollback with inert files and service hooks; no live process/network.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-history-rollback.XXXXXX")"
cleanup() {
  case "$TEST_ROOT" in "$TMP_BASE"/razvilka-history-rollback.*) rm -rf "$TEST_ROOT" ;; *) exit 1 ;; esac
}
trap cleanup EXIT HUP INT TERM

for MODE in after-stop after-recovery stop-during-history not-running; do
  BASE="$TEST_ROOT/$MODE"
  STATE="$BASE/var/lib/razvilka"
  BACKUP="$STATE/update-backups/before"
  mkdir -p "$BACKUP" "$BASE/bin" "$BASE/etc/init.d" "$BASE/etc/razvilka"
  printf '%s\n' '{"retained":true}' >"$BASE/etc/razvilka/config.json"
  cat >"$BASE/bin/razvilka" <<'BINARY'
#!/bin/sh
set -eu
STATE="$RAZVILKA_BASE/var/lib/razvilka"
case "${1:-}" in
  -self-update-read-version) printf 'flag provided but not defined: -self-update-read-version\n' >&2; exit 2 ;;
  -self-update-schema) printf '0\n' ;;
  -check-node-history-state)
    [ "$#" = 5 ] && [ "$2" = -node-history-config-root ] && [ "$3" = "$RAZVILKA_BASE/etc/razvilka" ] && [ "$4" = -node-history-state-root ] && [ "$5" = "$STATE" ] || exit 99
    COUNT=0
    [ ! -e "$STATE/history-calls" ] || COUNT="$(cat "$STATE/history-calls")"
    COUNT=$((COUNT + 1))
    printf '%s\n' "$COUNT" >"$STATE/history-calls"
    LIMIT=2
    [ "$HISTORY_TEST_MODE" != after-recovery ] || LIMIT=3
    if [ "$COUNT" -ge "$LIMIT" ]; then
      if [ "$HISTORY_TEST_MODE" = stop-during-history ]; then
        mkdir "$STATE/self-update-stop"
        printf '%s\n' '{"stopped":true}' >"$STATE/self-update-stop/current.json"
      fi
      printf '%s\n' '{"ok":false}'
      exit 1
    fi
    printf '%s\n' '{"ok":true}' ;;
  -recover-private-restore)
    [ "$HISTORY_TEST_MODE" = after-recovery ] || exit 99
    printf '%s\n' observed >"$STATE/recovery-called"
    printf '%s\n' '{"ok":true}' ;;
  -deactivate-dataplane) printf '%s\n' forbidden >"$STATE/deactivate-called"; exit 99 ;;
  *) exit 99 ;;
esac
BINARY
  cat >"$BASE/etc/init.d/S99razvilka" <<'INIT'
#!/bin/sh
set -eu
case "$1" in
  status) [ "$HISTORY_TEST_MODE" != not-running ] ;;
  stop|start) printf '%s\n' "$1" >>"$RAZVILKA_BASE/service-actions" ;;
  *) exit 99 ;;
esac
INIT
  chmod 700 "$BASE/bin/razvilka" "$BASE/etc/init.d/S99razvilka"
  cp "$BASE/bin/razvilka" "$BACKUP/razvilka.bin"
  cp "$BASE/etc/init.d/S99razvilka" "$BACKUP/S99razvilka"
  cp "$BASE/bin/razvilka" "$BASE/current-original"
  cp "$BASE/etc/init.d/S99razvilka" "$BASE/init-original"
  printf '# older controller\n' >>"$BACKUP/razvilka.bin"
  printf '# older init\n' >>"$BACKUP/S99razvilka"
  PRIVATE_PROTOCOL=0
  [ "$MODE" != after-recovery ] || PRIVATE_PROTOCOL=1
  cat >"$BACKUP/manifest" <<MANIFEST
PRIVATE_RESTORE_PROTOCOL=$PRIVATE_PROTOCOL
RAZ_BINARY_PRESENT=1
RAZ_INIT_PRESENT=1
CONFIG_PRESENT=0
CATALOG_PRESENT=0
SOURCES_PRESENT=0
TOKEN_PRESENT=0
LEGACY_INIT_PRESENT=0
LEGACY_DISABLED_PRESENT=0
LEGACY_WAS_RUNNING=0
RAZ_WAS_RUNNING=1
MANIFEST
  if HISTORY_TEST_MODE="$MODE" RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/rollback-entware.sh" "$BACKUP" --auto >"$BASE/result" 2>&1; then
    echo "Unreadable retained history accepted: $MODE" >&2; exit 1
  fi
  grep -q 'Target binary cannot read all retained node history' "$BASE/result"
  cmp "$BASE/bin/razvilka" "$BASE/current-original"
  cmp "$BASE/etc/init.d/S99razvilka" "$BASE/init-original"
  [ "$(cat "$BASE/etc/razvilka/config.json")" = '{"retained":true}' ]
  [ ! -e "$STATE/deactivate-called" ]
  case "$MODE" in
    after-stop|after-recovery) [ "$(cat "$BASE/service-actions")" = "$(printf 'stop\nstart')" ] ;;
    stop-during-history|not-running) [ "$(cat "$BASE/service-actions")" = stop ] ;;
  esac
  if [ "$MODE" = after-recovery ]; then [ "$(cat "$STATE/history-calls")" = 3 ] && [ -e "$STATE/recovery-called" ]; fi
  echo "PASS retained history rollback $MODE"
done
