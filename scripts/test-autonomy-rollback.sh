#!/bin/sh
set -eu
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) echo 'SKIP autonomy rollback: requires Unix permissions and symlinks'; exit 0 ;;
esac
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-autonomy-rollback.XXXXXX")"
cleanup() {
  case "$TEST_ROOT" in "$TMP_BASE"/razvilka-autonomy-rollback.*) rm -rf "$TEST_ROOT" ;; *) exit 1 ;; esac
}
trap cleanup EXIT HUP INT TERM

# Inert binaries/init scripts; these tests never change router networking.
for MODE in present absent legacy legacy-unsupported missing unsafe-dir unsafe-file invalid; do
  BASE="$TEST_ROOT/$MODE"
  APPDIR="$BASE/etc/razvilka"
  STATE="$APPDIR/config.json.automation.json.autonomy.json"
  BACKUP="$BASE/var/lib/razvilka/update-backups/before"
  mkdir -p "$BACKUP" "$BASE/bin" "$BASE/etc/init.d" "$APPDIR"
  echo new-state >"$STATE"
  echo retained >"$APPDIR/unrelated"
  cat >"$BASE/bin/razvilka" <<'BINARY'
#!/bin/sh
if [ "${1:-}" = -check-autonomy-state ]; then
  [ "$AUTONOMY_TEST_MODE" != legacy-unsupported ] || exit 1
  printf '%s\n' '{"ok":true}'
fi
BINARY
  cp "$BASE/bin/razvilka" "$BACKUP/razvilka.bin"
  cat >"$BASE/etc/init.d/S99razvilka" <<'INIT'
#!/bin/sh
set -eu
echo "$1" >>"$RAZVILKA_BASE/service-actions"
if [ "$1" = start ]; then
  STATE="$RAZVILKA_BASE/etc/razvilka/config.json.automation.json.autonomy.json"
  case "$AUTONOMY_TEST_MODE" in
    present) [ "$(cat "$STATE")" = old-state ] ;;
    absent) [ ! -e "$STATE" ] ;;
    legacy) [ "$(cat "$STATE")" = new-state ] ;;
  esac
fi
INIT
  cp "$BASE/etc/init.d/S99razvilka" "$BACKUP/S99razvilka"
  chmod 700 "$BASE/bin/razvilka" "$BASE/etc/init.d/S99razvilka" "$BACKUP/razvilka.bin"
  cat >"$BACKUP/manifest" <<'MANIFEST'
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
  case "$MODE" in
    absent) echo AUTONOMY_STATE_PRESENT=0 >>"$BACKUP/manifest" ;;
    legacy|legacy-unsupported) ;;
    invalid) echo AUTONOMY_STATE_PRESENT=2 >>"$BACKUP/manifest" ;;
    *) echo AUTONOMY_STATE_PRESENT=1 >>"$BACKUP/manifest"; echo old-state >"$BACKUP/autonomy-state.json" ;;
  esac
  case "$MODE" in
    missing) rm "$BACKUP/autonomy-state.json" ;;
    unsafe-dir) mv "$APPDIR" "$BASE/external-app"; ln -s "$BASE/external-app" "$APPDIR" ;;
    unsafe-file) mv "$STATE" "$BASE/external-state"; ln -s "$BASE/external-state" "$STATE" ;;
  esac
  if AUTONOMY_TEST_MODE="$MODE" RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/rollback-entware.sh" "$BACKUP" >"$BASE/result" 2>&1; then
    case "$MODE" in present|absent|legacy) ;; *) echo "Unsafe rollback accepted: $MODE"; exit 1 ;; esac
    grep -q '^start$' "$BASE/service-actions"
    [ "$(cat "$APPDIR/unrelated")" = retained ]
    if [ "$MODE" = present ]; then [ "$(ls -ld "$STATE" | awk '{print $1}')" = -rw------- ]; fi
  else
    case "$MODE" in legacy-unsupported|missing|unsafe-dir|unsafe-file|invalid) ;; *) cat "$BASE/result"; exit 1 ;; esac
    [ ! -e "$BASE/service-actions" ] || { echo "Refusal came after stopping service: $MODE"; exit 1; }
  fi
  echo "PASS autonomy rollback $MODE"
done
awk '/^backup_file\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/backup-function.sh"
grep '^backup_file "\$APPDIR/config.json.automation.json.autonomy.json" autonomy-state.json$' "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/backup-call.sh"
grep -q '^AUTONOMY_STATE_PRESENT=\$AUTONOMY_STATE_PRESENT$' "$ROOT/scripts/upgrade-entware.sh"
APPDIR="$TEST_ROOT/present/etc/razvilka"
BACKUP="$TEST_ROOT/snapshot"
mkdir "$BACKUP"
. "$TEST_ROOT/backup-function.sh"
. "$TEST_ROOT/backup-call.sh"
cmp "$APPDIR/config.json.automation.json.autonomy.json" "$BACKUP/autonomy-state.json"
echo 'PASS upgrade snapshots exact autonomy state before starting candidate'
