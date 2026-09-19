#!/bin/sh
# Entirely isolated stop/recovery/deactivation fixtures; no real daemon or routes.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
NATIVE_LINKS=1
case "$(uname -s)" in MINGW*|MSYS*) NATIVE_LINKS=0 ;; esac
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-uninstall.XXXXXX")"
cleanup() { case "$TEST_ROOT" in "$TMP_BASE"/razvilka-uninstall.*) rm -rf "$TEST_ROOT" ;; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for CASE in success symlink-base stop-failed recovery-failed deactivate-failed missing-binary unsafe-directory; do
  [ "$CASE" != symlink-base ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  BASE="$TEST_ROOT/$CASE"
  mkdir -p "$BASE/bin" "$BASE/etc/init.d" "$BASE/etc/razvilka/nodes-private" "$BASE/var/lib/razvilka/update-backups/previous"
  printf '%s\n' "$BASE/var/lib/razvilka/update-backups/previous" >"$BASE/var/lib/razvilka/current-backup"
  printf '%s\n' old-binary >"$BASE/var/lib/razvilka/update-backups/previous/razvilka.bin"
  printf '%s\n' current-settings >"$BASE/etc/razvilka/config.json"
  printf '%s\n' current-credentials >"$BASE/etc/razvilka/admin.credentials.json"
  printf '%s\n' current-nodes >"$BASE/etc/razvilka/nodes-private/nodes.private.json"
  cat >"$BASE/etc/init.d/S99razvilka" <<'INIT'
#!/bin/sh
set -eu
[ "$1" = stop ] || exit 97
printf '%s\n' stop >>"$RAZVILKA_BASE/calls"
[ "$CASE" != stop-failed ] || exit 42
INIT
  cat >"$BASE/bin/razvilka" <<'BINARY'
#!/bin/sh
set -eu
case "$1" in
  -recover-private-restore)
    printf '%s\n' recovery >>"$RAZVILKA_BASE/calls"
    [ "$CASE" != recovery-failed ] || exit 43
    printf '%s\n' '{"ok":true}'
    ;;
  -deactivate-dataplane)
    printf '%s\n' deactivate >>"$RAZVILKA_BASE/calls"
    [ "$CASE" != deactivate-failed ] || exit 44
    ;;
  *) exit 98 ;;
esac
BINARY
  chmod 700 "$BASE/etc/init.d/S99razvilka" "$BASE/bin/razvilka"
  case "$CASE" in
    missing-binary) rm "$BASE/bin/razvilka" ;;
    unsafe-directory) mv "$BASE/bin" "$BASE/other-bin"; printf unsafe >"$BASE/bin" ;;
  esac
  export CASE
  RUN_BASE="$BASE"
  if [ "$CASE" = symlink-base ]; then
    RUN_BASE="$TEST_ROOT/base-link"
    ln -s "$BASE" "$RUN_BASE"
  fi
  CODE=0
  RAZVILKA_BASE="$RUN_BASE" sh "$ROOT/scripts/uninstall-entware.sh" >"$BASE/output" 2>&1 || CODE=$?
  if [ "$CASE" = success ] || [ "$CASE" = symlink-base ]; then
    [ "$CODE" = 0 ] && [ ! -e "$BASE/bin/razvilka" ] && [ ! -e "$BASE/etc/init.d/S99razvilka" ] || { cat "$BASE/output"; exit 1; }
    [ "$(tr '\n' ',' <"$BASE/calls")" = stop,recovery,deactivate, ] || { echo "Uninstall did not stop/recover/deactivate in order" >&2; exit 1; }
    # A second removal must be harmless, even though the saved upgrade snapshot exists.
    RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/uninstall-entware.sh" >/dev/null
  else
    [ "$CODE" != 0 ] && [ -f "$BASE/etc/init.d/S99razvilka" ] || { echo "Failed cleanup deleted supervisor: $CASE" >&2; exit 1; }
    case "$CASE" in
      stop-failed) EXPECTED=stop, ;;
      recovery-failed) EXPECTED=stop,recovery, ;;
      deactivate-failed) EXPECTED=stop,recovery,deactivate, ;;
      *) EXPECTED= ;;
    esac
    ACTUAL=""
    [ ! -f "$BASE/calls" ] || ACTUAL="$(tr '\n' ',' <"$BASE/calls")"
    [ "$ACTUAL" = "$EXPECTED" ] || { echo "Unsafe uninstall continued: $CASE ($ACTUAL)" >&2; exit 1; }
    if [ "$CASE" != missing-binary ] && [ "$CASE" != unsafe-directory ]; then
      [ -x "$BASE/bin/razvilka" ] || { echo "Failed uninstall removed repair binary" >&2; exit 1; }
    fi
  fi
  [ "$(cat "$BASE/etc/razvilka/config.json")" = current-settings ] &&
    [ "$(cat "$BASE/etc/razvilka/admin.credentials.json")" = current-credentials ] &&
    [ "$(cat "$BASE/etc/razvilka/nodes-private/nodes.private.json")" = current-nodes ] &&
    [ "$(cat "$BASE/var/lib/razvilka/update-backups/previous/razvilka.bin")" = old-binary ] || { echo "Removal changed retained private data/backup" >&2; exit 1; }
done
for BAD_BASE in / relative; do
  if RAZVILKA_BASE="$BAD_BASE" sh "$ROOT/scripts/uninstall-entware.sh" >/dev/null 2>&1; then
    echo "Unsafe base accepted: $BAD_BASE" >&2; exit 1
  fi
done
if [ "$NATIVE_LINKS" -eq 1 ]; then
  ln -s / "$TEST_ROOT/root-link"
  for SCRIPT in bootstrap.sh upgrade-entware.sh rollback-entware.sh uninstall-entware.sh; do
    if RAZVILKA_BASE="$TEST_ROOT/root-link" sh "$ROOT/scripts/$SCRIPT" >/dev/null 2>&1; then
      echo "Canonical filesystem root accepted: $SCRIPT" >&2; exit 1
    fi
  done
fi
echo "Isolated Entware uninstall tests: PASS"
