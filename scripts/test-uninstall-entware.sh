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

assert_retained_in() {
  # $1 holds etc/razvilka, $2 holds the private razvilka tree.
  [ "$(cat "$1/config.json")" = current-settings ] &&
    [ "$(cat "$1/admin.credentials.json")" = current-credentials ] &&
    [ "$(cat "$1/nodes-private/nodes.private.json")" = current-nodes ] &&
    [ "$(cat "$2/state/update-backups/previous/razvilka.bin")" = old-binary ] &&
    [ "$(cat "$2/state/self-update-stop/ledger")" = control-ledger ] || { echo "Removal changed retained private data/backup: $CASE" >&2; exit 1; }
}

for CASE in success foreign-shared-var symlink-base stop-failed recovery-failed deactivate-failed missing-binary unsafe-directory \
  legacy-layout legacy-leftover purge purge-after-uninstall purge-legacy-leftover purge-running purge-from-inside purge-legacy-link; do
  [ "$CASE" != symlink-base ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  [ "$CASE" != purge-legacy-link ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  BASE="$TEST_ROOT/$CASE"
  mkdir -p "$BASE/var"
  printf keep-foreign >"$BASE/var/other-app.conf"
  if [ "$CASE" = foreign-shared-var ] && [ "$NATIVE_LINKS" -eq 1 ] && [ "$(id -u)" = 0 ]; then
    chown 1001 "$BASE/var"
  fi
  mkdir -p "$BASE/bin" "$BASE/etc/init.d" "$BASE/etc/razvilka/nodes-private" "$BASE/razvilka/state/update-backups/previous" \
    "$BASE/razvilka/state/self-update-stop"
  printf '%s\n' "$BASE/razvilka/state/update-backups/previous" >"$BASE/razvilka/state/current-backup"
  printf '%s\n' old-binary >"$BASE/razvilka/state/update-backups/previous/razvilka.bin"
  printf '%s\n' control-ledger >"$BASE/razvilka/state/self-update-stop/ledger"
  printf '%s\n' current-settings >"$BASE/etc/razvilka/config.json"
  printf '%s\n' current-credentials >"$BASE/etc/razvilka/admin.credentials.json"
  printf '%s\n' current-nodes >"$BASE/etc/razvilka/nodes-private/nodes.private.json"
  printf '%s\n' foreign-init >"$BASE/etc/init.d/S50other-app"
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
  # Process absence is proved by pidof; only purge-running sees a survivor.
  cat >"$BASE/bin/pidof" <<'PIDOF'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = razvilka ] || exit 97
[ "$CASE" = purge-running ] || exit 1
printf '%s\n' 4242
PIDOF
  chmod 700 "$BASE/etc/init.d/S99razvilka" "$BASE/bin/razvilka" "$BASE/bin/pidof"
  case "$CASE" in
    missing-binary) rm "$BASE/bin/razvilka" ;;
    unsafe-directory) mv "$BASE/bin" "$BASE/other-bin"; printf unsafe >"$BASE/bin" ;;
    legacy-layout)
      # <=0.19 layout: routes are recorded only below var/lib/razvilka.
      rm -rf "$BASE/razvilka"
      mkdir -p "$BASE/var/lib/razvilka/dataplane"
      printf '%s\n' legacy-routes >"$BASE/var/lib/razvilka/dataplane/state.json" ;;
    legacy-leftover|purge-legacy-leftover)
      mkdir -p "$BASE/var/lib/razvilka"
      printf '%s\n' legacy-leftover >"$BASE/var/lib/razvilka/marker" ;;
    purge-legacy-link)
      mkdir -p "$BASE/var/lib" "$TEST_ROOT/foreign-$CASE"
      printf '%s\n' foreign >"$TEST_ROOT/foreign-$CASE/marker"
      ln -s "$TEST_ROOT/foreign-$CASE" "$BASE/var/lib/razvilka" ;;
  esac
  FOREIGN_BEFORE="$(ls -nd "$BASE/var")"
  export CASE
  RUN_BASE="$BASE"
  if [ "$CASE" = symlink-base ]; then
    RUN_BASE="$TEST_ROOT/base-link"
    ln -s "$BASE" "$RUN_BASE"
  fi
  SCRIPT="$ROOT/scripts/uninstall-entware.sh"
  if [ "$CASE" = purge-from-inside ]; then
    # A release extracted into the private cache would move itself away.
    mkdir -p "$BASE/razvilka/cache/release/scripts"
    cp "$SCRIPT" "$BASE/razvilka/cache/release/scripts/uninstall-entware.sh"
    SCRIPT="$BASE/razvilka/cache/release/scripts/uninstall-entware.sh"
  fi
  set --
  case "$CASE" in purge|purge-*) set -- --purge ;; esac
  if [ "$CASE" = purge-after-uninstall ]; then
    RAZVILKA_BASE="$RUN_BASE" sh "$SCRIPT" >"$BASE/first-output" 2>&1 || { cat "$BASE/first-output"; exit 1; }
    [ ! -e "$BASE/bin/razvilka" ] && [ -f "$BASE/etc/razvilka/config.json" ] || { echo "Plain uninstall did not keep data" >&2; exit 1; }
  fi
  CODE=0
  RAZVILKA_BASE="$RUN_BASE" sh "$SCRIPT" "$@" >"$BASE/output" 2>&1 || CODE=$?
  CALLS=""
  [ ! -f "$BASE/calls" ] || CALLS="$(tr '\n' ',' <"$BASE/calls")"
  case "$CASE" in
    success|foreign-shared-var|symlink-base|legacy-leftover)
      [ "$CODE" = 0 ] && [ ! -e "$BASE/bin/razvilka" ] && [ ! -e "$BASE/etc/init.d/S99razvilka" ] || { cat "$BASE/output"; exit 1; }
      [ "$CALLS" = stop,recovery,deactivate, ] || { echo "Uninstall did not stop/recover/deactivate in order" >&2; exit 1; }
      # A second removal must be harmless, even though the saved upgrade snapshot exists.
      RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/uninstall-entware.sh" >/dev/null
      assert_retained_in "$BASE/etc/razvilka" "$BASE/razvilka"
      if [ "$CASE" = legacy-leftover ]; then
        [ "$(cat "$BASE/var/lib/razvilka/marker")" = legacy-leftover ] || { echo "Plain uninstall touched legacy data" >&2; exit 1; }
      fi
      ;;
    legacy-layout)
      # Refused before Stop: deactivating an empty 0.20 state and deleting the
      # binary would orphan the routes recorded by the older generation.
      [ "$CODE" = 1 ] && [ -z "$CALLS" ] && [ -x "$BASE/bin/razvilka" ] && [ -f "$BASE/etc/init.d/S99razvilka" ] &&
        grep -q '^Pre-0.20 RAZVILKA layout found' "$BASE/output" && grep -q 'RAZVILKA_VERSION=v' "$BASE/output" || {
        echo "Pre-0.20 layout was removed by the 0.20 uninstaller" >&2; cat "$BASE/output" >&2; exit 1;
      }
      [ "$(cat "$BASE/var/lib/razvilka/dataplane/state.json")" = legacy-routes ] && [ ! -e "$BASE/razvilka" ] || {
        echo "Pre-0.20 refusal changed legacy state or created 0.20 state" >&2; exit 1;
      }
      ;;
    purge|purge-after-uninstall|purge-legacy-leftover)
      [ "$CODE" = 0 ] && [ ! -e "$BASE/bin/razvilka" ] && [ ! -e "$BASE/etc/init.d/S99razvilka" ] || { cat "$BASE/output"; exit 1; }
      [ "$CALLS" = stop,recovery,deactivate, ] || { echo "Purge did not deactivate exactly once before moving data ($CALLS)" >&2; exit 1; }
      [ ! -e "$BASE/etc/razvilka" ] && [ ! -e "$BASE/razvilka" ] && [ ! -e "$BASE/var/lib/razvilka" ] || {
        echo "Purge left RAZVILKA data in place" >&2; exit 1;
      }
      set -- "$BASE"/razvilka-removed-*
      [ "$#" -eq 1 ] && [ -d "$1" ] || { echo "Purge did not create exactly one removed-data folder" >&2; exit 1; }
      REMOVED="$1"
      case "${REMOVED##*/}" in
        razvilka-removed-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
        *) echo "Removed-data folder is not UTC-stamped: $REMOVED" >&2; exit 1 ;;
      esac
      if [ "$NATIVE_LINKS" -eq 1 ]; then
        [ "$(ls -nd "$REMOVED" | awk '{print $1}')" = drwx------ ] || { echo "Removed-data folder is not private" >&2; exit 1; }
      fi
      assert_retained_in "$REMOVED/etc-razvilka" "$REMOVED/razvilka"
      if [ "$CASE" = purge-legacy-leftover ]; then
        [ "$(cat "$REMOVED/var-lib-razvilka/marker")" = legacy-leftover ] || { echo "Legacy data was not moved intact" >&2; exit 1; }
      fi
      [ -d "$BASE/bin" ] && [ -d "$BASE/etc/init.d" ] && [ "$(cat "$BASE/etc/init.d/S50other-app")" = foreign-init ] || {
        echo "Purge removed Entware directories or a foreign service" >&2; exit 1;
      }
      # Repeating purge finds nothing to move and never creates another folder.
      RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/uninstall-entware.sh" --purge >"$BASE/repeat-output" 2>&1 || { cat "$BASE/repeat-output"; exit 1; }
      set -- "$BASE"/razvilka-removed-*
      [ "$#" -eq 1 ] || { echo "Repeated purge created another folder" >&2; exit 1; }
      ;;
    purge-running)
      # Removal itself completed; a surviving writer keeps every byte in place.
      [ "$CODE" = 1 ] && [ "$CALLS" = stop,recovery,deactivate, ] && [ ! -e "$BASE/bin/razvilka" ] || {
        echo "Running process check did not stop purge after removal" >&2; cat "$BASE/output" >&2; exit 1;
      }
      assert_retained_in "$BASE/etc/razvilka" "$BASE/razvilka"
      set -- "$BASE"/razvilka-removed-*
      [ ! -e "$1" ] || { echo "Purge created a folder while a writer was running" >&2; exit 1; }
      ;;
    purge-from-inside|purge-legacy-link)
      [ "$CODE" = 1 ] && [ -z "$CALLS" ] && [ -x "$BASE/bin/razvilka" ] && [ -f "$BASE/etc/init.d/S99razvilka" ] || {
        echo "Unsafe purge started removal: $CASE" >&2; cat "$BASE/output" >&2; exit 1;
      }
      assert_retained_in "$BASE/etc/razvilka" "$BASE/razvilka"
      if [ "$CASE" = purge-legacy-link ]; then
        [ "$(cat "$TEST_ROOT/foreign-$CASE/marker")" = foreign ] && [ -L "$BASE/var/lib/razvilka" ] || { echo "Purge followed a legacy link" >&2; exit 1; }
      fi
      ;;
    *)
      [ "$CODE" != 0 ] && [ -f "$BASE/etc/init.d/S99razvilka" ] || { echo "Failed cleanup deleted supervisor: $CASE" >&2; exit 1; }
      case "$CASE" in
        stop-failed) EXPECTED=stop, ;;
        recovery-failed) EXPECTED=stop,recovery, ;;
        deactivate-failed) EXPECTED=stop,recovery,deactivate, ;;
        *) EXPECTED= ;;
      esac
      [ "$CALLS" = "$EXPECTED" ] || { echo "Unsafe uninstall continued: $CASE ($CALLS)" >&2; exit 1; }
      if [ "$CASE" != missing-binary ] && [ "$CASE" != unsafe-directory ]; then
        [ -x "$BASE/bin/razvilka" ] || { echo "Failed uninstall removed repair binary" >&2; exit 1; }
      fi
      assert_retained_in "$BASE/etc/razvilka" "$BASE/razvilka"
      ;;
  esac
  [ "$(cat "$BASE/var/other-app.conf")" = keep-foreign ] && [ "$(ls -nd "$BASE/var")" = "$FOREIGN_BEFORE" ] || {
    echo "Uninstall changed shared Entware /var metadata or bytes" >&2; exit 1;
  }
done
for BAD_BASE in / relative; do
  if RAZVILKA_BASE="$BAD_BASE" sh "$ROOT/scripts/uninstall-entware.sh" >/dev/null 2>&1; then
    echo "Unsafe base accepted: $BAD_BASE" >&2; exit 1
  fi
done
mkdir -p "$TEST_ROOT/options"
for BAD_OPTIONS in '--purge --purge' --force '--purge extra' ''; do
  CODE=0
  # shellcheck disable=SC2086 # Deliberately split the option list.
  if [ -n "$BAD_OPTIONS" ]; then set -- $BAD_OPTIONS; else set -- ''; fi
  RAZVILKA_BASE="$TEST_ROOT/options" sh "$ROOT/scripts/uninstall-entware.sh" "$@" >/dev/null 2>&1 || CODE=$?
  [ "$CODE" = 2 ] || { echo "Ambiguous uninstall options accepted: '$BAD_OPTIONS' ($CODE)" >&2; exit 1; }
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
