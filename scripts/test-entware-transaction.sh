#!/bin/sh
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
UPGRADE="$ROOT/scripts/upgrade-entware.sh"
ROLLBACK="$ROOT/scripts/rollback-entware.sh"
UNINSTALL="$ROOT/scripts/uninstall-entware.sh"
DAEMON="$(command -v start-stop-daemon || true)"
[ -n "$DAEMON" ] && [ -x "$DAEMON" ] || {
  echo "start-stop-daemon is required for the Entware transaction test" >&2
  exit 1
}
command -v ip >/dev/null 2>&1 || { echo "ip is required for the Entware transaction test" >&2; exit 1; }

TMP_BASE="${TMPDIR:-/tmp}"
[ -d "$TMP_BASE" ] || { echo "Temporary directory is unavailable: $TMP_BASE" >&2; exit 1; }
TMP_BASE="$(CDPATH= cd -- "$TMP_BASE" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-transaction.XXXXXX")"
PORT=$((18000 + ($$ % 10000)))
PRIMARY="$TEST_ROOT/primary"
CONFLICT="$TEST_ROOT/conflict"
REMOVAL="$TEST_ROOT/uninstall"
MARKER="$TEST_ROOT/manifest-executed"

cleanup() {
  for BASE in "$PRIMARY" "$CONFLICT" "$REMOVAL"; do
    INIT="$BASE/etc/init.d/S99razvilka"
    if [ -x "$INIT" ]; then
      RAZVILKA_BASE="$BASE" RAZVILKA_PORT="$PORT" "$INIT" stop >/dev/null 2>&1 || true
    fi
  done
  case "$TEST_ROOT" in
    "$TMP_BASE"/razvilka-transaction.*) rm -rf "$TEST_ROOT" ;;
    *) echo "Refusing unsafe test cleanup: $TEST_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

prepare_root() {
  BASE="$1"
  mkdir -p "$BASE/sbin"
  ln -s "$DAEMON" "$BASE/sbin/start-stop-daemon"
}

assert_absent() {
  [ ! -e "$1" ] || { echo "Expected path to be absent: $1" >&2; exit 1; }
}

prepare_root "$PRIMARY"
prepare_root "$CONFLICT"
prepare_root "$REMOVAL"

RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$UPGRADE" --dry-run >/dev/null
assert_absent "$PRIMARY/bin/razvilka"
assert_absent "$PRIMARY/etc/init.d/S99razvilka"

RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 \
  "$UPGRADE" --apply >/dev/null
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" \
  "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null

PRIMARY_BACKUP="$(cat "$PRIMARY/var/lib/razvilka/current-backup")"
[ -d "$PRIMARY_BACKUP" ] || { echo "Primary rollback snapshot is missing" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP" | awk '{print $1}')" = drwx------ ] || { echo "Snapshot mode is not 700" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP/manifest" | awk '{print $1}')" = -rw------- ] || { echo "Manifest mode is not 600" >&2; exit 1; }

# A same-version upgrade must preserve committed adapter metadata that is
# temporarily removed by controlled dataplane deactivation.
mkdir -p "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter"
printf '%s\n' preserved >"$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 \
  "$UPGRADE" --apply --without-components >/dev/null
[ "$(cat "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker")" = preserved ] || {
  echo "Dataplane runtime snapshot was not restored after upgrade" >&2
  exit 1
}
SECOND_BACKUP="$(cat "$PRIMARY/var/lib/razvilka/current-backup")"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$SECOND_BACKUP" >/dev/null
[ "$(cat "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker")" = preserved ] || {
  echo "Dataplane runtime snapshot was not restored by rollback" >&2
  exit 1
}

# The second instance cannot bind to the occupied port. It must fail and remove
# every newly installed target through the automatic rollback trap.
if RAZVILKA_BASE="$CONFLICT" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=2 \
  "$UPGRADE" --apply >/dev/null 2>&1; then
  echo "Conflicting upgrade unexpectedly succeeded" >&2
  exit 1
fi
assert_absent "$CONFLICT/bin/razvilka"
assert_absent "$CONFLICT/etc/init.d/S99razvilka"
assert_absent "$CONFLICT/etc/razvilka/config.json"
assert_absent "$CONFLICT/etc/razvilka/community-catalog.json"

# A manifest is data, never shell. Unknown keys are rejected before a service
# is stopped, and embedded command substitution must remain literal.
MALICIOUS="$PRIMARY/var/lib/razvilka/update-backups/malicious-test"
cp -a "$PRIMARY_BACKUP" "$MALICIOUS"
printf 'EVIL=$(touch %s)\n' "$MARKER" >>"$MALICIOUS/manifest"
if RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$MALICIOUS" >/dev/null 2>&1; then
  echo "Malicious manifest unexpectedly passed validation" >&2
  exit 1
fi
assert_absent "$MARKER"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" \
  "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null

# Canonical-path validation rejects traversal even when the textual prefix is
# inside update-backups.
if RAZVILKA_BASE="$PRIMARY" "$ROLLBACK" \
  "$PRIMARY/var/lib/razvilka/update-backups/../.." >/dev/null 2>&1; then
  echo "Rollback path traversal unexpectedly passed validation" >&2
  exit 1
fi

RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$PRIMARY_BACKUP" >/dev/null
assert_absent "$PRIMARY/bin/razvilka"
assert_absent "$PRIMARY/etc/init.d/S99razvilka"
assert_absent "$PRIMARY/etc/razvilka/config.json"
assert_absent "$PRIMARY/etc/razvilka/community-catalog.json"
# Uninstall is rollback-aware: a fresh transactional install has a snapshot,
# so uninstall must restore that snapshot instead of deleting files blindly.
RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 \
  "$UPGRADE" --apply >/dev/null
RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" \
  "$REMOVAL/etc/init.d/S99razvilka" status >/dev/null
RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" "$UNINSTALL" >/dev/null
assert_absent "$REMOVAL/bin/razvilka"
assert_absent "$REMOVAL/etc/init.d/S99razvilka"
assert_absent "$REMOVAL/etc/razvilka/config.json"
assert_absent "$REMOVAL/etc/razvilka/community-catalog.json"


trap - EXIT HUP INT TERM
cleanup
echo "Entware transaction test: OK"
