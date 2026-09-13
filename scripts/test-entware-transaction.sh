#!/bin/sh
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
sh "$ROOT/scripts/test-installer-architecture.sh"
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

# Exercise the production startup/acceptance block and rollback trap together.
# The health CLI's asynchronous observations are covered by Go HTTP tests; here
# its exact supervised PID/strict/wait arguments and exit-75 propagation must
# survive the shell boundary. These fixtures never start a daemon.
test_upgrade_readiness() {
  READINESS_ROOT="$TEST_ROOT/readiness"
  mkdir -p "$READINESS_ROOT"
  awk '/^rollback_on_error\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' \
    "$UPGRADE" >"$READINESS_ROOT/rollback-function.sh"
  awk '/^stage 6 / {copy=1} copy {print} copy && /-healthcheck-wait/ {exit}' \
    "$UPGRADE" >"$READINESS_ROOT/startup.sh"
  grep -q -- '-healthcheck-wait' "$READINESS_ROOT/startup.sh" || {
    echo "Upgrade has no bounded readiness check" >&2; exit 1;
  }
  for READINESS_START_CODE in 0 75 1; do
  for READINESS_CODE in 0 1 75; do
    READINESS_CASE="$READINESS_ROOT/$READINESS_START_CODE-$READINESS_CODE"
    mkdir -p "$READINESS_CASE/bin"
    cat >"$READINESS_CASE/bin/razvilka" <<'HEALTH_FIXTURE'
#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = -healthcheck ] &&
  [ "$2" = http://127.0.0.1:8787/api/v1/status ] &&
  [ "$3" = -healthcheck-pid ] && [ "$4" = 4242 ] &&
  [ "$5" = -healthcheck-require-dataplane ] &&
  [ "$6" = -healthcheck-wait ] && [ "$7" = 9m ] || {
    echo "Upgrade lost exact PID, strict evidence or bounded wait" >&2; exit 98;
  }
touch "$READINESS_CASE/health-called"
exit "$READINESS_CODE"
HEALTH_FIXTURE
    cat >"$READINESS_CASE/init" <<'INIT_FIXTURE'
#!/bin/sh
set -eu
case "$1" in
  clear-guard) : ;;
  start) touch "$READINESS_CASE/running"; exit "$READINESS_START_CODE" ;;
  pid) printf '%s\n' 4242 ;;
  lan-ip) printf '%s\n' 127.0.0.1 ;;
  *) echo "Unexpected one-shot supervision before readiness" >&2; exit 97 ;;
esac
INIT_FIXTURE
    cat >"$READINESS_CASE/rollback" <<'ROLLBACK_FIXTURE'
#!/bin/sh
set -eu
touch "$READINESS_CASE/rolled-back"
rm "$READINESS_CASE/running"
ROLLBACK_FIXTURE
    chmod 700 "$READINESS_CASE/bin/razvilka" "$READINESS_CASE/init"
    cat >"$READINESS_CASE/run.sh" <<'STARTUP_FIXTURE'
#!/bin/sh
set -eu
BASE="$READINESS_CASE"
BINDIR="$BASE/bin"
RAZ_INIT="$BASE/init"
ROLLBACK="$BASE/rollback"
BACKUP=fixture-snapshot
CURRENT_BACKUP="$BASE/current-backup"
RAZVILKA_PORT=8787
stage() { :; }
. "$READINESS_ROOT/rollback-function.sh"
trap 'rollback_on_error $?' EXIT
. "$READINESS_ROOT/startup.sh"
touch "$BASE/accepted"
trap - EXIT
STARTUP_FIXTURE
    export READINESS_CASE READINESS_CODE READINESS_ROOT READINESS_START_CODE
    ACTUAL_CODE=0
    sh "$READINESS_CASE/run.sh" >"$READINESS_CASE/output" 2>&1 || ACTUAL_CODE=$?
    if [ "$READINESS_START_CODE" -eq 1 ]; then
      [ "$ACTUAL_CODE" -eq 1 ] && [ -f "$READINESS_CASE/rolled-back" ] || exit 1
      assert_absent "$READINESS_CASE/accepted"
      assert_absent "$READINESS_CASE/health-called"
      assert_absent "$READINESS_CASE/running"
      continue
    fi
    [ "$ACTUAL_CODE" -eq "$READINESS_CODE" ] && [ -f "$READINESS_CASE/health-called" ] || {
      echo "Upgrade readiness exit contract failed ($READINESS_CODE -> $ACTUAL_CODE)" >&2
      cat "$READINESS_CASE/output" >&2
      exit 1
    }
    if [ "$READINESS_CODE" -eq 0 ]; then
      [ -f "$READINESS_CASE/accepted" ] && [ -f "$READINESS_CASE/running" ] || exit 1
      assert_absent "$READINESS_CASE/rolled-back"
    elif [ "$READINESS_CODE" -eq 75 ]; then
      [ -f "$READINESS_CASE/running" ] && [ "$(cat "$READINESS_CASE/current-backup")" = fixture-snapshot ] || exit 1
      assert_absent "$READINESS_CASE/accepted"
      assert_absent "$READINESS_CASE/rolled-back"
    else
      [ -f "$READINESS_CASE/rolled-back" ] || exit 1
      assert_absent "$READINESS_CASE/accepted"
      assert_absent "$READINESS_CASE/running"
    fi
  done
  done
}

test_upgrade_readiness
prepare_root "$PRIMARY"
prepare_root "$CONFLICT"
prepare_root "$REMOVAL"

# Read-only checks must not repair even legacy staging permissions.
mkdir -p "$PRIMARY/var/lib/razvilka/staging/sing-box"
chmod 755 "$PRIMARY/var/lib/razvilka/staging/sing-box"

RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$UPGRADE" --dry-run >/dev/null
assert_absent "$PRIMARY/bin/razvilka"
assert_absent "$PRIMARY/etc/init.d/S99razvilka"
[ "$(ls -ld "$PRIMARY/var/lib/razvilka/staging/sing-box" | awk '{print $1}')" = drwxr-xr-x ] || {
  echo "Read-only preflight changed legacy staging permissions" >&2; exit 1;
}

RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 \
  "$UPGRADE" --apply >/dev/null
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" \
  "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null

PRIMARY_BACKUP="$(cat "$PRIMARY/var/lib/razvilka/current-backup")"
[ -d "$PRIMARY_BACKUP" ] || { echo "Primary rollback snapshot is missing" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP" | awk '{print $1}')" = drwx------ ] || { echo "Snapshot mode is not 700" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP/manifest" | awk '{print $1}')" = -rw------- ] || { echo "Manifest mode is not 600" >&2; exit 1; }
grep -q '^PRIVATE_RESTORE_PROTOCOL=1$' "$PRIMARY_BACKUP/manifest" || { echo "Private restore protocol is not recorded" >&2; exit 1; }

# A same-version upgrade must preserve committed adapter metadata that is
# temporarily removed by controlled dataplane deactivation.
mkdir -p "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter"
printf '%s\n' preserved >"$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker"
mkdir -p "$PRIMARY/var/lib/razvilka/staging/test-private" "$PRIMARY/etc/razvilka/cloudflare-private/test-private"
printf '%s\n' staged-original >"$PRIMARY/var/lib/razvilka/staging/test-private/marker"
printf '%s\n' provider-original >"$PRIMARY/etc/razvilka/cloudflare-private/test-private/marker"
SOURCE_STATE_ORIGINAL='{"schema":1,"draft":{"telegram-cidrs":false},"applied":{"telegram-cidrs":true}}'
printf '%s\n' "$SOURCE_STATE_ORIGINAL" >"$PRIMARY/etc/razvilka/source-state.json"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 \
  "$UPGRADE" --apply --without-components >/dev/null
[ "$(cat "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker")" = preserved ] || {
  echo "Dataplane runtime snapshot was not restored after upgrade" >&2
  exit 1
}
[ "$(cat "$PRIMARY/etc/razvilka/source-state.json")" = "$SOURCE_STATE_ORIGINAL" ] || {
  echo "Source selection state changed during upgrade" >&2
  exit 1
}
SECOND_BACKUP="$(cat "$PRIMARY/var/lib/razvilka/current-backup")"
assert_absent "$SECOND_BACKUP/private-restore"
grep -q '^STAGING_PRESENT=1$' "$SECOND_BACKUP/manifest" || { echo "Staging snapshot was not recorded" >&2; exit 1; }
grep -q '^CLOUDFLARE_PRIVATE_PRESENT=1$' "$SECOND_BACKUP/manifest" || { echo "Provider snapshot was not recorded" >&2; exit 1; }
printf '%s\n' '{"schema":1,"draft":{},"applied":{}}' >"$PRIMARY/etc/razvilka/source-state.json"
printf '%s\n' staged-changed >"$PRIMARY/var/lib/razvilka/staging/test-private/marker"
printf '%s\n' provider-changed >"$PRIMARY/etc/razvilka/cloudflare-private/test-private/marker"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$SECOND_BACKUP" >/dev/null
[ "$(cat "$PRIMARY/var/lib/razvilka/dataplane/runtime/test-adapter/ownership.marker")" = preserved ] || {
  echo "Dataplane runtime snapshot was not restored by rollback" >&2
  exit 1
}
[ "$(cat "$PRIMARY/etc/razvilka/source-state.json")" = "$SOURCE_STATE_ORIGINAL" ] || {
  echo "Source selection state was not restored by rollback" >&2
  exit 1
}
[ "$(cat "$PRIMARY/var/lib/razvilka/staging/test-private/marker")" = staged-original ] || {
  echo "Staging private data was not restored by rollback" >&2
  exit 1
}
[ "$(cat "$PRIMARY/etc/razvilka/cloudflare-private/test-private/marker")" = provider-original ] || {
  echo "Provider private data was not restored by rollback" >&2
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

# A complete manifest with a missing private directory must be rejected before
# the running service or any live file is touched.
INCOMPLETE="$PRIMARY/var/lib/razvilka/update-backups/incomplete-private-test"
cp -a "$SECOND_BACKUP" "$INCOMPLETE"
rm -rf "$INCOMPLETE/staging"
if RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$INCOMPLETE" >/dev/null 2>&1; then
  echo "Incomplete private snapshot unexpectedly passed validation" >&2
  exit 1
fi
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" \
  "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null

# Rollback must not write through a failed stop. A fake daemon acknowledges
# TERM without sending it; S99 must detect the still-running owned PID and the
# rollback script must return before restoring any snapshot file.
FAKE_DAEMON="$TEST_ROOT/fake-stop-daemon"
cat >"$FAKE_DAEMON" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 755 "$FAKE_DAEMON"
LIVE_SOURCE_BEFORE_STOP_TEST="$(cat "$PRIMARY/etc/razvilka/source-state.json")"
if RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_START_STOP_DAEMON="$FAKE_DAEMON" \
  "$ROLLBACK" "$SECOND_BACKUP" >/dev/null 2>&1; then
  echo "Rollback unexpectedly continued after a failed stop" >&2
  exit 1
fi
[ "$(cat "$PRIMARY/etc/razvilka/source-state.json")" = "$LIVE_SOURCE_BEFORE_STOP_TEST" ] || {
  echo "Rollback wrote files after a failed stop" >&2
  exit 1
}
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" \
  "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null

# A corrupt private journal is a hard recovery boundary. With the isolated
# service stopped, rollback must leave even an intentionally invalid live file
# untouched until an operator repairs the test-owned journal.
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" stop >/dev/null
mkdir -p "$PRIMARY/etc/razvilka/private-restore"
printf '%s\n' '{"corrupt-private-journal":' >"$PRIMARY/etc/razvilka/private-restore/restore.private.json"
printf '%s\n' 'RECOVERY_FAILURE_SENTINEL' >"$PRIMARY/etc/razvilka/source-state.json"
if RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$ROLLBACK" "$SECOND_BACKUP" >/dev/null 2>&1; then
  echo "Rollback unexpectedly continued through a corrupt private journal" >&2
  exit 1
fi
[ "$(cat "$PRIMARY/etc/razvilka/source-state.json")" = RECOVERY_FAILURE_SENTINEL ] || {
  echo "Rollback wrote files after private recovery failed" >&2
  exit 1
}
rm -f "$PRIMARY/etc/razvilka/private-restore/restore.private.json"
printf '%s\n' "$LIVE_SOURCE_BEFORE_STOP_TEST" >"$PRIMARY/etc/razvilka/source-state.json"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" start >/dev/null
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
