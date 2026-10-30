#!/bin/sh
# Temp-base transaction: a test-only Go overlay models the NEW native initializer
# leaf only. Ordinary Main and every installer/S99 script remain unchanged.
# This test makes no claim of native canonical control initialization.
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
sh "$ROOT/scripts/test-entware-path-safety.sh"
sh "$ROOT/scripts/test-installer-architecture.sh"
sh "$ROOT/scripts/test-legacy-layout-guard.sh"
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
  mkdir -p "$BASE/var/lib"
  printf '%s\n' keep-other-app >"$BASE/var/lib/other-app.conf"
  if [ "$(id -u)" = 0 ]; then chown 1001 "$BASE/var"; fi
  ln -s "$DAEMON" "$BASE/sbin/start-stop-daemon"
}

prepare_modeled_clean_bundle() {
  # No production path/env override is added. The canonical command cannot
  # authorize this temp installation; record ONLY its exact shell boundary.
  MODEL_BUNDLE="$TEST_ROOT/modeled-clean-control-bundle"
  mkdir -p "$MODEL_BUNDLE/dist"
  cp -a "$ROOT/scripts" "$ROOT/configs" "$MODEL_BUNDLE/"
  case "$(uname -m)" in
    x86_64|amd64) MODEL_ARCH=amd64 ;;
    aarch64|arm64) MODEL_ARCH=arm64 ;;
    *) echo "Transaction model requires the existing native AMD64/ARM64 Main" >&2; exit 1 ;;
  esac
  RAZVILKA_TEST_CLEAN_CONTROL_LOG="$TEST_ROOT/clean-control-invocations"
  export RAZVILKA_TEST_CLEAN_CONTROL_LOG
  cat >"$TEST_ROOT/modeled-native-leaf.go" <<'CLEAN_CONTROL_MODEL'
package main
import (
  "context"
  "os"
  "github.com/ArtixSx/razvilka/internal/operationgate"
)
// TEST MODEL ONLY. No native issuer, ledger, image replacement or permissions.
func initializeNativeCleanInstallControl(ctx context.Context, gate *operationgate.Gate, expected string) error {
  if ctx == nil || gate == nil || len(expected) != 64 { return operationgate.ErrSelfUpdateStopJournal }
  return gate.WithExclusiveContext(ctx, func() error {
    path := os.Getenv("RAZVILKA_TEST_CLEAN_CONTROL_LOG")
    if path == "" { return operationgate.ErrSelfUpdateStopJournal }
    file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil { return err }
    _, err = file.WriteString("MODELED_INSTALL_CONTROL_COMMAND\n")
    closeErr := file.Close()
    if err != nil { return err }
    return closeErr
  })
}
CLEAN_CONTROL_MODEL
  # Replace exactly the dedicated initializer leaf, not Main/dispatch, shell
  # checks or S99. The model ELF remains identical before/after the command.
  python3 - "$ROOT/cmd/razvilka/clean_install_control_linux.go" "$TEST_ROOT/modeled-native-leaf.go" \
    "$TEST_ROOT/clean-control-overlay.json" <<'CLEAN_CONTROL_OVERLAY'
import json, pathlib, sys
original, modeled, output = map(pathlib.Path, sys.argv[1:])
with output.open('x', encoding='utf-8') as stream:
    json.dump({'Replace': {str(original.resolve()): str(modeled.resolve())}}, stream)
CLEAN_CONTROL_OVERLAY
  (cd "$ROOT" && GOOS=linux GOARCH="$MODEL_ARCH" CGO_ENABLED=0 go build -trimpath \
    -overlay "$TEST_ROOT/clean-control-overlay.json" -o "$MODEL_BUNDLE/dist/razvilka-linux-$MODEL_ARCH" ./cmd/razvilka)
  (cd "$MODEL_BUNDLE" && sha256sum dist/razvilka-linux-* >dist/SHA256SUMS)
  UPGRADE="$MODEL_BUNDLE/scripts/upgrade-entware.sh"
  ROLLBACK="$MODEL_BUNDLE/scripts/rollback-entware.sh"
  UNINSTALL="$MODEL_BUNDLE/scripts/uninstall-entware.sh"
}

assert_absent() {
  [ ! -e "$1" ] && [ ! -L "$1" ] || { echo "Expected path to be absent: $1" >&2; exit 1; }
}

# Exercise startup arguments and error-trap dispatch as isolated shell units.
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
  for READINESS_PRIOR in 1 0; do
  for READINESS_START_CODE in 0 75 1; do
  for READINESS_CODE in 0 1 75; do
    READINESS_CASE="$READINESS_ROOT/$READINESS_PRIOR-$READINESS_START_CODE-$READINESS_CODE"
    mkdir -p "$READINESS_CASE/bin"
    cat >"$READINESS_CASE/bin/razvilka" <<'HEALTH_FIXTURE'
#!/bin/sh
set -eu
# Route evidence is required exactly when the previous version confirmed it.
if [ "$READINESS_PRIOR" -eq 1 ]; then
  [ "$#" -eq 7 ] && [ "$1" = -healthcheck ] &&
    [ "$2" = http://127.0.0.1:8787/api/v1/status ] &&
    [ "$3" = -healthcheck-pid ] && [ "$4" = 4242 ] &&
    [ "$5" = -healthcheck-require-dataplane ] &&
    [ "$6" = -healthcheck-wait ] && [ "$7" = 9m ] || {
      echo "Upgrade lost exact PID, strict evidence or bounded wait" >&2; exit 98;
    }
else
  [ "$#" -eq 6 ] && [ "$1" = -healthcheck ] &&
    [ "$2" = http://127.0.0.1:8787/api/v1/status ] &&
    [ "$3" = -healthcheck-pid ] && [ "$4" = 4242 ] &&
    [ "$5" = -healthcheck-wait ] && [ "$6" = 9m ] || {
      echo "Upgrade without prior route evidence lost exact PID or bounded wait" >&2; exit 98;
    }
fi
touch "$READINESS_CASE/health-called"
exit "$READINESS_CODE"
HEALTH_FIXTURE
    cat >"$READINESS_CASE/init" <<'INIT_FIXTURE'
#!/bin/false
# Deliberately non-POSIX firmware interpreter: callers must select Entware sh.
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
PRIOR_ROUTES_CONFIRMED=$READINESS_PRIOR
stage() { :; }
. "$READINESS_ROOT/rollback-function.sh"
trap 'rollback_on_error $?' EXIT
. "$READINESS_ROOT/startup.sh"
touch "$BASE/accepted"
trap - EXIT
STARTUP_FIXTURE
    export READINESS_CASE READINESS_CODE READINESS_ROOT READINESS_START_CODE READINESS_PRIOR
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
  done
}

# The candidate binary classifies the previous process. Only a known
# degradation (exit 10) relaxes the strict route check; busy, fenced, down,
# wrong identity and any other code keep it.
test_prior_route_evidence() {
  PRIOR_ROOT="$TEST_ROOT/prior-evidence"
  mkdir -p "$PRIOR_ROOT"
  awk '/^PRIOR_ROUTES_CONFIRMED=1$/ {copy=1} copy {print} copy && /^fi$/ {exit}'     "$UPGRADE" >"$PRIOR_ROOT/probe.sh"
  grep -q -- '-healthcheck-prior' "$PRIOR_ROOT/probe.sh" || {
    echo "Upgrade has no prior route classification" >&2; exit 1;
  }
  for PRIOR_CODE in 0 10 75 76 1 2 98; do
    PRIOR_CASE="$PRIOR_ROOT/$PRIOR_CODE"
    mkdir -p "$PRIOR_CASE/bin"
    cat >"$PRIOR_CASE/candidate" <<PRIOR_FIXTURE
#!/bin/sh
[ "\$*" = "-healthcheck http://127.0.0.1:8787/api/v1/status -healthcheck-pid 4242 -healthcheck-prior -healthcheck-wait 3m" ] || exit 99
exit $PRIOR_CODE
PRIOR_FIXTURE
    printf '#!/bin/false\ncase "$1" in pid) echo 4242 ;; lan-ip) echo 127.0.0.1 ;; esac\n' >"$PRIOR_CASE/init"
    chmod 700 "$PRIOR_CASE/candidate" "$PRIOR_CASE/init"
    RESULT="$(BASE="$PRIOR_CASE" BINDIR="$PRIOR_CASE/bin" BIN_SOURCE="$PRIOR_CASE/candidate" RAZ_INIT="$PRIOR_CASE/init" RAZ_WAS_RUNNING=1       sh -c 'set -eu; . "$1" >/dev/null; printf %s "$PRIOR_ROUTES_CONFIRMED"' sh "$PRIOR_ROOT/probe.sh")"
    EXPECTED=1
    [ "$PRIOR_CODE" -ne 10 ] || EXPECTED=0
    [ "$RESULT" = "$EXPECTED" ] || {
      echo "Prior route classification $PRIOR_CODE -> $RESULT, want $EXPECTED" >&2; exit 1;
    }
  done
}

# Capture every stopped installation entry, including inode, content, mode, owner
# and link target. Ignore timestamps: a read-only rollback probe creates/removes
# a private scratch directory, which can change its parent's directory mtime.
# The fixture owns these paths and never creates names containing newlines.
installation_image() (
  IMAGE_ROOT="$1"
  IMAGE_OUTPUT="$2"
  cd "$IMAGE_ROOT"
  find . -print >"$IMAGE_OUTPUT.paths"
  LC_ALL=C sort "$IMAGE_OUTPUT.paths" >"$IMAGE_OUTPUT.sorted"
  while IFS= read -r IMAGE_PATH; do
    printf '%s\n' "$IMAGE_PATH"
    ls -ldin "$IMAGE_PATH" >"$IMAGE_OUTPUT.stat"
    awk '{print $1, $2, $4, $5}' "$IMAGE_OUTPUT.stat"
    if [ -L "$IMAGE_PATH" ]; then
      readlink "$IMAGE_PATH"
    elif [ -f "$IMAGE_PATH" ]; then
      sha256sum "$IMAGE_PATH"
    elif [ ! -d "$IMAGE_PATH" ]; then
      echo "Unexpected installation object: $IMAGE_PATH" >&2
      exit 1
    fi
  done <"$IMAGE_OUTPUT.sorted" >"$IMAGE_OUTPUT"
  rm -f "$IMAGE_OUTPUT.paths" "$IMAGE_OUTPUT.sorted" "$IMAGE_OUTPUT.stat"
)

assert_installation_unchanged() {
  installation_image "$PRIMARY" "$TEST_ROOT/installed-after"
  cmp -s "$TEST_ROOT/installed-before" "$TEST_ROOT/installed-after" || {
    echo "Reader3 refusal/read-only check changed installation bytes, inode or metadata" >&2
    diff -u "$TEST_ROOT/installed-before" "$TEST_ROOT/installed-after" >&2 || true
    exit 1
  }
}

# Main delivers every actual metadata flag without a shim/downshift. Only the
# explicit NEW native initializer leaf was replaced in this test-only ELF.
# check-self-update-state intentionally has fixed /opt roots; RAZVILKA_BASE here
# does not relocate its retained-format scanner to the test installation.
assert_native_metadata() (
  METADATA_BASE="$1"
  for METADATA_FLAG in -self-update-read-version -self-update-schema -check-self-update-state; do
    case "$METADATA_FLAG" in
      -self-update-read-version) METADATA_EXPECTED=4 ;;
      -self-update-schema) METADATA_EXPECTED=0 ;;
      -check-self-update-state) METADATA_EXPECTED='{"ok":true}' ;;
    esac
    RAZVILKA_BASE="$METADATA_BASE" timeout -k 1 15 "$METADATA_BASE/bin/razvilka" "$METADATA_FLAG" \
      >"$TEST_ROOT/metadata-output" 2>"$TEST_ROOT/metadata-error" || {
      echo "Actual native metadata command failed: $METADATA_FLAG" >&2
      cat "$TEST_ROOT/metadata-error" >&2
      exit 1
    }
    printf '%s\n' "$METADATA_EXPECTED" >"$TEST_ROOT/metadata-expected"
    cmp -s "$TEST_ROOT/metadata-output" "$TEST_ROOT/metadata-expected" &&
      [ ! -s "$TEST_ROOT/metadata-error" ] || {
      echo "Actual native metadata ABI was not canonical: $METADATA_FLAG" >&2
      exit 1
    }
  done
)

assert_refused() (
  REFUSAL_NAME="$1"
  REFUSAL_BASE="$2"
  REFUSAL_REASON="$3"
  shift 3
  REFUSAL_CODE=0
  RAZVILKA_BASE="$REFUSAL_BASE" RAZVILKA_PORT="$PORT" timeout -k 1 30 "$@" \
    >"$TEST_ROOT/$REFUSAL_NAME-output" 2>&1 || REFUSAL_CODE=$?
  [ "$REFUSAL_CODE" -eq 1 ] && grep -Fxq "$REFUSAL_REASON" "$TEST_ROOT/$REFUSAL_NAME-output" || {
    echo "Wrong refusal boundary for $REFUSAL_NAME (exit $REFUSAL_CODE)" >&2
    cat "$TEST_ROOT/$REFUSAL_NAME-output" >&2
    exit 1
  }
)

assert_primary_pid() {
  CURRENT_PID="$(RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" pid)"
  [ "$CURRENT_PID" = "$PRIMARY_PID" ] || { echo "Raw reader3 refusal stopped or replaced the live PID" >&2; exit 1; }
  RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null
}

# This is an isolated shell-function test, not a legacy-binary update or a
# managed reader3 transaction. It never mutates a native installation.
test_snapshot_pruning() (
  BACKUPROOT="$TEST_ROOT/pruning"
  BACKUP="$BACKUPROOT/20990101T000001Z-2"
  RAZVILKA_KEEP_UPDATE_BACKUPS=5
  mkdir -p "$BACKUP" "$BACKUPROOT/20990101T000000Z-1" "$BACKUPROOT/manual-keep" "$TEST_ROOT/outside-backup"
  for OLD in 20000101T000001Z-1 20000101T000002Z-2 20000101T000003Z-3 20000101T000004Z-4 20000101T000005Z-5; do
    mkdir -m 700 "$BACKUPROOT/$OLD"
  done
  ln -s "$TEST_ROOT/outside-backup" "$BACKUPROOT/19990101T000000Z-9"
  awk '/^prune_update_backups\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' \
    "$UPGRADE" >"$TEST_ROOT/prune-function.sh"
  grep -q '^prune_update_backups() {' "$TEST_ROOT/prune-function.sh"
  . "$TEST_ROOT/prune-function.sh"
  prune_update_backups
  [ -d "$BACKUP" ] && [ -d "$BACKUPROOT/20990101T000000Z-1" ] &&
    [ -d "$BACKUPROOT/20000101T000005Z-5" ] && [ -d "$BACKUPROOT/20000101T000003Z-3" ] || {
    echo "Retention removed a recent snapshot" >&2; exit 1;
  }
  assert_absent "$BACKUPROOT/20000101T000002Z-2"
  assert_absent "$BACKUPROOT/20000101T000001Z-1"
  [ -d "$BACKUPROOT/manual-keep" ] && [ -L "$BACKUPROOT/19990101T000000Z-9" ] && [ -d "$TEST_ROOT/outside-backup" ] || {
    echo "Retention removed a foreign entry" >&2; exit 1;
  }
)

assert_uninstall_preserves_data() (
  REMOVAL_BASE="$1"
  sha256sum "$REMOVAL_BASE/etc/razvilka/config.json" "$REMOVAL_BASE/etc/razvilka/admin.token" \
    "$REMOVAL_BASE/etc/razvilka/community-catalog.json" "$REMOVAL_BASE/razvilka/state/current-backup" >"$TEST_ROOT/removal-before"
  installation_image "$REMOVAL_BASE/razvilka/state/update-backups" "$TEST_ROOT/backups-before"
  SHARED_METADATA="$(ls -nd "$REMOVAL_BASE/var")"
  RAZVILKA_BASE="$REMOVAL_BASE" RAZVILKA_PORT="$PORT" "$UNINSTALL" >/dev/null
  assert_absent "$REMOVAL_BASE/bin/razvilka"
  assert_absent "$REMOVAL_BASE/etc/init.d/S99razvilka"
  sha256sum "$REMOVAL_BASE/etc/razvilka/config.json" "$REMOVAL_BASE/etc/razvilka/admin.token" \
    "$REMOVAL_BASE/etc/razvilka/community-catalog.json" "$REMOVAL_BASE/razvilka/state/current-backup" >"$TEST_ROOT/removal-after"
  cmp -s "$TEST_ROOT/removal-before" "$TEST_ROOT/removal-after" || { echo "Uninstall changed saved data" >&2; exit 1; }
  installation_image "$REMOVAL_BASE/razvilka/state/update-backups" "$TEST_ROOT/backups-after"
  cmp -s "$TEST_ROOT/backups-before" "$TEST_ROOT/backups-after" || { echo "Uninstall changed rollback snapshots" >&2; exit 1; }
  [ "$(cat "$REMOVAL_BASE/var/lib/other-app.conf")" = keep-other-app ] && [ "$(ls -nd "$REMOVAL_BASE/var")" = "$SHARED_METADATA" ] || {
    echo "Uninstall changed shared foreign Entware var" >&2; exit 1;
  }
  # A second uninstall is harmless; this is not a second raw installation.
  RAZVILKA_BASE="$REMOVAL_BASE" RAZVILKA_PORT="$PORT" "$UNINSTALL" >/dev/null
)

# Granular inert shell contracts only. The fake rollback in readiness tests
# observes trap dispatch; it does not prove native reader3 rollback succeeds.
prepare_modeled_clean_bundle
test_upgrade_readiness
test_prior_route_evidence
test_snapshot_pruning
prepare_root "$PRIMARY"
prepare_root "$CONFLICT"
prepare_root "$REMOVAL"

# The actual installer and Main never adopt a <=0.19 layout: a retained old
# state directory, or an installed controller without the 0.20 reader ABI,
# refuses dry-run and apply before Stop, snapshot or any installation write.
PRE020_REFUSAL='Pre-0.20 RAZVILKA installation found; 0.20 installs only on a clean base; installation unchanged'
LEGACY_STATE="$TEST_ROOT/legacy-state"
LEGACY_CONTROLLER="$TEST_ROOT/legacy-controller"
prepare_root "$LEGACY_STATE"
mkdir -p "$LEGACY_STATE/var/lib/razvilka"
printf '%s\n' legacy-settings >"$LEGACY_STATE/var/lib/razvilka/state-marker"
prepare_root "$LEGACY_CONTROLLER"
mkdir -p "$LEGACY_CONTROLLER/bin"
cat >"$LEGACY_CONTROLLER/bin/razvilka" <<'LEGACY_MAIN'
#!/bin/sh
# Go flag ABI of a <=0.19 controller; any other entrypoint is a test failure.
[ "$#" -eq 1 ] && [ "$1" = -self-update-read-version ] || exit 98
printf 'flag provided but not defined: -self-update-read-version\nUsage of razvilka:\n' >&2
exit 2
LEGACY_MAIN
chmod 755 "$LEGACY_CONTROLLER/bin/razvilka"
for LEGACY_BASE in "$LEGACY_STATE" "$LEGACY_CONTROLLER"; do
  installation_image "$LEGACY_BASE" "$TEST_ROOT/legacy-before"
  for LEGACY_MODE in --dry-run --apply; do
    assert_refused "pre020${LEGACY_MODE}-${LEGACY_BASE##*/}" "$LEGACY_BASE" "$PRE020_REFUSAL" \
      "$UPGRADE" "$LEGACY_MODE" --without-components
    installation_image "$LEGACY_BASE" "$TEST_ROOT/legacy-after"
    cmp -s "$TEST_ROOT/legacy-before" "$TEST_ROOT/legacy-after" || {
      echo "Pre-0.20 refusal changed the legacy installation: $LEGACY_BASE $LEGACY_MODE" >&2
      diff -u "$TEST_ROOT/legacy-before" "$TEST_ROOT/legacy-after" >&2 || true
      exit 1
    }
  done
done

# Actual installer preflight/ordinary Main must not repair legacy permissions.
mkdir -p "$PRIMARY/razvilka/state/staging/sing-box"
chmod 755 "$PRIMARY/razvilka/state/staging/sing-box"
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$UPGRADE" --dry-run >/dev/null
assert_absent "$PRIMARY/bin/razvilka"
assert_absent "$PRIMARY/etc/init.d/S99razvilka"
[ "$(ls -ld "$PRIMARY/razvilka/state/staging/sing-box" | awk '{print $1}')" = drwxr-xr-x ] || {
  echo "Read-only preflight changed legacy staging permissions" >&2; exit 1;
}
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 "$UPGRADE" --apply --without-components >/dev/null
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" status >/dev/null
assert_native_metadata "$PRIMARY"
PRIMARY_BACKUP="$(cat "$PRIMARY/razvilka/state/current-backup")"
[ -d "$PRIMARY_BACKUP" ] || { echo "Fresh-install snapshot is missing" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP" | awk '{print $1}')" = drwx------ ] || { echo "Snapshot mode is not 700" >&2; exit 1; }
[ "$(ls -ld "$PRIMARY_BACKUP/manifest" | awk '{print $1}')" = -rw------- ] || { echo "Manifest mode is not 600" >&2; exit 1; }
grep -q '^PRIVATE_RESTORE_PROTOCOL=1$' "$PRIMARY_BACKUP/manifest" || { echo "Private restore protocol is not recorded" >&2; exit 1; }
grep -q '^RAZ_BINARY_PRESENT=0$' "$PRIMARY_BACKUP/manifest" || { echo "Fresh installation unexpectedly recorded a previous binary" >&2; exit 1; }

# Read capability3 plus schema0 is not raw update authority. With a real daemon
# running, refusal must precede Stop and leave that exact supervised PID alive.
MANAGED_REFUSAL='This controller requires the journaled self update workflow; raw application replacement is unavailable'
PRIMARY_PID="$(RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" pid)"
[ -n "$PRIMARY_PID" ] || { echo "Fresh installation has no supervised PID" >&2; exit 1; }
sha256sum "$PRIMARY/bin/razvilka" "$PRIMARY/etc/init.d/S99razvilka" "$PRIMARY/etc/razvilka/config.json" \
  "$PRIMARY/etc/razvilka/admin.token" "$PRIMARY_BACKUP/manifest" "$PRIMARY/razvilka/state/current-backup" >"$TEST_ROOT/live-before"
assert_refused live-raw-upgrade "$PRIMARY" "$MANAGED_REFUSAL" "$UPGRADE" --apply --without-components
assert_primary_pid
assert_refused live-raw-rollback "$PRIMARY" "$MANAGED_REFUSAL" "$ROLLBACK" "$PRIMARY_BACKUP"
assert_primary_pid
sha256sum "$PRIMARY/bin/razvilka" "$PRIMARY/etc/init.d/S99razvilka" "$PRIMARY/etc/razvilka/config.json" \
  "$PRIMARY/etc/razvilka/admin.token" "$PRIMARY_BACKUP/manifest" "$PRIMARY/razvilka/state/current-backup" >"$TEST_ROOT/live-after"
cmp -s "$TEST_ROOT/live-before" "$TEST_ROOT/live-after" || { echo "Live reader3 refusal changed installed files" >&2; exit 1; }

# A conflicting fresh installation fails readiness after copying reader3.
# Its automatic raw rollback must also refuse; retained files need explicit
# repair. This is a failure/preservation check, not accepted journaled recovery.
CONFLICT_CODE=0
RAZVILKA_BASE="$CONFLICT" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=2 "$UPGRADE" --apply --without-components \
  >"$TEST_ROOT/conflict-output" 2>&1 || CONFLICT_CODE=$?
[ "$CONFLICT_CODE" -ne 0 ] && grep -Fxq "$MANAGED_REFUSAL" "$TEST_ROOT/conflict-output" &&
  grep -Fxq 'Automatic rollback failed; manual intervention required' "$TEST_ROOT/conflict-output" || {
  echo "Conflicting fresh install did not preserve the reader3 recovery boundary" >&2
  cat "$TEST_ROOT/conflict-output" >&2
  exit 1
}
[ -f "$CONFLICT/bin/razvilka" ] && [ -f "$CONFLICT/etc/init.d/S99razvilka" ] || {
  echo "Failed fresh installation lost its reader3 repair files" >&2; exit 1;
}
assert_native_metadata "$CONFLICT"
set -- "$CONFLICT/razvilka/state/update-backups/"*
[ "$#" -eq 1 ] && [ -f "$1/manifest" ] || { echo "Failed fresh installation lost its snapshot" >&2; exit 1; }
RAZVILKA_BASE="$CONFLICT" RAZVILKA_PORT="$PORT" "$UNINSTALL" >/dev/null
assert_absent "$CONFLICT/bin/razvilka"
assert_absent "$CONFLICT/etc/init.d/S99razvilka"

# Stop the actual process to make whole-tree byte/metadata comparisons stable.
# This is process quiescence, not durable D11 Stop or stopped settlement.
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$PRIMARY/etc/init.d/S99razvilka" stop >/dev/null
mkdir -p "$PRIMARY/razvilka/state/staging/test-private" "$PRIMARY/etc/razvilka/cloudflare-private/test-private"
printf '%s\n' staged-original >"$PRIMARY/razvilka/state/staging/test-private/marker"
printf '%s\n' provider-original >"$PRIMARY/etc/razvilka/cloudflare-private/test-private/marker"
printf '%s\n' '{"schema":1,"draft":{"telegram-cidrs":false},"applied":{"telegram-cidrs":true}}' >"$PRIMARY/etc/razvilka/source-state.json"
installation_image "$PRIMARY" "$TEST_ROOT/installed-before"
assert_native_metadata "$PRIMARY"
assert_installation_unchanged
RAZVILKA_BASE="$PRIMARY" RAZVILKA_PORT="$PORT" "$UPGRADE" --dry-run --without-components >/dev/null
assert_installation_unchanged
assert_refused stopped-raw-upgrade "$PRIMARY" "$MANAGED_REFUSAL" "$UPGRADE" --apply --without-components
assert_installation_unchanged
ln -s "$PRIMARY" "$TEST_ROOT/primary-link"
assert_refused stopped-raw-rollback "$TEST_ROOT/primary-link" "$MANAGED_REFUSAL" "$ROLLBACK" "$PRIMARY_BACKUP"
assert_installation_unchanged
assert_refused stopped-auto-rollback "$PRIMARY" "$MANAGED_REFUSAL" "$ROLLBACK" "$PRIMARY_BACKUP" --auto
assert_installation_unchanged

# These manifest/path validators run before reader admission. Assert their
# specific diagnostics, so an earlier reader3 refusal cannot mask the coverage.
MALICIOUS="$PRIMARY/razvilka/state/update-backups/malicious-test"
cp -a "$PRIMARY_BACKUP" "$MALICIOUS"
printf 'EVIL=$(touch %s)\n' "$MARKER" >>"$MALICIOUS/manifest"
INCOMPLETE="$PRIMARY/razvilka/state/update-backups/incomplete-private-test"
cp -a "$PRIMARY_BACKUP" "$INCOMPLETE"
rm -rf "$INCOMPLETE/staging"
installation_image "$PRIMARY" "$TEST_ROOT/installed-before"
assert_refused malicious-manifest "$PRIMARY" 'Unknown rollback manifest key: EVIL' "$ROLLBACK" "$MALICIOUS"
assert_absent "$MARKER"
assert_installation_unchanged
assert_refused incomplete-snapshot "$PRIMARY" 'Snapshot directory is missing or unsafe: staging' "$ROLLBACK" "$INCOMPLETE"
assert_installation_unchanged
assert_refused traversal "$PRIMARY" "Refusing rollback outside $PRIMARY/razvilka/state/update-backups: $PRIMARY/razvilka" \
  "$ROLLBACK" "$PRIMARY/razvilka/state/update-backups/../.."
assert_installation_unchanged
# Remove only these test-owned malformed snapshots before native effect helpers;
# their rejection checks above are complete, and the valid snapshot is retained.
rm -rf "$MALICIOUS" "$INCOMPLETE"

# Actual uninstall removes the current reader3 panel and keeps saved data.
# It does not use raw rollback to undo the successful fresh installation.
assert_uninstall_preserves_data "$PRIMARY"
[ "$(cat "$PRIMARY/razvilka/state/staging/test-private/marker")" = staged-original ] &&
  [ "$(cat "$PRIMARY/etc/razvilka/cloudflare-private/test-private/marker")" = provider-original ] || {
  echo "Uninstall removed retained private data" >&2; exit 1;
}
RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 "$UPGRADE" --apply --without-components >/dev/null
RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" "$REMOVAL/etc/init.d/S99razvilka" status >/dev/null
assert_native_metadata "$REMOVAL"
REMOVAL_BACKUP="$(cat "$REMOVAL/razvilka/state/current-backup")"
grep -q '^RAZ_BINARY_PRESENT=0$' "$REMOVAL_BACKUP/manifest" || { echo "Uninstall fixture was not a fresh installation" >&2; exit 1; }
assert_uninstall_preserves_data "$REMOVAL"

# Retained data (config and control ledger) refuses a raw reinstall. Explicit
# purge moves every RAZVILKA folder aside, so the actual installer performs a
# genuinely clean installation again: new control epoch and fresh snapshot.
# Purge proves process absence with host-wide pidof and never kills; a foreign
# razvilka on the test host makes this block an explicit, printed skip.
PURGE_REINSTALLS=0
if [ -z "$(pidof razvilka 2>/dev/null || true)" ]; then
  RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" "$UNINSTALL" --purge >/dev/null
  assert_absent "$REMOVAL/etc/razvilka"
  assert_absent "$REMOVAL/razvilka"
  set -- "$REMOVAL"/razvilka-removed-*
  [ "$#" -eq 1 ] && [ -f "$1/etc-razvilka/config.json" ] && [ -f "$1/etc-razvilka/admin.token" ] &&
    [ -f "$1/razvilka/state/current-backup" ] && [ "$(ls -ld "$1" | awk '{print $1}')" = drwx------ ] || {
    echo "Purge did not move the retained data into one private folder" >&2; exit 1;
  }
  [ "$(cat "$REMOVAL/var/lib/other-app.conf")" = keep-other-app ] || { echo "Purge changed foreign Entware data" >&2; exit 1; }
  RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" RAZVILKA_HEALTH_RETRIES=5 "$UPGRADE" --apply --without-components >/dev/null
  RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" "$REMOVAL/etc/init.d/S99razvilka" status >/dev/null
  assert_native_metadata "$REMOVAL"
  REMOVAL_BACKUP="$(cat "$REMOVAL/razvilka/state/current-backup")"
  grep -q '^RAZ_BINARY_PRESENT=0$' "$REMOVAL_BACKUP/manifest" && grep -q '^CONFIG_PRESENT=0$' "$REMOVAL_BACKUP/manifest" &&
    grep -q '^TOKEN_PRESENT=0$' "$REMOVAL_BACKUP/manifest" || { echo "Reinstall after purge was not a clean installation" >&2; exit 1; }
  RAZVILKA_BASE="$REMOVAL" RAZVILKA_PORT="$PORT" "$UNINSTALL" >/dev/null
  assert_absent "$REMOVAL/bin/razvilka"
  PURGE_REINSTALLS=1
else
  echo "SKIP purge reinstall: a razvilka process outside this test runs on the host"
fi

[ "$(wc -l <"$RAZVILKA_TEST_CLEAN_CONTROL_LOG")" -eq $((3 + PURGE_REINSTALLS)) ] || {
  echo "Temp transaction lost the exact modeled clean-control calls" >&2; exit 1;
}
for MODEL_BASE in "$PRIMARY" "$CONFLICT" "$REMOVAL"; do
  assert_absent "$MODEL_BASE/razvilka/state/self-update-stop"
done

trap - EXIT HUP INT TERM
cleanup
echo "Entware actual shell/S99/Main transaction (test-only modeled native initializer), readonly metadata and reader3 raw refusal: OK"
echo "Canonical Linux clean control and first consent POST before Prepare require the separate genuine clean-install probe."
echo "Journaled update, durable Stop settlement and Resume acceptance are separate D11 gates."
