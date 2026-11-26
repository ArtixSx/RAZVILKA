#!/bin/sh
# Actual installer shell boundary with recording command fixtures ONLY.
# No native Main, control ledger, process, network or route is created here.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/razvilka-clean-control-model.XXXXXX")"
# Retain this finite model's files for inspection; never remove host state.
awk '
  /^# Only a genuinely new installation creates/ {copy=1}
  copy && /^stage 6 / {exit}
  copy {print}
' "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/clean-entry.sh"
grep -q 'install-control-initialize' "$TEST_ROOT/clean-entry.sh"
awk '/^require_legacy_file_protocol_free\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' \
  "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/retained-guard.sh"

TOTAL=0
for CASE in clean binary-only config-only existing changed-image refused wrong-marker changed-after-helper; do
  CASE_ROOT="$TEST_ROOT/$CASE"
  mkdir -p "$CASE_ROOT/bin"
  cat >"$CASE_ROOT/bin/razvilka" <<'COMMAND'
#!/bin/sh
set -eu
[ "$#" = 2 ] && [ "$1" = install-control-initialize ] || exit 98
SELF_SHA="$(sha256sum "$0" | awk '{print $1}')"
[ "$2" = "$SELF_SHA" ] || exit 98
printf '%s\n' "$1 $2" >>"$CASE_ROOT/invocation"
if [ "$CASE" = changed-after-helper ]; then printf '\n# changed fixture image\n' >>"$0"; fi
case "$CASE" in refused) exit 3 ;; wrong-marker) printf 'unknown\n' ;; *) printf 'CLEAN_INSTALL_CONTROL_READY\n' ;; esac
COMMAND
  chmod 700 "$CASE_ROOT/bin/razvilka"
  ACTUAL="$(sha256sum "$CASE_ROOT/bin/razvilka" | awk '{print $1}')"
  RAZ_BINARY_PRESENT=0
  CONFIG_PRESENT=0
  case "$CASE" in
    binary-only) RAZ_BINARY_PRESENT=1 ;;
    config-only) CONFIG_PRESENT=1 ;;
    existing) RAZ_BINARY_PRESENT=1; CONFIG_PRESENT=1 ;;
    changed-image) ACTUAL=changed ;;
  esac
  export CASE CASE_ROOT ACTUAL RAZ_BINARY_PRESENT CONFIG_PRESENT
  CODE=0
  BINDIR="$CASE_ROOT/bin" sh -c 'set -eu; . "$1"; printf "first-start-boundary\n" >"$CASE_ROOT/start"' \
    sh "$TEST_ROOT/clean-entry.sh" >"$CASE_ROOT/output" 2>"$CASE_ROOT/error" || CODE=$?
  case "$CASE" in
    clean)
      [ "$CODE" -eq 0 ] && [ "$(wc -l <"$CASE_ROOT/invocation")" -eq 1 ] && [ -f "$CASE_ROOT/start" ] ;;
    binary-only|config-only|existing)
      [ "$CODE" -eq 0 ] && [ ! -e "$CASE_ROOT/invocation" ] && [ -f "$CASE_ROOT/start" ] ;;
    changed-image)
      [ "$CODE" -ne 0 ] && [ ! -e "$CASE_ROOT/invocation" ] && [ ! -e "$CASE_ROOT/start" ] ;;
    refused|wrong-marker|changed-after-helper)
      [ "$CODE" -ne 0 ] && [ "$(wc -l <"$CASE_ROOT/invocation")" -eq 1 ] && [ ! -e "$CASE_ROOT/start" ] ;;
  esac
  [ ! -e "$CASE_ROOT/razvilka/state/self-update-stop" ]
  TOTAL=$((TOTAL+1))
done

for STATE in empty partial stopped; do
  CASE_ROOT="$TEST_ROOT/retained-$STATE"
  mkdir -p "$CASE_ROOT/state/self-update-stop"
  # Presence is all this original shell guard consumes. These opaque markers
  # are NOT application JSON; real ready/Stop/partial records use Go models.
  printf '%s\n' "$STATE-retained-bytes" >"$CASE_ROOT/state/self-update-stop/opaque"
  BEFORE="$(sha256sum "$CASE_ROOT/state/self-update-stop/opaque")"
  CODE=0
  STATEDIR="$CASE_ROOT/state" BINDIR="$CASE_ROOT/bin" sh -c 'set -eu; . "$1"; require_legacy_file_protocol_free; exit 99' \
    sh "$TEST_ROOT/retained-guard.sh" >"$CASE_ROOT/output" 2>&1 || CODE=$?
  [ "$CODE" -eq 1 ]
  [ "$BEFORE" = "$(sha256sum "$CASE_ROOT/state/self-update-stop/opaque")" ]
  [ ! -e "$CASE_ROOT/state/self-update-stop/.control.lock" ]
  TOTAL=$((TOTAL+1))
done

printf 'CLEAN_CONTROL_INSTALLER_MODELS_PASS cases=%s native_initialization=false\n' "$TOTAL"
