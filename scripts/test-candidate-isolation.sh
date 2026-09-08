#!/bin/sh
# Executes the real launcher against temporary files and a recording daemon.
# No server, router command, network request or signal other than kill -0 runs.
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="$ROOT/scripts/start-candidate-entware.sh"
STOP_SCRIPT="$ROOT/scripts/stop-candidate-entware.sh"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-candidate-test.XXXXXX")"
cleanup() {
    case "$TEST_ROOT" in
        "$TMP_BASE"/razvilka-candidate-test.*) rm -rf "$TEST_ROOT" ;;
        *) echo "Refusing unsafe candidate test cleanup" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEST_ROOT/mocks" "$TEST_ROOT/outside"
printf '%s\n' production-unchanged >"$TEST_ROOT/outside/config.json"
cat >"$TEST_ROOT/mocks/readlink" <<'EOF'
#!/bin/sh
case "$1" in /proc/*/exe) printf '%s\n' "$TEST_RUNNING_BINARY" ;; *) exit 1 ;; esac
EOF
cat >"$TEST_ROOT/mocks/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 700 "$TEST_ROOT/mocks/readlink" "$TEST_ROOT/mocks/sleep"
PATH="$TEST_ROOT/mocks:$PATH"
export PATH
TEST_PID=$$
export TEST_PID

prepare() {
    BASE="$TEST_ROOT/$1"
    mkdir -p "$BASE/bin" "$BASE/sbin" "$BASE/var/run" "$BASE/etc"
    cat >"$BASE/bin/razvilka-candidate" <<'EOF'
#!/bin/sh
[ "$1" = -healthcheck ] && [ "$2" = http://192.168.1.1:8788/api/v1/status ] && [ "$3" = -healthcheck-pid ] && [ "$4" = "$TEST_PID" ] || exit 99
COUNT=0
[ ! -f "$TEST_CAPTURE.health" ] || COUNT="$(cat "$TEST_CAPTURE.health")"
COUNT=$((COUNT + 1))
printf '%s\n' "$COUNT" >"$TEST_CAPTURE.health"
[ "$COUNT" -gt "${TEST_HEALTH_FAILURES:-0}" ]
EOF
    cat >"$BASE/sbin/start-stop-daemon" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >"$TEST_CAPTURE"
printf '%s\n' "$RAZVILKA_USQUE_REPAIR_STATE" >"$TEST_CAPTURE.env"
PID_FILE=''
while [ "$#" -gt 0 ]; do
    case "$1" in -p) shift; PID_FILE="$1" ;; esac
    shift
done
[ -n "$PID_FILE" ] || exit 1
printf '%s\n' "$TEST_PID" >"$PID_FILE"
EOF
    chmod 700 "$BASE/bin/razvilka-candidate" "$BASE/sbin/start-stop-daemon"
    TEST_CAPTURE="$BASE/launcher.args"
    TEST_RUNNING_BINARY="$BASE/bin/razvilka-candidate"
    TEST_HEALTH_FAILURES=0
    export TEST_CAPTURE TEST_RUNNING_BINARY TEST_HEALTH_FAILURES
}
launch() { RAZVILKA_CANDIDATE_BASE="$BASE" sh "$SCRIPT" >"$BASE/result.log" 2>&1; }
refuse_stop() {
    if RAZVILKA_CANDIDATE_BASE="$BASE" sh "$STOP_SCRIPT" >"$BASE/stop.log" 2>&1; then
        echo "Unsafe candidate stop was accepted" >&2; exit 1
    fi
    [ -f "$BASE/var/run/razvilka-candidate.pid" ] || { echo "Refused stop erased its PID file" >&2; exit 1; }
}
refused() {
    if launch; then echo "Unsafe candidate launch was accepted" >&2; exit 1; fi
    [ ! -e "$TEST_CAPTURE" ] || { echo "Refused candidate reached daemon" >&2; exit 1; }
}

prepare fresh
TEST_HEALTH_FAILURES=2
export TEST_HEALTH_FAILURES
launch
[ "$(cat "$TEST_CAPTURE.health")" = 3 ] || { echo "Candidate did not wait for readiness" >&2; exit 1; }
[ -f "$BASE/var/lib/razvilka-candidate/.candidate-layout-v1" ] || { echo "Layout ownership missing" >&2; exit 1; }
[ "$(cat "$TEST_CAPTURE.env")" = "$BASE/var/lib/razvilka-candidate/usque-repair" ] || exit 1

# Verify every main writable flag, not just the historical small override set.
for FLAG in config catalog sources cache stage backups token-file credentials-file custom-services community-catalog devices node-state cloudflare-state warp-state smart-route-state dataplane-state metrics-history strategy-lab-state audit-log dns-state; do
    VALUE="$(awk -v flag="-$FLAG" '$0 == flag { getline; print; found=1; exit } END { if (!found) exit 1 }' "$TEST_CAPTURE")" || {
        echo "Candidate omitted a required state flag: $FLAG" >&2; exit 1;
    }
    case "$VALUE" in "$BASE"/*/razvilka-candidate|"$BASE"/*/razvilka-candidate/*) ;; *) echo "Candidate state escaped its installation: $FLAG" >&2; exit 1 ;; esac
done

# Existing owned PID returns without invoking the daemon again.
rm "$TEST_CAPTURE"
launch
[ ! -e "$TEST_CAPTURE" ] || { echo "Already-running candidate launched twice" >&2; exit 1; }

# Owned state survives a real apply/restart workflow; startup must not be
# permanently read-only just because its own journal now exists.
rm "$BASE/var/run/razvilka-candidate.pid"
mkdir -p "$BASE/var/lib/razvilka-candidate/dataplane"
printf '%s\n' owned-journal >"$BASE/var/lib/razvilka-candidate/dataplane/latest-committed-plan.json"
launch
[ "$(cat "$BASE/var/lib/razvilka-candidate/dataplane/latest-committed-plan.json")" = owned-journal ] || exit 1

prepare foreign-pid
printf '%s\n' "$TEST_PID" >"$BASE/var/run/razvilka-candidate.pid"
TEST_RUNNING_BINARY="$TEST_ROOT/outside/production-daemon"
export TEST_RUNNING_BINARY
refused
refuse_stop

for BAD_PID in 0 1 invalid; do
    prepare "invalid-pid-$BAD_PID"
    printf '%s\n' "$BAD_PID" >"$BASE/var/run/razvilka-candidate.pid"
    refused
    refuse_stop
done

for JOURNAL in var/lib/razvilka-candidate/dataplane var/lib/razvilka-candidate/usque-repair etc/razvilka-candidate/private-restore etc/razvilka-candidate/private-restore-nodes-v1 etc/razvilka-candidate/private-restore-native-v1 etc/razvilka-candidate/private-restore-feeds-v1; do
    prepare "journal-$(printf '%s' "$JOURNAL" | tr '/' '-')"
    mkdir -p "$BASE/$JOURNAL"
    printf '%s\n' copied-production >"$BASE/$JOURNAL/record.json"
    refused
    [ "$(cat "$BASE/$JOURNAL/record.json")" = copied-production ] || exit 1
done

prepare bad-marker
mkdir -p "$BASE/var/lib/razvilka-candidate"
printf '%s\n' another-installation >"$BASE/var/lib/razvilka-candidate/.candidate-layout-v1"
refused

prepare not-ready
TEST_HEALTH_FAILURES=99
export TEST_HEALTH_FAILURES
if launch; then echo "Unready candidate advertised successful start" >&2; exit 1; fi
[ "$(cat "$TEST_CAPTURE.health")" = 12 ] || { echo "Readiness retry was not bounded" >&2; exit 1; }
[ -f "$BASE/var/run/razvilka-candidate.pid" ] || { echo "Readiness failure erased running PID" >&2; exit 1; }

prepare symlink-store
if ln -s "$TEST_ROOT/outside" "$BASE/etc/razvilka-candidate" && [ -L "$BASE/etc/razvilka-candidate" ]; then
    refused
else
    echo "SKIP symlink-store: filesystem does not create native symlinks"
fi
prepare symlink-file
mkdir -p "$BASE/etc/razvilka-candidate"
if ln -s "$TEST_ROOT/outside/config.json" "$BASE/etc/razvilka-candidate/config.json" && [ -L "$BASE/etc/razvilka-candidate/config.json" ]; then
    refused
else
    echo "SKIP symlink-file: filesystem does not create native symlinks"
fi
prepare symlink-pid
if ln -s "$TEST_ROOT/outside/config.json" "$BASE/var/run/razvilka-candidate.pid" && [ -L "$BASE/var/run/razvilka-candidate.pid" ]; then
    refused
    refuse_stop
else
    echo "SKIP symlink-pid: filesystem does not create native symlinks"
fi
[ "$(cat "$TEST_ROOT/outside/config.json")" = production-unchanged ] || exit 1

echo "Candidate launcher isolation tests: PASS"
