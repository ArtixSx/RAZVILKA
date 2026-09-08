#!/bin/sh
set -eu

umask 077

BASE="${RAZVILKA_CANDIDATE_BASE:-/opt}"
case "$BASE" in
    /*) ;;
    *) echo "Candidate base must be absolute" >&2; exit 1 ;;
esac
BASE="${BASE%/}"
case "$BASE/" in
    /|*/../*|*/./*|*//*) echo "Candidate base must be a non-root normalized path" >&2; exit 1 ;;
esac
[ -d "$BASE" ] || { echo "Candidate base directory is missing" >&2; exit 1; }
BINARY="$BASE/bin/razvilka-candidate"
CONFIG_DIR="$BASE/etc/razvilka-candidate"
STATE_DIR="$BASE/var/lib/razvilka-candidate"
CACHE_DIR="$BASE/var/cache/razvilka-candidate"
LOG_DIR="$BASE/var/log/razvilka-candidate"
PID_FILE="$BASE/var/run/razvilka-candidate.pid"
LOG_FILE="$LOG_DIR/server.log"
DAEMON="$BASE/sbin/start-stop-daemon"
LAYOUT_MARKER="$STATE_DIR/.candidate-layout-v1"

# /opt itself may be the normal Entware symlink. Below that explicit base,
# candidate paths must not redirect writes into another installation.
for TARGET in "$BINARY" "$CONFIG_DIR" "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR" "$PID_FILE"; do
    CHECK="$TARGET"
    while [ "$CHECK" != "$BASE" ]; do
        [ ! -L "$CHECK" ] || { echo "Candidate path contains a symlink; refusing startup" >&2; exit 1; }
        CHECK="${CHECK%/*}"
    done
done
for TARGET in "$CONFIG_DIR" "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR"; do
    if [ -e "$TARGET" ]; then
        [ -d "$TARGET" ] || { echo "Candidate directory is not a directory" >&2; exit 1; }
        LINKS="$(find "$TARGET" -type l -print)" || exit 1
        [ -z "$LINKS" ] || { echo "Candidate store contains a symlink; refusing startup" >&2; exit 1; }
    fi
done
[ -f "$BINARY" ] && [ -x "$DAEMON" ] || { echo "Candidate binary or launcher is missing" >&2; exit 1; }
EXPECTED_BINARY="$(CDPATH= cd -- "${BINARY%/*}" && pwd -P)/${BINARY##*/}"

owned_pid() {
    case "$1" in ''|0|1|*[!0-9]*) return 1 ;; esac
    kill -0 "$1" 2>/dev/null || return 1
    RUNNING_BINARY="$(readlink "/proc/$1/exe" 2>/dev/null || true)"
    [ "$RUNNING_BINARY" = "$EXPECTED_BINARY" ] || [ "$RUNNING_BINARY" = "$BINARY" ]
}

await_ready() {
    READY_PID="$1"
    ATTEMPT=0
    # The binary bounds one health request to four seconds. Twelve attempts
    # plus one-second gaps stay below one minute, including failed readiness.
    while [ "$ATTEMPT" -lt 12 ]; do
        owned_pid "$READY_PID" || { echo "Candidate exited or changed identity before readiness" >&2; return 1; }
        if "$BINARY" -healthcheck http://192.168.1.1:8788/api/v1/status -healthcheck-pid "$READY_PID" >/dev/null 2>&1; then
            return 0
        fi
        ATTEMPT=$((ATTEMPT + 1))
        [ "$ATTEMPT" -ge 12 ] || sleep 1
    done
    echo "Candidate did not become ready; process and PID file kept for inspection: $LOG_FILE" >&2
    return 1
}

if [ -r "$PID_FILE" ]; then
    PID="$(cat "$PID_FILE")"
    case "$PID" in
        ''|0|1|*[!0-9]*) echo "Invalid candidate PID file; refusing startup" >&2; exit 1 ;;
        *)
            if kill -0 "$PID" 2>/dev/null; then
                owned_pid "$PID" || { echo "Candidate PID belongs to another executable; refusing startup" >&2; exit 1; }
                await_ready "$PID" || exit 1
                echo "RAZVILKA candidate already running (pid $PID)"
                exit 0
            fi
            ;;
    esac
fi

# A marker is created only for a layout with no prior recovery state. It ties
# later apply/restart journals to this candidate installation without replaying
# a copied production journal on its first start. It is not a network sandbox.
EXPECTED_LAYOUT="candidate-layout-v1
$CONFIG_DIR
$STATE_DIR"
if [ -e "$LAYOUT_MARKER" ]; then
    [ -f "$LAYOUT_MARKER" ] && [ "$(cat "$LAYOUT_MARKER")" = "$EXPECTED_LAYOUT" ] || {
        echo "Candidate layout ownership is invalid; existing state preserved" >&2; exit 1;
    }
else
    for JOURNAL in "$STATE_DIR/dataplane" "$STATE_DIR/usque-repair" "$CONFIG_DIR/private-restore" "$CONFIG_DIR/private-restore-nodes-v1" "$CONFIG_DIR/private-restore-native-v1" "$CONFIG_DIR/private-restore-feeds-v1"; do
        if [ -e "$JOURNAL" ]; then
            echo "Unowned candidate recovery state exists; existing state preserved" >&2
            exit 1
        fi
    done
fi

mkdir -p "$CONFIG_DIR" "$CACHE_DIR" "$STATE_DIR/staging" "$STATE_DIR/backups" "$LOG_DIR" "$BASE/var/run"
chmod 700 "$CONFIG_DIR" "$CACHE_DIR" "$STATE_DIR" "$STATE_DIR/staging" "$STATE_DIR/backups" "$LOG_DIR"
if [ ! -e "$LAYOUT_MARKER" ]; then
    (set -C; printf '%s\n' "$EXPECTED_LAYOUT" >"$LAYOUT_MARKER") || exit 1
fi
chmod 700 "$BINARY"

# Every writable store belongs to the candidate. Engine resources still belong
# to the router: use an empty Safe Mode config and review before live apply.
export RAZVILKA_USQUE_REPAIR_STATE="$STATE_DIR/usque-repair"
"$DAEMON" -S -b -m -p "$PID_FILE" -x "$BINARY" -O "$LOG_FILE" -- \
    -config "$CONFIG_DIR/config.json" \
    -catalog "$CONFIG_DIR/service-catalog.json" \
    -sources "$CONFIG_DIR/sources.json" \
    -cache "$CACHE_DIR" \
    -stage "$STATE_DIR/staging" \
    -backups "$STATE_DIR/backups" \
    -token-file "$CONFIG_DIR/admin.token" \
    -credentials-file "$CONFIG_DIR/admin.credentials.json" \
    -custom-services "$CONFIG_DIR/custom-services.json" \
    -community-catalog "$CONFIG_DIR/community-catalog.json" \
    -devices "$CONFIG_DIR/devices.json" \
    -node-state "$CONFIG_DIR/nodes-private" \
    -cloudflare-state "$CONFIG_DIR/cloudflare-private" \
    -warp-state "$STATE_DIR/warp" \
    -smart-route-state "$STATE_DIR/smart-route.json" \
    -dataplane-state "$STATE_DIR/dataplane" \
    -metrics-history "$STATE_DIR/metrics/history.jsonl" \
    -strategy-lab-state "$STATE_DIR/strategy-lab.json" \
    -audit-log "$STATE_DIR/audit/events.jsonl" \
    -dns-state "$STATE_DIR/dns/state.json" \
    -listen 192.168.1.1:8788

sleep 1
PID="$(cat "$PID_FILE" 2>/dev/null || true)"

case "$PID" in
    ''|0|1|*[!0-9]*)
        echo "RAZVILKA candidate failed to create a valid PID file; inspect $LOG_FILE" >&2
        exit 1
        ;;
esac

if ! owned_pid "$PID"; then
    echo "RAZVILKA candidate failed to start; inspect $LOG_FILE" >&2
    exit 1
fi

await_ready "$PID" || exit 1

echo "RAZVILKA candidate started on http://192.168.1.1:8788/ (pid $PID)"
