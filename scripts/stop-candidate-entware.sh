#!/bin/sh
set -eu

BASE="${RAZVILKA_CANDIDATE_BASE:-/opt}"
case "$BASE" in /*) ;; *) echo "Candidate base must be absolute" >&2; exit 1 ;; esac
BASE="${BASE%/}"
case "$BASE/" in /|*/../*|*/./*|*//*) echo "Candidate base must be a non-root normalized path" >&2; exit 1 ;; esac
[ -d "$BASE" ] || { echo "Candidate base directory is missing" >&2; exit 1; }
BINARY="$BASE/bin/razvilka-candidate"
PID_FILE="$BASE/razvilka/candidate/run/razvilka.pid"
for TARGET in "$BINARY" "$PID_FILE"; do
    CHECK="$TARGET"
    while [ "$CHECK" != "$BASE" ]; do
        [ ! -L "$CHECK" ] || { echo "Candidate path contains a symlink; refusing stop" >&2; exit 1; }
        CHECK="${CHECK%/*}"
    done
done

if [ ! -r "$PID_FILE" ]; then
    echo "RAZVILKA candidate is not running (PID file absent)"
    exit 0
fi

PID="$(cat "$PID_FILE")"
case "$PID" in
    ''|0|1|*[!0-9]*)
        echo "Refusing to stop: invalid candidate PID file" >&2
        exit 1
        ;;
esac

if [ ! -d "/proc/$PID" ]; then
    rm -f "$PID_FILE"
    echo "RAZVILKA candidate is not running (stale PID file removed)"
    exit 0
fi

[ -f "$BINARY" ] || { echo "Candidate binary is missing; refusing stop" >&2; exit 1; }
EXPECTED_BINARY="$(CDPATH= cd -- "${BINARY%/*}" && pwd -P)/${BINARY##*/}"
RUNNING_BINARY="$(readlink "/proc/$PID/exe" 2>/dev/null || true)"
if [ "$RUNNING_BINARY" != "$EXPECTED_BINARY" ] && [ "$RUNNING_BINARY" != "$BINARY" ]; then
    echo "Refusing to stop pid $PID: executable is $RUNNING_BINARY" >&2
    exit 1
fi

kill "$PID"

WAIT=0
# Match the installed panel: join its live phase and rollback before replacement.
# The panel's shared graceful shutdown budget is 390 seconds.
while kill -0 "$PID" 2>/dev/null && [ "$WAIT" -lt 395 ]; do
    sleep 1
    WAIT=$((WAIT + 1))
done

if kill -0 "$PID" 2>/dev/null; then
    echo "Candidate did not stop after 395 seconds; PID file kept" >&2
    exit 1
fi

rm -f "$PID_FILE"
echo "RAZVILKA candidate stopped"
