#!/bin/sh
set -eu

BINARY=/opt/bin/razvilka-v0.0.8-candidate
PID_FILE=/opt/var/run/razvilka-v0.0.8-candidate.pid

if [ ! -r "$PID_FILE" ]; then
    echo "RAZVILKA candidate is not running (PID file absent)"
    exit 0
fi

PID="$(cat "$PID_FILE")"
case "$PID" in
    ''|*[!0-9]*)
        echo "Refusing to stop: invalid candidate PID file" >&2
        exit 1
        ;;
esac

if [ ! -d "/proc/$PID" ]; then
    rm -f "$PID_FILE"
    echo "RAZVILKA candidate is not running (stale PID file removed)"
    exit 0
fi

RUNNING_BINARY="$(readlink "/proc/$PID/exe" 2>/dev/null || true)"
if [ "$RUNNING_BINARY" != "$BINARY" ]; then
    echo "Refusing to stop pid $PID: executable is $RUNNING_BINARY" >&2
    exit 1
fi

kill "$PID"

WAIT=0
while kill -0 "$PID" 2>/dev/null && [ "$WAIT" -lt 10 ]; do
    sleep 1
    WAIT=$((WAIT + 1))
done

if kill -0 "$PID" 2>/dev/null; then
    echo "Candidate did not stop after 10 seconds; PID file kept" >&2
    exit 1
fi

rm -f "$PID_FILE"
echo "RAZVILKA candidate stopped"
