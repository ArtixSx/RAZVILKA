#!/bin/sh
set -eu

umask 077

BINARY=/opt/bin/razvilka-candidate
CONFIG_DIR=/opt/etc/razvilka-candidate
STATE_DIR=/opt/var/lib/razvilka-candidate
CACHE_DIR=/opt/var/cache/razvilka-candidate
LOG_DIR=/opt/var/log/razvilka-candidate
PID_FILE=/opt/var/run/razvilka-candidate.pid
LOG_FILE="$LOG_DIR/server.log"
DAEMON=/opt/sbin/start-stop-daemon

if [ -r "$PID_FILE" ]; then
    PID="$(cat "$PID_FILE")"
    case "$PID" in
        ''|*[!0-9]*) ;;
        *)
            if kill -0 "$PID" 2>/dev/null; then
                echo "RAZVILKA candidate already running (pid $PID)"
                exit 0
            fi
            ;;
    esac
fi

mkdir -p "$CACHE_DIR" "$STATE_DIR/staging" "$STATE_DIR/backups" "$LOG_DIR" /opt/var/run
chmod 700 "$BINARY"

"$DAEMON" -S -b -m -p "$PID_FILE" -x "$BINARY" -O "$LOG_FILE" -- \
    -config "$CONFIG_DIR/config.json" \
    -catalog "$CONFIG_DIR/service-catalog.json" \
    -sources "$CONFIG_DIR/sources.json" \
    -cache "$CACHE_DIR" \
    -stage "$STATE_DIR/staging" \
    -backups "$STATE_DIR/backups" \
    -token-file "$CONFIG_DIR/admin.token" \
    -listen 192.168.1.1:8788

sleep 1
PID="$(cat "$PID_FILE" 2>/dev/null || true)"

case "$PID" in
    ''|*[!0-9]*)
        echo "RAZVILKA candidate failed to create a valid PID file; inspect $LOG_FILE" >&2
        exit 1
        ;;
esac

if ! kill -0 "$PID" 2>/dev/null; then
    echo "RAZVILKA candidate failed to start; inspect $LOG_FILE" >&2
    exit 1
fi

echo "RAZVILKA candidate started on http://192.168.1.1:8788/ (pid $PID)"
