#!/bin/sh
# RAZVILKA_UNINSTALL_PRESERVES_DATA=1
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
case "$BASE" in /*) ;; *) echo "RAZVILKA_BASE must be an absolute directory" >&2; exit 1 ;; esac
[ -d "$BASE" ] || { echo "RAZVILKA_BASE is missing" >&2; exit 1; }
BASE="$(CDPATH= cd -- "$BASE" && pwd -P)"
[ "$BASE" != / ] || { echo "Refusing to use the filesystem root as RAZVILKA_BASE" >&2; exit 1; }
PATH="$BASE/sbin:$BASE/bin:$BASE/usr/sbin:$BASE/usr/bin:$PATH"
export PATH
APPDIR="$BASE/etc/razvilka"
STATEDIR="$BASE/var/lib/razvilka"
INIT="$BASE/etc/init.d/S99razvilka"
BINARY="$BASE/bin/razvilka"

case "${1:-}" in
  '') ;;
  -h|--help) echo "Usage: sh uninstall-entware.sh (remove panel and owned routes; keep data)"; exit 0 ;;
  *) echo "Unknown option: $1. Use rollback-entware.sh explicitly to restore an older version." >&2; exit 2 ;;
esac

# Deletion and execution must stay inside this installation, even when an old
# or partially removed tree contains links. Do not follow them into another app.
for DIR in "$BASE/bin" "$BASE/etc" "$BASE/etc/init.d" "$APPDIR" "$BASE/var" "$BASE/var/lib" "$STATEDIR"; do
  [ ! -L "$DIR" ] && { [ ! -e "$DIR" ] || [ -d "$DIR" ]; } || { echo "Unsafe installation directory: $DIR" >&2; exit 1; }
done
for FILE in "$INIT" "$BINARY"; do
  [ ! -L "$FILE" ] && { [ ! -e "$FILE" ] || { [ -f "$FILE" ] && [ -x "$FILE" ]; }; } || { echo "Unsafe installation file: $FILE" >&2; exit 1; }
done

if [ ! -e "$BINARY" ] && [ ! -e "$INIT" ]; then
  echo "RAZVILKA panel files are already absent. Retained data was not changed."
  exit 0
fi
[ -x "$BINARY" ] || { echo "Current binary is missing; cannot safely deactivate its routes. Reinstall RAZVILKA before removal." >&2; exit 1; }

if [ -x "$INIT" ]; then
  RAZVILKA_BASE="$BASE" "$INIT" stop
else
  # Without the PID-verifying supervisor, absence of a process must be proved
  # before touching runtime state. A possibly foreign process is never killed.
  command -v pidof >/dev/null 2>&1 || { echo "Cannot verify process absence without pidof" >&2; exit 1; }
  [ -z "$(pidof razvilka 2>/dev/null || true)" ] || { echo "RAZVILKA is running but its init script is missing; removal stopped" >&2; exit 1; }
fi

# Settle retained private journals while their writer is stopped. A failed
# stop, private recovery or owned-route cleanup keeps the binary for repair.
RECOVERY_OUTPUT="$("$BINARY" -recover-private-restore \
  -config "$APPDIR/config.json" -custom-services "$APPDIR/custom-services.json" \
  -devices "$APPDIR/devices.json" -node-state "$APPDIR/nodes-private" \
  -stage "$STATEDIR/staging" -warp-state "$STATEDIR/warp" \
  -cloudflare-state "$APPDIR/cloudflare-private")"
printf '%s\n' "$RECOVERY_OUTPUT" | grep -q '"ok":true' || { echo "Private restore recovery did not report success; panel files kept" >&2; exit 1; }
"$BINARY" -deactivate-dataplane \
  -stage "$STATEDIR/staging" \
  -backups "$STATEDIR/backups" \
  -dataplane-state "$STATEDIR/dataplane" >/dev/null
rm -f "$INIT" "$BINARY"
# Uninstall is never an implicit rollback: current settings, credentials, nodes,
# component packages and update snapshots remain available for reinstallation.
echo "RAZVILKA panel and owned routes removed. Data and backups kept in $APPDIR and $STATEDIR; installed bypass packages were not removed."
