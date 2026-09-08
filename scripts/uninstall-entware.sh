#!/bin/sh
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
STATEDIR="$BASE/var/lib/razvilka"
CURRENT_BACKUP="$STATEDIR/current-backup"
ROLLBACK="$HERE/rollback-entware.sh"
INIT="$BASE/etc/init.d/S99razvilka"
BINARY="$BASE/bin/razvilka"

if [ -r "$CURRENT_BACKUP" ]; then
  [ -x "$ROLLBACK" ] || { echo "Rollback helper is unavailable: $ROLLBACK" >&2; exit 1; }
  BACKUP="$(cat "$CURRENT_BACKUP")"
  echo "Restoring pre-install snapshot instead of removing files blindly: $BACKUP"
  export RAZVILKA_BASE="$BASE"
  exec "$ROLLBACK" "$BACKUP"
fi

[ -x "$INIT" ] && RAZVILKA_BASE="$BASE" "$INIT" stop || true
if [ -x "$BINARY" ]; then
  "$BINARY" -deactivate-dataplane \
    -stage "$STATEDIR/staging" \
    -backups "$STATEDIR/backups" \
    -dataplane-state "$STATEDIR/dataplane" >/dev/null
fi
rm -f "$INIT" "$BINARY"
# Keep config/catalog/cache by default: future reinstall or rollback can reuse them.
echo "RAZVILKA binary/service removed. Data kept at $BASE/etc/razvilka and $BASE/var/cache/razvilka"
