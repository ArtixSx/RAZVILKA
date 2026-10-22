#!/bin/sh
# RAZVILKA_UNINSTALL_PRESERVES_DATA=1
# RAZVILKA_UNINSTALL_PURGE_MOVES_DATA=1
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
STATEDIR="$BASE/razvilka/state"
# Releases up to 0.19 (and 0.20 candidates before the private layout) kept
# their routes, journals and snapshots here. This uninstaller never reads it.
LEGACY_STATEDIR="$BASE/var/lib/razvilka"
INIT="$BASE/etc/init.d/S99razvilka"
BINARY="$BASE/bin/razvilka"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"

PURGE=0
case "$#:${1:-}" in
  0:) ;;
  1:--purge) PURGE=1 ;;
  1:-h|1:--help)
    echo "Usage: sh uninstall-entware.sh [--purge]"
    echo "Default: remove the panel and its owned routes; keep settings, connections and snapshots."
    echo "--purge: then move all RAZVILKA data to $BASE/razvilka-removed-<UTC> (mode 0700) for a clean reinstall."
    exit 0 ;;
  *) echo "Unknown option: $*. Use rollback-entware.sh explicitly to restore an older version." >&2; exit 2 ;;
esac

# Deletion and execution must stay inside this installation, even when an old
# or partially removed tree contains links. Do not follow them into another app.
for DIR in "$BASE" "$BASE/bin" "$BASE/etc" "$BASE/etc/init.d" "$APPDIR" "$BASE/razvilka" "$BASE/razvilka/run" "$STATEDIR"; do
  [ ! -L "$DIR" ] && { [ ! -e "$DIR" ] || [ -d "$DIR" ]; } || { echo "Unsafe installation directory: $DIR" >&2; exit 1; }
  case "$DIR" in
    "$BASE/razvilka"|"$BASE/razvilka/"*)
      if [ -d "$DIR" ]; then
        PRIVATE_OWNER="$(LC_ALL=C ls -nd -- "$DIR" | awk '
          NR == 1 && $3 ~ /^[0-9]+$/ && substr($1,1,1) == "d" && substr($1,6,1) != "w" && substr($1,9,1) != "w" { print $3; ok=1 }
          END { if (NR != 1 || !ok) exit 1 }
        ')" && [ "$PRIVATE_OWNER" = "$(id -u)" ] || { echo "Unsafe private installation owner or permissions: $DIR" >&2; exit 1; }
      fi ;;
  esac
done
for FILE in "$INIT" "$BINARY"; do
  [ ! -L "$FILE" ] && { [ ! -e "$FILE" ] || { [ -f "$FILE" ] && [ -x "$FILE" ]; }; } || { echo "Unsafe installation file: $FILE" >&2; exit 1; }
done

# Purge moves whole directories. Prove every precondition before Stop, so a
# refused purge never leaves a half-removed installation behind.
if [ "$PURGE" -eq 1 ]; then
  for DIR in "$BASE/var" "$BASE/var/lib" "$LEGACY_STATEDIR"; do
    [ ! -L "$DIR" ] && { [ ! -e "$DIR" ] || [ -d "$DIR" ]; } || { echo "Unsafe installation directory: $DIR; nothing was removed" >&2; exit 1; }
  done
  # The release running this script must not live inside the data it moves.
  case "$HERE/" in
    "$BASE/razvilka/"*|"$APPDIR/"*|"$LEGACY_STATEDIR/"*)
      echo "Purge must run from a release extracted outside the RAZVILKA data folders; nothing was removed" >&2; exit 1 ;;
  esac
  command -v pidof >/dev/null 2>&1 || { echo "Cannot verify process absence without pidof; nothing was removed" >&2; exit 1; }
fi

if [ ! -e "$BINARY" ] && [ ! -e "$INIT" ]; then
  if [ "$PURGE" -eq 0 ]; then
    echo "RAZVILKA panel files are already absent. Retained data was not changed."
    exit 0
  fi
  echo "RAZVILKA panel files are already absent; moving the retained data."
else
  # A pre-0.20 layout records its routes only in the legacy directory. Its
  # deactivation here would read an empty 0.20 state and then delete the one
  # binary able to remove those routes. Only its own release may remove it.
  if { [ -e "$LEGACY_STATEDIR" ] || [ -L "$LEGACY_STATEDIR" ]; } && [ ! -e "$STATEDIR" ] && [ ! -L "$STATEDIR" ]; then
    echo "Pre-0.20 RAZVILKA layout found; its routes are recorded in $LEGACY_STATEDIR; nothing was removed" >&2
    echo "Удалите эту установку деинсталлятором её собственной версии (номер покажет /opt/bin/razvilka -version):" >&2
    echo "  RAZVILKA_VERSION=v<версия> sh /opt/tmp/razvilka-setup.sh --uninstall" >&2
    echo "Порядок перехода: docs/INSTALL_RU.md, раздел «Переход с 0.19.3 и более ранних версий»." >&2
    exit 1
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
  # Removal retires RAZVILKA's stopped component configuration before its
  # ownership ledger can be moved away. Ordinary Stop/update keeps that ledger
  # and must not take this path. Shared component packages remain installed.
  "$BINARY" -deactivate-dataplane -retire-dataplane-for-removal \
    -stage "$STATEDIR/staging" \
    -backups "$STATEDIR/backups" \
    -dataplane-state "$STATEDIR/dataplane" >/dev/null
  rm -f "$INIT" "$BINARY"
  if [ "$PURGE" -eq 0 ]; then
    # Uninstall is never an implicit rollback: current settings, credentials, nodes,
    # component packages and update snapshots remain available for reinstallation.
    echo "RAZVILKA panel and owned routes removed. Data and backups kept in $APPDIR and $STATEDIR; installed bypass packages were not removed."
    exit 0
  fi
  echo "RAZVILKA panel and owned routes removed; moving the retained data."
fi

# Explicit purge: the panel is gone and its routes are deactivated. Move, never
# delete, every RAZVILKA data folder (settings, credentials, nodes, journals,
# control ledger and snapshots) into one new private folder, so the next
# bootstrap is a genuinely clean installation. Entware, other applications and
# installed bypass packages are untouched.
[ -z "$(pidof razvilka 2>/dev/null || true)" ] || {
  echo "A razvilka process is still running; the panel was removed but its data was not moved" >&2; exit 1;
}
if [ ! -e "$APPDIR" ] && [ ! -e "$BASE/razvilka" ] && [ ! -e "$LEGACY_STATEDIR" ]; then
  echo "No RAZVILKA data folders remain; nothing to move."
  exit 0
fi
PURGE_DIR="$BASE/razvilka-removed-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$PURGE_DIR" || { echo "Cannot create a new private folder $PURGE_DIR; data was not moved" >&2; exit 1; }
purge_move() {
  [ -e "$1" ] || return 0
  mv "$1" "$PURGE_DIR/$2" || {
    echo "Purge stopped: $1 was not moved; data moved so far is in $PURGE_DIR. Repeat --purge." >&2; exit 1;
  }
  echo "  moved: $1 -> $PURGE_DIR/$2"
}
purge_move "$APPDIR" etc-razvilka
purge_move "$BASE/razvilka" razvilka
purge_move "$LEGACY_STATEDIR" var-lib-razvilka
echo "RAZVILKA data moved to $PURGE_DIR (root only). Entware and installed bypass packages were not removed."
echo "Данные RAZVILKA перенесены в $PURGE_DIR. Следующая установка будет чистой."
echo "Удалите эту папку сами, когда убедитесь, что сохранённые настройки и ключи больше не нужны."
