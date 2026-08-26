#!/bin/sh
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
STATEDIR="$BASE/var/lib/razvilka"
BACKUPROOT="$STATEDIR/update-backups"
APPDIR="$BASE/etc/razvilka"
BINDIR="$BASE/bin"
INITDIR="$BASE/etc/init.d"
RAZ_INIT="$INITDIR/S99razvilka"
LEGACY_INIT="$INITDIR/S99artem-flow"
LEGACY_DISABLED="$INITDIR/S99artem-flow.razvilka-disabled"
AUTO=0
BACKUP=""

for ARG in "$@"; do
  case "$ARG" in
    --auto) AUTO=1 ;;
    -h|--help)
      echo "Usage: $0 [BACKUP_DIRECTORY] [--auto]"
      exit 0
      ;;
    *)
      if [ -n "$BACKUP" ]; then echo "Only one backup directory is allowed" >&2; exit 2; fi
      BACKUP="$ARG"
      ;;
  esac
done

if [ -z "$BACKUP" ]; then
  [ -r "$STATEDIR/current-backup" ] || { echo "No current rollback snapshot" >&2; exit 1; }
  BACKUP="$(cat "$STATEDIR/current-backup")"
fi
[ -d "$BACKUP" ] && [ ! -L "$BACKUP" ] || { echo "Invalid rollback directory: $BACKUP" >&2; exit 1; }
BACKUPROOT_REAL="$(CDPATH= cd -- "$BACKUPROOT" 2>/dev/null && pwd -P)" || { echo "Rollback root is unavailable: $BACKUPROOT" >&2; exit 1; }
BACKUP_REAL="$(CDPATH= cd -- "$BACKUP" 2>/dev/null && pwd -P)" || { echo "Cannot resolve rollback directory: $BACKUP" >&2; exit 1; }
case "$BACKUP_REAL" in
  "$BACKUPROOT_REAL"/*) BACKUP="$BACKUP_REAL" ;;
  *) echo "Refusing rollback outside $BACKUPROOT_REAL: $BACKUP_REAL" >&2; exit 1 ;;
esac
[ -f "$BACKUP/manifest" ] && [ ! -L "$BACKUP/manifest" ] || { echo "Rollback manifest is missing or unsafe" >&2; exit 1; }

RAZ_BINARY_PRESENT=
RAZ_INIT_PRESENT=
CONFIG_PRESENT=
CATALOG_PRESENT=
COMMUNITY_PRESENT=0
SOURCES_PRESENT=
SOURCE_STATE_PRESENT=0
TOKEN_PRESENT=
CREDENTIALS_PRESENT=0
CUSTOM_SERVICES_PRESENT=0
DEVICES_PRESENT=0
DATAPLANE_STATE_PRESENT=0
LEGACY_INIT_PRESENT=
LEGACY_DISABLED_PRESENT=
LEGACY_WAS_RUNNING=
RAZ_WAS_RUNNING=
while IFS='=' read -r KEY VALUE; do
  case "$KEY" in
    RAZ_BINARY_PRESENT) RAZ_BINARY_PRESENT="$VALUE" ;;
    RAZ_INIT_PRESENT) RAZ_INIT_PRESENT="$VALUE" ;;
    CONFIG_PRESENT) CONFIG_PRESENT="$VALUE" ;;
    CATALOG_PRESENT) CATALOG_PRESENT="$VALUE" ;;
    COMMUNITY_PRESENT) COMMUNITY_PRESENT="$VALUE" ;;
    SOURCES_PRESENT) SOURCES_PRESENT="$VALUE" ;;
    SOURCE_STATE_PRESENT) SOURCE_STATE_PRESENT="$VALUE" ;;
    TOKEN_PRESENT) TOKEN_PRESENT="$VALUE" ;;
    CREDENTIALS_PRESENT) CREDENTIALS_PRESENT="$VALUE" ;;
    CUSTOM_SERVICES_PRESENT) CUSTOM_SERVICES_PRESENT="$VALUE" ;;
    DEVICES_PRESENT) DEVICES_PRESENT="$VALUE" ;;
    DATAPLANE_STATE_PRESENT) DATAPLANE_STATE_PRESENT="$VALUE" ;;
    LEGACY_INIT_PRESENT) LEGACY_INIT_PRESENT="$VALUE" ;;
    LEGACY_DISABLED_PRESENT) LEGACY_DISABLED_PRESENT="$VALUE" ;;
    LEGACY_WAS_RUNNING) LEGACY_WAS_RUNNING="$VALUE" ;;
    RAZ_WAS_RUNNING) RAZ_WAS_RUNNING="$VALUE" ;;
    *) echo "Unknown rollback manifest key: $KEY" >&2; exit 1 ;;
  esac
done <"$BACKUP/manifest"
for VALUE in "$RAZ_BINARY_PRESENT" "$RAZ_INIT_PRESENT" "$CONFIG_PRESENT" "$CATALOG_PRESENT" "$COMMUNITY_PRESENT" "$SOURCES_PRESENT" "$SOURCE_STATE_PRESENT" "$TOKEN_PRESENT" "$CREDENTIALS_PRESENT" "$CUSTOM_SERVICES_PRESENT" "$DEVICES_PRESENT" "$DATAPLANE_STATE_PRESENT" "$LEGACY_INIT_PRESENT" "$LEGACY_DISABLED_PRESENT" "$LEGACY_WAS_RUNNING" "$RAZ_WAS_RUNNING"; do
  case "$VALUE" in 0|1) ;; *) echo "Invalid rollback manifest" >&2; exit 1 ;; esac
done

if [ "$AUTO" -ne 1 ]; then
  echo "Rollback snapshot: $BACKUP"
  echo "This will stop the current RAZVILKA process and restore the listed snapshot."
fi

if [ -x "$RAZ_INIT" ]; then
  RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop || true
fi
if [ -x "$BINDIR/razvilka" ]; then
  "$BINDIR/razvilka" -deactivate-dataplane \
    -stage "$STATEDIR/staging" \
    -backups "$STATEDIR/backups" \
    -dataplane-state "$STATEDIR/dataplane" >/dev/null
fi

restore_or_remove() {
  PRESENT="$1"
  SNAPSHOT="$2"
  TARGET="$3"
  MODE_BITS="$4"
  if [ "$PRESENT" -eq 1 ]; then
    [ -f "$BACKUP/$SNAPSHOT" ] || { echo "Snapshot file missing: $SNAPSHOT" >&2; return 1; }
    TMP="$TARGET.razvilka-rollback-$$"
    cp "$BACKUP/$SNAPSHOT" "$TMP"
    chmod "$MODE_BITS" "$TMP"
    mv "$TMP" "$TARGET"
  else
    rm -f "$TARGET"
  fi
}

mkdir -p "$APPDIR" "$BINDIR" "$INITDIR"
restore_or_remove "$RAZ_BINARY_PRESENT" razvilka.bin "$BINDIR/razvilka" 755
restore_or_remove "$RAZ_INIT_PRESENT" S99razvilka "$RAZ_INIT" 755
restore_or_remove "$CONFIG_PRESENT" config.json "$APPDIR/config.json" 600
restore_or_remove "$CATALOG_PRESENT" service-catalog.json "$APPDIR/service-catalog.json" 600
restore_or_remove "$COMMUNITY_PRESENT" community-catalog.json "$APPDIR/community-catalog.json" 600
restore_or_remove "$SOURCES_PRESENT" sources.json "$APPDIR/sources.json" 600
restore_or_remove "$SOURCE_STATE_PRESENT" source-state.json "$APPDIR/source-state.json" 600
restore_or_remove "$TOKEN_PRESENT" admin.token "$APPDIR/admin.token" 600
restore_or_remove "$CREDENTIALS_PRESENT" admin.credentials.json "$APPDIR/admin.credentials.json" 600
restore_or_remove "$CUSTOM_SERVICES_PRESENT" custom-services.json "$APPDIR/custom-services.json" 600
restore_or_remove "$DEVICES_PRESENT" devices.json "$APPDIR/devices.json" 600

# Restore the committed runtime metadata removed by the upgrade's controlled
# deactivation. The target is the fixed dataplane child of the validated base,
# never a user-provided path.
rm -rf "$STATEDIR/dataplane"
if [ "$DATAPLANE_STATE_PRESENT" -eq 1 ]; then
  [ -d "$BACKUP/dataplane" ] && [ ! -L "$BACKUP/dataplane" ] || { echo "Dataplane snapshot is missing or unsafe" >&2; exit 1; }
  mkdir -p "$STATEDIR/dataplane"
  cp -a "$BACKUP/dataplane/." "$STATEDIR/dataplane/"
fi

restore_or_remove "$LEGACY_INIT_PRESENT" S99artem-flow "$LEGACY_INIT" 755
restore_or_remove "$LEGACY_DISABLED_PRESENT" S99artem-flow.razvilka-disabled "$LEGACY_DISABLED" 755

rm -f "$STATEDIR/start-failures" "$STATEDIR/boot-disabled"
if [ "$RAZ_WAS_RUNNING" -eq 1 ] && [ "$RAZ_INIT_PRESENT" -eq 1 ]; then
  RAZVILKA_BASE="$BASE" "$RAZ_INIT" start
elif [ "$LEGACY_WAS_RUNNING" -eq 1 ]; then
  if [ -x "$LEGACY_INIT" ]; then
    "$LEGACY_INIT" start
  elif [ -x "$LEGACY_DISABLED" ]; then
    "$LEGACY_DISABLED" start
  else
    echo "Legacy ARTEM Flow was running but its restored init script is unavailable" >&2
    exit 1
  fi
fi

echo "Rollback complete: $BACKUP"
