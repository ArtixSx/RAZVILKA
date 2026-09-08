#!/bin/sh
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
case "$BASE" in
  /*) ;;
  *) echo "RAZVILKA_BASE must be an absolute directory" >&2; exit 1 ;;
esac
[ -d "$BASE" ] && [ ! -L "$BASE" ] || { echo "RAZVILKA_BASE is missing or unsafe: $BASE" >&2; exit 1; }
BASE="$(CDPATH= cd -- "$BASE" && pwd -P)"
[ "$BASE" != / ] || { echo "Refusing to use the filesystem root as RAZVILKA_BASE" >&2; exit 1; }
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
PRIVATE_RESTORE_PROTOCOL=0
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
# "skip" keeps old snapshots backward compatible: historical manifests did
# not include these private mutable directories and must never delete them.
STAGING_PRESENT=skip
CLOUDFLARE_PRIVATE_PRESENT=skip
LEGACY_INIT_PRESENT=
LEGACY_DISABLED_PRESENT=
LEGACY_WAS_RUNNING=
RAZ_WAS_RUNNING=
while IFS='=' read -r KEY VALUE; do
  case "$KEY" in
    PRIVATE_RESTORE_PROTOCOL) PRIVATE_RESTORE_PROTOCOL="$VALUE" ;;
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
    STAGING_PRESENT) STAGING_PRESENT="$VALUE" ;;
    CLOUDFLARE_PRIVATE_PRESENT) CLOUDFLARE_PRIVATE_PRESENT="$VALUE" ;;
    LEGACY_INIT_PRESENT) LEGACY_INIT_PRESENT="$VALUE" ;;
    LEGACY_DISABLED_PRESENT) LEGACY_DISABLED_PRESENT="$VALUE" ;;
    LEGACY_WAS_RUNNING) LEGACY_WAS_RUNNING="$VALUE" ;;
    RAZ_WAS_RUNNING) RAZ_WAS_RUNNING="$VALUE" ;;
    *) echo "Unknown rollback manifest key: $KEY" >&2; exit 1 ;;
  esac
done <"$BACKUP/manifest"
for VALUE in "$PRIVATE_RESTORE_PROTOCOL" "$RAZ_BINARY_PRESENT" "$RAZ_INIT_PRESENT" "$CONFIG_PRESENT" "$CATALOG_PRESENT" "$COMMUNITY_PRESENT" "$SOURCES_PRESENT" "$SOURCE_STATE_PRESENT" "$TOKEN_PRESENT" "$CREDENTIALS_PRESENT" "$CUSTOM_SERVICES_PRESENT" "$DEVICES_PRESENT" "$DATAPLANE_STATE_PRESENT" "$LEGACY_INIT_PRESENT" "$LEGACY_DISABLED_PRESENT" "$LEGACY_WAS_RUNNING" "$RAZ_WAS_RUNNING"; do
  case "$VALUE" in 0|1) ;; *) echo "Invalid rollback manifest" >&2; exit 1 ;; esac
done
for VALUE in "$STAGING_PRESENT" "$CLOUDFLARE_PRIVATE_PRESENT"; do
  case "$VALUE" in 0|1|skip) ;; *) echo "Invalid rollback manifest" >&2; exit 1 ;; esac
done

require_snapshot_file() {
  PRESENT="$1"
  NAME="$2"
  if [ "$PRESENT" -eq 1 ]; then
    [ -f "$BACKUP/$NAME" ] && [ ! -L "$BACKUP/$NAME" ] || { echo "Snapshot file is missing or unsafe: $NAME" >&2; exit 1; }
  fi
}
require_snapshot_dir() {
  PRESENT="$1"
  NAME="$2"
  case "$PRESENT" in
    1) [ -d "$BACKUP/$NAME" ] && [ ! -L "$BACKUP/$NAME" ] || { echo "Snapshot directory is missing or unsafe: $NAME" >&2; exit 1; } ;;
    0|skip) ;;
  esac
}

require_snapshot_file "$RAZ_BINARY_PRESENT" razvilka.bin
require_snapshot_file "$RAZ_INIT_PRESENT" S99razvilka
require_snapshot_file "$CONFIG_PRESENT" config.json
require_snapshot_file "$CATALOG_PRESENT" service-catalog.json
require_snapshot_file "$COMMUNITY_PRESENT" community-catalog.json
require_snapshot_file "$SOURCES_PRESENT" sources.json
require_snapshot_file "$SOURCE_STATE_PRESENT" source-state.json
require_snapshot_file "$TOKEN_PRESENT" admin.token
require_snapshot_file "$CREDENTIALS_PRESENT" admin.credentials.json
require_snapshot_file "$CUSTOM_SERVICES_PRESENT" custom-services.json
require_snapshot_file "$DEVICES_PRESENT" devices.json
require_snapshot_file "$LEGACY_INIT_PRESENT" S99artem-flow
require_snapshot_file "$LEGACY_DISABLED_PRESENT" S99artem-flow.razvilka-disabled
require_snapshot_dir "$DATAPLANE_STATE_PRESENT" dataplane
require_snapshot_dir "$STAGING_PRESENT" staging
require_snapshot_dir "$CLOUDFLARE_PRIVATE_PRESENT" cloudflare-private

# Registration requests are monotonic external effects. Keep native WARP state
# in place, and never start an old binary that cannot see an unresolved request.
require_native_enrollment_schema() {
  SUBSCRIPTION_REQUIRED=0
  for SUBSCRIPTION_STATE in "$APPDIR/subscriptions-private/subscriptions.private.json" \
    "$APPDIR/private-restore-feeds-v1/restore.private.json"; do
    if [ -e "$SUBSCRIPTION_STATE" ] || [ -L "$SUBSCRIPTION_STATE" ]; then
      [ -f "$SUBSCRIPTION_STATE" ] && [ ! -L "$SUBSCRIPTION_STATE" ] || { echo "Private subscription state is unsafe; installation unchanged" >&2; return 1; }
      SUBSCRIPTION_REQUIRED=1
    fi
  done
  if [ "$SUBSCRIPTION_REQUIRED" -eq 1 ]; then
    SUBSCRIPTION_SCHEMA="$("$1" -subscription-schema 2>/dev/null)" || { echo "Target binary cannot preserve private subscriptions; installation unchanged" >&2; return 1; }
    [ "$SUBSCRIPTION_SCHEMA" = 1 ] || { echo "Target binary has an incompatible subscription schema; installation unchanged" >&2; return 1; }
  fi
  NATIVE_REQUIRED=0
  # Empty journal directories exist on every startup. Only files are evidence
  # of this protocol; a retained restore journal is conservatively included.
  for NATIVE_STATE in "$STATEDIR/warp/native-enrollment.private.json" \
    "$STATEDIR/warp/native-enrollment/current.json" "$STATEDIR/warp/native-enrollment/pending.json" \
    "$APPDIR/private-restore-native-v1/restore.private.json"; do
    if [ -e "$NATIVE_STATE" ] || [ -L "$NATIVE_STATE" ]; then
      [ -f "$NATIVE_STATE" ] && [ ! -L "$NATIVE_STATE" ] || { echo "Native WARP state is unsafe; installation unchanged" >&2; return 1; }
      NATIVE_REQUIRED=1
    fi
  done
  if [ "$NATIVE_REQUIRED" -eq 1 ]; then
    NATIVE_SCHEMA="$("$1" -native-enrollment-schema 2>/dev/null)" || {
      echo "Target binary cannot preserve native WARP registration state; installation unchanged" >&2; return 1;
    }
    [ "$NATIVE_SCHEMA" = 1 ] || { echo "Target binary has an incompatible native WARP schema; installation unchanged" >&2; return 1; }
  fi
}
if [ "$RAZ_BINARY_PRESENT" -eq 1 ]; then
  require_native_enrollment_schema "$BACKUP/razvilka.bin"
fi

if [ "$PRIVATE_RESTORE_PROTOCOL" -eq 1 ]; then
  [ -f "$BINDIR/razvilka" ] && [ ! -L "$BINDIR/razvilka" ] && [ -x "$BINDIR/razvilka" ] || {
    echo "Current RAZVILKA binary cannot settle the private restore journal" >&2
    exit 1
  }
fi

if [ "$AUTO" -ne 1 ]; then
  echo "Rollback snapshot: $BACKUP"
  echo "This will stop the current RAZVILKA process and restore the listed snapshot."
fi

CURRENT_WAS_RUNNING=0
if [ -x "$RAZ_INIT" ]; then
  if RAZVILKA_BASE="$BASE" "$RAZ_INIT" status >/dev/null 2>&1; then
    CURRENT_WAS_RUNNING=1
  fi
  RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop
elif command -v pidof >/dev/null 2>&1 && [ -n "$(pidof razvilka 2>/dev/null || true)" ]; then
  echo "RAZVILKA is running but its init script is unavailable; rollback was not started" >&2
  exit 1
fi
# A registration can complete its local checkpoint during graceful shutdown.
# No files have changed yet, so a compatibility refusal can restart this app.
if [ "$RAZ_BINARY_PRESENT" -eq 1 ] && ! require_native_enrollment_schema "$BACKUP/razvilka.bin"; then
  if [ "$CURRENT_WAS_RUNNING" -eq 1 ]; then
    RAZVILKA_BASE="$BASE" "$RAZ_INIT" start >/dev/null 2>&1 || echo "Could not restart the unchanged RAZVILKA process" >&2
  fi
  exit 1
fi
if [ "$PRIVATE_RESTORE_PROTOCOL" -eq 1 ]; then
  RECOVERY_OUTPUT="$("$BINDIR/razvilka" -recover-private-restore \
    -config "$APPDIR/config.json" \
    -custom-services "$APPDIR/custom-services.json" \
    -devices "$APPDIR/devices.json" \
    -stage "$STATEDIR/staging" \
    -warp-state "$STATEDIR/warp" \
    -cloudflare-state "$APPDIR/cloudflare-private")"
  printf '%s\n' "$RECOVERY_OUTPUT" | grep -q '"ok":true' || {
    echo "Private restore recovery did not report success; rollback was not started" >&2
    exit 1
  }
fi
# Settling a pending restore can materialize a native image that was absent
# before recovery. Recheck before deactivating or replacing the current app.
if [ "$RAZ_BINARY_PRESENT" -eq 1 ] && ! require_native_enrollment_schema "$BACKUP/razvilka.bin"; then
  if [ "$CURRENT_WAS_RUNNING" -eq 1 ]; then
    RAZVILKA_BASE="$BASE" "$RAZ_INIT" start >/dev/null 2>&1 || echo "Could not restart the unchanged RAZVILKA process" >&2
  fi
  exit 1
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

restore_dir() {
  PRESENT="$1"
  NAME="$2"
  TARGET="$3"
  case "$PRESENT" in
    skip) return 0 ;;
  esac
  case "$TARGET" in
    "$BASE"/*) ;;
    *) echo "Refusing unsafe rollback target: $TARGET" >&2; return 1 ;;
  esac
  rm -rf "$TARGET"
  if [ "$PRESENT" -eq 1 ]; then
    mkdir -p "$TARGET"
    cp -a "$BACKUP/$NAME/." "$TARGET/"
  fi
}

# Restore mutable directory images only after the current journal is idle.
# The journal itself is deliberately never copied or removed.
restore_dir "$DATAPLANE_STATE_PRESENT" dataplane "$STATEDIR/dataplane"
restore_dir "$STAGING_PRESENT" staging "$STATEDIR/staging"
restore_dir "$CLOUDFLARE_PRIVATE_PRESENT" cloudflare-private "$APPDIR/cloudflare-private"

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
