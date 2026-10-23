#!/bin/sh
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
case "$BASE" in
  /*) ;;
  *) echo "RAZVILKA_BASE must be an absolute directory" >&2; exit 1 ;;
esac
[ -d "$BASE" ] || { echo "RAZVILKA_BASE is missing: $BASE" >&2; exit 1; }
BASE="$(CDPATH= cd -- "$BASE" && pwd -P)"
[ "$BASE" != / ] || { echo "Refusing to use the filesystem root as RAZVILKA_BASE" >&2; exit 1; }
PATH="$BASE/sbin:$BASE/bin:$BASE/usr/sbin:$BASE/usr/bin:$PATH"
export PATH
STATEDIR="$BASE/razvilka/state"
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

require_installation_paths() {
  for DIR in "$BASE" "$BINDIR" "$BASE/etc" "$INITDIR" "$APPDIR" "$BASE/razvilka" \
    "$BASE/razvilka/run" "$STATEDIR" "$BACKUPROOT"; do
    [ ! -L "$DIR" ] && { [ ! -e "$DIR" ] || [ -d "$DIR" ]; } || {
      echo "Unsafe installation directory: $DIR; rollback not started" >&2; return 1;
    }
    case "$DIR" in
      "$BASE/razvilka"|"$BASE/razvilka/"*)
        if [ -d "$DIR" ]; then
          PRIVATE_OWNER="$(LC_ALL=C ls -nd -- "$DIR" | awk '
            NR == 1 && $3 ~ /^[0-9]+$/ && substr($1,1,1) == "d" && substr($1,6,1) != "w" && substr($1,9,1) != "w" { print $3; ok=1 }
            END { if (NR != 1 || !ok) exit 1 }
          ')" && [ "$PRIVATE_OWNER" = "$(id -u)" ] || {
            echo "Unsafe private installation owner or permissions: $DIR; rollback not started" >&2; return 1;
          }
        fi ;;
    esac
  done
  [ ! -L "$STATEDIR/current-backup" ] && { [ ! -e "$STATEDIR/current-backup" ] || [ -f "$STATEDIR/current-backup" ]; } || {
    echo "Unsafe current backup pointer; rollback not started" >&2; return 1;
  }
}
require_installation_paths

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
DNS_STATE_PRESENT=skip
AUTONOMY_STATE_PRESENT=skip
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
    DNS_STATE_PRESENT) DNS_STATE_PRESENT="$VALUE" ;;
    AUTONOMY_STATE_PRESENT) AUTONOMY_STATE_PRESENT="$VALUE" ;;
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
for VALUE in "$STAGING_PRESENT" "$CLOUDFLARE_PRIVATE_PRESENT" "$DNS_STATE_PRESENT" "$AUTONOMY_STATE_PRESENT"; do
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
if [ "$DNS_STATE_PRESENT" != skip ]; then
  require_snapshot_file "$DNS_STATE_PRESENT" dns-state.json
fi
if [ "$AUTONOMY_STATE_PRESENT" != skip ]; then
  require_snapshot_file "$AUTONOMY_STATE_PRESENT" autonomy-state.json
fi
[ ! -L "$APPDIR" ] && { [ ! -e "$APPDIR" ] || [ -d "$APPDIR" ]; } || { echo "Autonomy directory is unsafe" >&2; exit 1; }
[ ! -L "$APPDIR/config.json.automation.json.autonomy.json" ] && { [ ! -e "$APPDIR/config.json.automation.json.autonomy.json" ] || [ -f "$APPDIR/config.json.automation.json.autonomy.json" ]; } || { echo "Autonomy state file is unsafe" >&2; exit 1; }
  # Inspect before stopping anything. DNS state must never be restored through
  # a substituted directory or a symbolic link to another application's data.
  for DIR in "$STATEDIR" "$STATEDIR/dns"; do
    [ ! -L "$DIR" ] && { [ ! -e "$DIR" ] || [ -d "$DIR" ]; } || {
      echo "DNS rollback directory is unsafe" >&2; exit 1;
    }
  done
  [ ! -L "$STATEDIR/dns/state.json" ] && { [ ! -e "$STATEDIR/dns/state.json" ] || [ -f "$STATEDIR/dns/state.json" ]; } || {
    echo "DNS rollback file is unsafe" >&2; exit 1;
  }

# Registration requests are monotonic external effects. Keep native WARP state
# in place, and never start an old binary that cannot see an unresolved request.
probe_self_update_metadata() (
  # These exact metadata entrypoints are read-only, including under Stop.
  # Unsupported flags need the old Go ABI, never a guessed empty response.
  case "$2" in -self-update-read-version|-self-update-schema|-check-self-update-state|-component-update-schema|-check-component-update-state) ;; *) exit 1 ;; esac
  [ -f "$1" ] && [ ! -L "$1" ] && [ -x "$1" ] || { echo "Self update metadata binary is unsafe; installation unchanged" >&2; exit 1; }
  command -v timeout >/dev/null 2>&1 || {
    echo "Bounded self update metadata probe is unavailable; installation unchanged" >&2
    echo "Нужна утилита timeout: opkg install coreutils-timeout" >&2; exit 1;
  }
  SELF_PROBE_DIR="$(mktemp -d "$STATEDIR/.rollback-reader.XXXXXX")" || exit 1
  trap 'rm -f "$SELF_PROBE_DIR/output" "$SELF_PROBE_DIR/error" "$SELF_PROBE_DIR/expected"; rmdir "$SELF_PROBE_DIR"' EXIT
  trap 'exit 1' HUP INT TERM
  SELF_PROBE_CODE=0
  (
    # POSIX -f units are 512 bytes; some shells use 1024. Both are bounded.
    ulimit -f 128 || exit 125
    exec timeout -k 1 5 "$1" "$2"
  ) >"$SELF_PROBE_DIR/output" 2>"$SELF_PROBE_DIR/error" || SELF_PROBE_CODE=$?
  for SELF_PROBE_FILE in output error; do
    SELF_PROBE_BYTES="$(wc -c <"$SELF_PROBE_DIR/$SELF_PROBE_FILE")" || exit 1
    [ "$SELF_PROBE_BYTES" -lt 65536 ] || {
      echo "Self update metadata exceeds its output limit; installation unchanged" >&2; exit 1;
    }
  done
  if [ "$SELF_PROBE_CODE" -eq 0 ] && [ ! -s "$SELF_PROBE_DIR/error" ]; then
    case "$2" in
      -self-update-read-version) SELF_PROBE_VALUES='2 3 4' ;;
      -self-update-schema) SELF_PROBE_VALUES='0 1 2' ;;
      -component-update-schema) SELF_PROBE_VALUES='2 3 4' ;;
      -check-self-update-state|-check-component-update-state) SELF_PROBE_VALUES='{"ok":true}' ;;
    esac
    for SELF_PROBE_VALUE in $SELF_PROBE_VALUES; do
      printf '%s\n' "$SELF_PROBE_VALUE" >"$SELF_PROBE_DIR/expected"
      if cmp -s "$SELF_PROBE_DIR/output" "$SELF_PROBE_DIR/expected"; then
        printf '%s\n' "$SELF_PROBE_VALUE"
        exit 0
      fi
    done
  fi
  if [ "$2" != -check-self-update-state ] && [ "$2" != -check-component-update-state ] && [ "$SELF_PROBE_CODE" -eq 2 ] && [ ! -s "$SELF_PROBE_DIR/output" ] &&
    IFS= read -r SELF_PROBE_FIRST <"$SELF_PROBE_DIR/error" && [ "$SELF_PROBE_FIRST" = "flag provided but not defined: $2" ]; then
    printf '%s\n' unsupported
    exit 0
  fi
  echo "Self update metadata is unknown or incompatible; installation unchanged" >&2
  exit 1
)

require_target_self_update_compatibility() {
  SELF_TARGET_READER="$(probe_self_update_metadata "$1" -self-update-read-version)" || return 1
  case "$SELF_TARGET_READER" in
    unsupported) return 0 ;; # Existing selected-backup/private-state gates still apply.
    3|4)
      # Fixed production roots only; no shell backup or public root arguments.
      probe_self_update_metadata "$1" -check-self-update-state >/dev/null || return 1
      ;;
    *) echo "Target controller requires the journaled self update workflow; raw rollback is unavailable" >&2; return 1 ;;
  esac
}

require_legacy_file_protocol_free() {
  for SELF_PROTOCOL_PATH in "$STATEDIR/self-update/current.json" "$STATEDIR/self-update-files/current.json" "$STATEDIR/self-update-stop"; do
    if [ -e "$SELF_PROTOCOL_PATH" ] || [ -L "$SELF_PROTOCOL_PATH" ]; then
      echo "Use matching self update recovery; raw application replacement is unavailable with retained control/file protocol" >&2
      return 1
    fi
  done
  for SELF_PROTOCOL_DIR in "$STATEDIR/self-update" "$STATEDIR/self-update-files"; do
    if [ -e "$SELF_PROTOCOL_DIR" ] || [ -L "$SELF_PROTOCOL_DIR" ]; then
      [ -d "$SELF_PROTOCOL_DIR" ] && [ ! -L "$SELF_PROTOCOL_DIR" ] && [ -r "$SELF_PROTOCOL_DIR" ] && [ -x "$SELF_PROTOCOL_DIR" ] || {
        echo "Self update protocol directory is unsafe; installation unchanged" >&2; return 1;
      }
      SELF_PROTOCOL_CONTENTS="$(LC_ALL=C ls -A "$SELF_PROTOCOL_DIR" 2>/dev/null && printf '|')" || {
        echo "Self update protocol directory cannot be inspected; installation unchanged" >&2; return 1;
      }
      # The sentinel preserves even entries consisting entirely of newlines.
      [ "$SELF_PROTOCOL_CONTENTS" = '|' ] || {
        echo "Use matching self update recovery; raw application replacement is unavailable with retained protocol artifacts" >&2
        return 1
      }
    fi
  done
  if [ -f "$BINDIR/razvilka" ] && [ -x "$BINDIR/razvilka" ]; then
    SELF_PROTOCOL_READER="$(probe_self_update_metadata "$BINDIR/razvilka" -self-update-read-version)" || return 1
    [ "$SELF_PROTOCOL_READER" = unsupported ] || {
      echo "This controller requires the journaled self update workflow; raw application replacement is unavailable" >&2; return 1;
    }
    SELF_PROTOCOL_SCHEMA="$(probe_self_update_metadata "$BINDIR/razvilka" -self-update-schema)" || return 1
    case "$SELF_PROTOCOL_SCHEMA" in
      unsupported|0|1) ;;
      *) echo "This controller requires the journaled self update workflow; raw application replacement is unavailable" >&2; return 1 ;;
    esac
  fi
}

require_node_history_compatibility() {
  NODE_HISTORY_COMPATIBILITY="$("$1" -check-node-history-state -node-history-config-root "$APPDIR" -node-history-state-root "$STATEDIR" 2>/dev/null)" || {
    echo "Target binary cannot read all retained node history; installation unchanged" >&2; return 1;
  }
  [ "$NODE_HISTORY_COMPATIBILITY" = '{"ok":true}' ] || {
    echo "Retained node history compatibility not confirmed; installation unchanged" >&2; return 1;
  }
}

require_native_enrollment_schema() {
  # Retain both application handoff and file-phase receipts through downgrade.
  # Empty directories alone do not opt an installation into this protocol.
  SELF_UPDATE_REQUIRED=0
  for SELF_UPDATE_DIR in "$STATEDIR/self-update" "$STATEDIR/self-update-files"; do
    if [ -e "$SELF_UPDATE_DIR" ] || [ -L "$SELF_UPDATE_DIR" ]; then
      [ -d "$SELF_UPDATE_DIR" ] && [ ! -L "$SELF_UPDATE_DIR" ] || { echo "Self update directory is unsafe; installation unchanged" >&2; return 1; }
    fi
  done
  for SELF_UPDATE_RECEIPT in "$STATEDIR/self-update/current.json" "$STATEDIR/self-update-files/current.json"; do
    if [ -e "$SELF_UPDATE_RECEIPT" ] || [ -L "$SELF_UPDATE_RECEIPT" ]; then
      [ -f "$SELF_UPDATE_RECEIPT" ] && [ ! -L "$SELF_UPDATE_RECEIPT" ] || { echo "Self update receipt is unsafe; installation unchanged" >&2; return 1; }
      SELF_UPDATE_REQUIRED=1
    fi
  done
  if [ "$SELF_UPDATE_REQUIRED" -eq 1 ]; then
    SELF_UPDATE_SCHEMA="$("$1" -self-update-schema 2>/dev/null)" || { echo "Target binary cannot preserve self update recovery; installation unchanged" >&2; return 1; }
    [ "$SELF_UPDATE_SCHEMA" = 2 ] || { echo "Target binary has an incompatible self update schema; installation unchanged" >&2; return 1; }
  fi
  # Never restore an old process over a retained package-operation fence.
  # Recheck after quiescing; a transaction can appear after initial preflight.
  COMPONENT_JOURNAL="$STATEDIR/components/update-journal/current.json"
  if [ -e "$COMPONENT_JOURNAL" ] || [ -L "$COMPONENT_JOURNAL" ]; then
    [ -f "$COMPONENT_JOURNAL" ] && [ ! -L "$COMPONENT_JOURNAL" ] || { echo "Component update journal is unsafe; installation unchanged" >&2; return 1; }
    # The standalone reader inspects fixed production roots, never a supplied
    # alternate installation. Its declared version alone is not state proof.
    COMPONENT_PRODUCTION_BASE="$(CDPATH= cd -- /opt && pwd -P)" || return 1
    [ "$BASE" = "$COMPONENT_PRODUCTION_BASE" ] || { echo "Retained component state requires the fixed production root; installation unchanged" >&2; return 1; }
    COMPONENT_SCHEMA="$(probe_self_update_metadata "$1" -component-update-schema)" || { echo "Target binary cannot preserve component update recovery; installation unchanged" >&2; return 1; }
    case "$COMPONENT_SCHEMA" in 2|3|4) ;; *) echo "Target binary has an incompatible component update schema; installation unchanged" >&2; return 1 ;; esac
    probe_self_update_metadata "$1" -check-component-update-state >/dev/null || {
      echo "Target binary cannot read retained component update state; installation unchanged" >&2; return 1;
    }
  fi
  if [ "$AUTONOMY_STATE_PRESENT" = skip ] && [ -e "$APPDIR/config.json.automation.json.autonomy.json" ]; then
    AUTONOMY_COMPATIBILITY="$("$1" -check-autonomy-state -config "$APPDIR/config.json" 2>/dev/null)" || {
      echo "Snapshot has no autonomy copy and previous version cannot confirm compatibility; installation unchanged" >&2; return 1;
    }
    [ "$AUTONOMY_COMPATIBILITY" = '{"ok":true}' ] || { echo "Autonomy compatibility not confirmed" >&2; return 1; }
  fi
  if [ "${DNS_STATE_PRESENT:-skip}" = skip ] && { [ -e "$STATEDIR/dns/state.json" ] || [ -L "$STATEDIR/dns/state.json" ]; }; then
    # A historical snapshot has no paired DNS image. Only the target binary
    # can confirm that the retained state is readable, without migrating it.
    DNS_COMPATIBILITY="$("$1" -check-dns-state -dns-state "$STATEDIR/dns/state.json" 2>/dev/null)" || {
      echo "Snapshot has no DNS copy and the previous version cannot confirm compatibility; installation unchanged" >&2; return 1;
    }
    [ "$DNS_COMPATIBILITY" = '{"ok":true}' ] || {
      echo "Previous version did not confirm DNS compatibility; installation unchanged" >&2; return 1;
    }
  fi
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
# This fence also covers paired/archived receipt4. A raw shell selection can
# never restore six old files over later state, even when metadata is readable.
require_legacy_file_protocol_free
if [ "$RAZ_BINARY_PRESENT" -eq 1 ]; then
  require_target_self_update_compatibility "$BACKUP/razvilka.bin"
  require_native_enrollment_schema "$BACKUP/razvilka.bin"
  require_node_history_compatibility "$BACKUP/razvilka.bin"
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

require_legacy_file_protocol_free
require_installation_paths
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
require_legacy_file_protocol_free
# No files have changed yet, so a compatibility refusal can restart this app.
restart_unchanged_after_compatibility_refusal() {
  [ "$CURRENT_WAS_RUNNING" -eq 1 ] || return 0
  # Stop or a retained managed protocol can appear during the target check.
  # Only the legacy path with no such authority may restart unchanged files.
  require_legacy_file_protocol_free || return 0
  RAZVILKA_BASE="$BASE" "$RAZ_INIT" start >/dev/null 2>&1 || echo "Could not restart the unchanged RAZVILKA process" >&2
}
if [ "$RAZ_BINARY_PRESENT" -eq 1 ] && { ! require_target_self_update_compatibility "$BACKUP/razvilka.bin" || ! require_native_enrollment_schema "$BACKUP/razvilka.bin" || ! require_node_history_compatibility "$BACKUP/razvilka.bin"; }; then
  restart_unchanged_after_compatibility_refusal
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
require_legacy_file_protocol_free
# before recovery. Recheck before deactivating or replacing the current app.
if [ "$RAZ_BINARY_PRESENT" -eq 1 ] && { ! require_target_self_update_compatibility "$BACKUP/razvilka.bin" || ! require_native_enrollment_schema "$BACKUP/razvilka.bin" || ! require_node_history_compatibility "$BACKUP/razvilka.bin"; }; then
  restart_unchanged_after_compatibility_refusal
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

require_installation_paths
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
if [ "$DNS_STATE_PRESENT" != skip ]; then
  mkdir -p "$STATEDIR/dns"
  restore_or_remove "$DNS_STATE_PRESENT" dns-state.json "$STATEDIR/dns/state.json" 600
fi
if [ "$AUTONOMY_STATE_PRESENT" != skip ]; then
  restore_or_remove "$AUTONOMY_STATE_PRESENT" autonomy-state.json "$APPDIR/config.json.automation.json.autonomy.json" 600
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
