#!/bin/sh
set -eu
umask 077

MODE=dry-run
FROM_ARTEM=0
for ARG in "$@"; do
  case "$ARG" in
    --dry-run) MODE=dry-run ;;
    --apply) MODE=apply ;;
    --from-artem-flow) FROM_ARTEM=1 ;;
    -h|--help)
      echo "Usage: $0 [--dry-run|--apply] [--from-artem-flow]"
      exit 0
      ;;
    *) echo "Unknown option: $ARG" >&2; exit 2 ;;
  esac
done

BASE="${RAZVILKA_BASE:-/opt}"
APPDIR="$BASE/etc/razvilka"
CACHEDIR="$BASE/var/cache/razvilka"
STATEDIR="$BASE/var/lib/razvilka"
LOGDIR="$BASE/var/log/razvilka"
BINDIR="$BASE/bin"
INITDIR="$BASE/etc/init.d"
BACKUPROOT="$STATEDIR/update-backups"
CURRENT_BACKUP="$STATEDIR/current-backup"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INIT_SOURCE="$HERE/scripts/S99razvilka"
ROLLBACK="$HERE/scripts/rollback-entware.sh"
CATALOG_SOURCE="$HERE/configs/service-catalog.json"
SOURCES_SOURCE="$HERE/configs/sources.json"
EXAMPLE_CONFIG="$HERE/configs/config.example.json"
RAZ_INIT="$INITDIR/S99razvilka"
LEGACY_INIT="$INITDIR/S99artem-flow"
LEGACY_DISABLED="$INITDIR/S99artem-flow.razvilka-disabled"

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  aarch64|arm64) ARCH=arm64 ;;
  mips) ARCH=mips ;;
  mipsel|mipsle) ARCH=mipsle ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac
BIN_SOURCE="$HERE/dist/razvilka-linux-$ARCH"

require_file() {
  [ -f "$1" ] || { echo "Required file is missing: $1" >&2; exit 1; }
}

require_file "$BIN_SOURCE"
require_file "$INIT_SOURCE"
require_file "$ROLLBACK"
require_file "$CATALOG_SOURCE"
require_file "$SOURCES_SOURCE"
require_file "$EXAMPLE_CONFIG"
[ -x "$BIN_SOURCE" ] || { echo "Candidate binary is not executable: $BIN_SOURCE" >&2; exit 1; }
[ -x "$INIT_SOURCE" ] || { echo "Init script is not executable: $INIT_SOURCE" >&2; exit 1; }
[ -x "$ROLLBACK" ] || { echo "Rollback script is not executable: $ROLLBACK" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
[ -x "$BASE/sbin/start-stop-daemon" ] || { echo "$BASE/sbin/start-stop-daemon is required" >&2; exit 1; }

EXPECTED=""
if [ -r "$HERE/dist/SHA256SUMS" ]; then
  EXPECTED="$(awk -v name="razvilka-linux-$ARCH" '$2 == name || $2 == "dist/" name {print $1; exit}' "$HERE/dist/SHA256SUMS")"
fi
ACTUAL="$(sha256sum "$BIN_SOURCE" | awk '{print $1}')"
if [ -n "$EXPECTED" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Candidate checksum mismatch: expected $EXPECTED, got $ACTUAL" >&2
  exit 1
fi

LEGACY_RUNNING_DETECTED=0
if [ -x "$LEGACY_INIT" ] && command -v pidof >/dev/null 2>&1 && [ -n "$(pidof artem-flow 2>/dev/null || true)" ]; then
  LEGACY_RUNNING_DETECTED=1
fi
if [ "$LEGACY_RUNNING_DETECTED" -eq 1 ] && [ "$FROM_ARTEM" -ne 1 ]; then
  echo "ARTEM Flow is running; repeat with --from-artem-flow to authorize a reversible handover" >&2
  exit 1
fi

CONFIG_SOURCE="$APPDIR/config.json"
CONFIG_ORIGIN=razvilka
if [ ! -f "$CONFIG_SOURCE" ]; then
  if [ "$FROM_ARTEM" -eq 1 ] && [ -f "$BASE/etc/artem-flow/config.json" ]; then
    CONFIG_SOURCE="$BASE/etc/artem-flow/config.json"
    CONFIG_ORIGIN=artem-flow
  else
    CONFIG_SOURCE="$EXAMPLE_CONFIG"
    CONFIG_ORIGIN=example
  fi
fi

VERSION="$($BIN_SOURCE -version)"
[ -n "$VERSION" ] || { echo "Candidate did not report a version" >&2; exit 1; }
CHECK_OUTPUT="$($BIN_SOURCE -check -config "$CONFIG_SOURCE" -catalog "$CATALOG_SOURCE" -sources "$SOURCES_SOURCE")"
printf '%s\n' "$CHECK_OUTPUT" | grep -q '"ok": true' || { echo "Candidate preflight did not report success" >&2; exit 1; }

echo "RAZVILKA transactional preflight"
echo "  mode: $MODE"
echo "  version: $VERSION"
echo "  architecture: $ARCH_RAW -> $ARCH"
echo "  binary_sha256: $ACTUAL"
echo "  config_origin: $CONFIG_ORIGIN ($CONFIG_SOURCE)"
echo "  target: $BINDIR/razvilka"
echo "  init: $RAZ_INIT"
printf '%s\n' "$CHECK_OUTPUT"

if [ "$MODE" = dry-run ]; then
  echo "Dry-run complete: no files or services were changed."
  exit 0
fi

mkdir -p "$APPDIR" "$CACHEDIR" "$STATEDIR" "$LOGDIR" "$BINDIR" "$INITDIR" "$BACKUPROOT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP="$BACKUPROOT/$STAMP"
mkdir "$BACKUP"
chmod 700 "$BACKUP"

present() {
  if [ -e "$1" ]; then printf '1'; else printf '0'; fi
}

RAZ_BINARY_PRESENT="$(present "$BINDIR/razvilka")"
RAZ_INIT_PRESENT="$(present "$RAZ_INIT")"
CONFIG_PRESENT="$(present "$APPDIR/config.json")"
CATALOG_PRESENT="$(present "$APPDIR/service-catalog.json")"
SOURCES_PRESENT="$(present "$APPDIR/sources.json")"
TOKEN_PRESENT="$(present "$APPDIR/admin.token")"
LEGACY_INIT_PRESENT="$(present "$LEGACY_INIT")"
LEGACY_DISABLED_PRESENT="$(present "$LEGACY_DISABLED")"
LEGACY_WAS_RUNNING="$LEGACY_RUNNING_DETECTED"
RAZ_WAS_RUNNING=0
if [ -x "$RAZ_INIT" ] && command -v pidof >/dev/null 2>&1 && [ -n "$(pidof razvilka 2>/dev/null || true)" ]; then
  RAZ_WAS_RUNNING=1
fi

cat >"$BACKUP/manifest" <<EOF
RAZ_BINARY_PRESENT=$RAZ_BINARY_PRESENT
RAZ_INIT_PRESENT=$RAZ_INIT_PRESENT
CONFIG_PRESENT=$CONFIG_PRESENT
CATALOG_PRESENT=$CATALOG_PRESENT
SOURCES_PRESENT=$SOURCES_PRESENT
TOKEN_PRESENT=$TOKEN_PRESENT
LEGACY_INIT_PRESENT=$LEGACY_INIT_PRESENT
LEGACY_DISABLED_PRESENT=$LEGACY_DISABLED_PRESENT
LEGACY_WAS_RUNNING=$LEGACY_WAS_RUNNING
RAZ_WAS_RUNNING=$RAZ_WAS_RUNNING
EOF
chmod 600 "$BACKUP/manifest"

backup_file() {
  SRC="$1"
  NAME="$2"
  if [ -f "$SRC" ]; then
    cp -p "$SRC" "$BACKUP/$NAME"
  fi
}

backup_file "$BINDIR/razvilka" razvilka.bin
backup_file "$RAZ_INIT" S99razvilka
backup_file "$APPDIR/config.json" config.json
backup_file "$APPDIR/service-catalog.json" service-catalog.json
backup_file "$APPDIR/sources.json" sources.json
backup_file "$APPDIR/admin.token" admin.token
backup_file "$LEGACY_INIT" S99artem-flow
backup_file "$LEGACY_DISABLED" S99artem-flow.razvilka-disabled

rollback_on_error() {
  CODE="$1"
  trap - EXIT HUP INT TERM
  echo "Upgrade failed; restoring $BACKUP" >&2
  "$ROLLBACK" "$BACKUP" --auto || echo "Automatic rollback failed; manual intervention required" >&2
  exit "$CODE"
}
trap 'rollback_on_error $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$RAZ_WAS_RUNNING" -eq 1 ]; then
  "$RAZ_INIT" stop
fi
if [ "$FROM_ARTEM" -eq 1 ] && [ "$LEGACY_WAS_RUNNING" -eq 1 ]; then
  "$LEGACY_INIT" stop
fi

install_atomic() {
  SRC="$1"
  DST="$2"
  MODE_BITS="$3"
  TMP="$DST.razvilka-update-$$"
  cp "$SRC" "$TMP"
  chmod "$MODE_BITS" "$TMP"
  mv "$TMP" "$DST"
}

install_atomic "$BIN_SOURCE" "$BINDIR/razvilka" 755
install_atomic "$INIT_SOURCE" "$RAZ_INIT" 755
if [ "$CONFIG_PRESENT" -eq 0 ]; then
  install_atomic "$CONFIG_SOURCE" "$APPDIR/config.json" 600
fi
install_atomic "$CATALOG_SOURCE" "$APPDIR/service-catalog.json" 600
install_atomic "$SOURCES_SOURCE" "$APPDIR/sources.json" 600

if [ "$FROM_ARTEM" -eq 1 ] && [ "$LEGACY_INIT_PRESENT" -eq 1 ]; then
  [ ! -e "$LEGACY_DISABLED" ] || { echo "Legacy disabled init already exists: $LEGACY_DISABLED" >&2; false; }
  mv "$LEGACY_INIT" "$LEGACY_DISABLED"
fi

"$BINDIR/razvilka" -migrate-config \
  -config "$APPDIR/config.json" \
  -catalog "$APPDIR/service-catalog.json" \
  -sources "$APPDIR/sources.json" >/dev/null

RAZVILKA_BASE="$BASE" "$RAZ_INIT" clear-guard
RAZVILKA_BASE="$BASE" "$RAZ_INIT" start
RAZVILKA_BASE="$BASE" "$RAZ_INIT" status

printf '%s\n' "$BACKUP" >"$CURRENT_BACKUP"
chmod 600 "$CURRENT_BACKUP"
trap - EXIT HUP INT TERM

LAN_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
[ -n "$LAN_IP" ] || LAN_IP="127.0.0.1"
echo "Upgrade complete. Rollback snapshot: $BACKUP"
echo "Open: http://$LAN_IP:${RAZVILKA_PORT:-8787}"
echo "Admin token file: $APPDIR/admin.token"
echo "Safe Mode remains controlled by $APPDIR/config.json"
