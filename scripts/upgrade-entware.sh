#!/bin/sh
set -eu
umask 077

MODE=dry-run
FROM_ARTEM=0
INSTALL_COMPONENTS=0
for ARG in "$@"; do
  case "$ARG" in
    --dry-run) MODE=dry-run ;;
    --apply) MODE=apply ;;
    --from-artem-flow) FROM_ARTEM=1 ;;
	--with-components|--starter-pack) INSTALL_COMPONENTS=1 ;;
	--without-components) INSTALL_COMPONENTS=0 ;;
    -h|--help)
      echo "Usage: $0 [--dry-run|--apply] [--from-artem-flow] [--starter-pack]"
      echo "Default: install/update only the RAZVILKA UI/control plane."
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
COMMUNITY_SOURCE="$HERE/configs/community-catalog.json"
SOURCES_SOURCE="$HERE/configs/sources.json"
EXAMPLE_CONFIG="$HERE/configs/config.example.json"
RAZ_INIT="$INITDIR/S99razvilka"
LEGACY_INIT="$INITDIR/S99artem-flow"
LEGACY_DISABLED="$INITDIR/S99artem-flow.razvilka-disabled"
LEGACY_CONTROL=""

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

stage() {
  printf '\n[%s/7] %s\n' "$1" "$2"
}

require_file "$BIN_SOURCE"
require_file "$INIT_SOURCE"
require_file "$ROLLBACK"
require_file "$CATALOG_SOURCE"
require_file "$COMMUNITY_SOURCE"
require_file "$SOURCES_SOURCE"
require_file "$EXAMPLE_CONFIG"
[ -r "$BIN_SOURCE" ] || { echo "Candidate binary is not readable: $BIN_SOURCE" >&2; exit 1; }
[ -r "$INIT_SOURCE" ] || { echo "Init script is not readable: $INIT_SOURCE" >&2; exit 1; }
[ -r "$ROLLBACK" ] || { echo "Rollback script is not readable: $ROLLBACK" >&2; exit 1; }
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
# Windows and some NAS unpackers discard Unix executable bits. Normalizing the
# extracted candidate is safe after its checksum has been verified and avoids a
# manual chmod step; the live binary is still installed atomically with 0755.
if [ ! -x "$BIN_SOURCE" ]; then
  chmod 755 "$BIN_SOURCE" || { echo "Cannot make candidate binary executable: $BIN_SOURCE" >&2; exit 1; }
  echo "Archive mode normalized for candidate binary: $BIN_SOURCE"
fi

LEGACY_RUNNING_DETECTED=0
if [ -x "$LEGACY_INIT" ]; then
  LEGACY_CONTROL="$LEGACY_INIT"
elif [ -x "$LEGACY_DISABLED" ]; then
  # A previously interrupted or manually reverted handover can leave the
  # legacy process alive while its init already has the disabled suffix.
  # Keep that state reversible and use the existing script as the controller.
  LEGACY_CONTROL="$LEGACY_DISABLED"
fi
if [ -n "$LEGACY_CONTROL" ] && command -v pidof >/dev/null 2>&1 && [ -n "$(pidof artem-flow 2>/dev/null || true)" ]; then
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
CHECK_OUTPUT="$($BIN_SOURCE -check -config "$CONFIG_SOURCE" -catalog "$CATALOG_SOURCE" -sources "$SOURCES_SOURCE" -community-catalog "$COMMUNITY_SOURCE")"
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
COMMUNITY_PRESENT="$(present "$APPDIR/community-catalog.json")"
SOURCES_PRESENT="$(present "$APPDIR/sources.json")"
SOURCE_STATE_PRESENT="$(present "$APPDIR/source-state.json")"
TOKEN_PRESENT="$(present "$APPDIR/admin.token")"
CREDENTIALS_PRESENT="$(present "$APPDIR/admin.credentials.json")"
CUSTOM_SERVICES_PRESENT="$(present "$APPDIR/custom-services.json")"
DEVICES_PRESENT="$(present "$APPDIR/devices.json")"
DATAPLANE_STATE_PRESENT="$(present "$STATEDIR/dataplane")"
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
COMMUNITY_PRESENT=$COMMUNITY_PRESENT
SOURCES_PRESENT=$SOURCES_PRESENT
SOURCE_STATE_PRESENT=$SOURCE_STATE_PRESENT
TOKEN_PRESENT=$TOKEN_PRESENT
CREDENTIALS_PRESENT=$CREDENTIALS_PRESENT
CUSTOM_SERVICES_PRESENT=$CUSTOM_SERVICES_PRESENT
DEVICES_PRESENT=$DEVICES_PRESENT
DATAPLANE_STATE_PRESENT=$DATAPLANE_STATE_PRESENT
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
backup_file "$APPDIR/community-catalog.json" community-catalog.json
backup_file "$APPDIR/sources.json" sources.json
backup_file "$APPDIR/source-state.json" source-state.json
backup_file "$APPDIR/admin.token" admin.token
backup_file "$APPDIR/admin.credentials.json" admin.credentials.json
backup_file "$APPDIR/custom-services.json" custom-services.json
backup_file "$APPDIR/devices.json" devices.json
if [ "$DATAPLANE_STATE_PRESENT" -eq 1 ]; then
  mkdir "$BACKUP/dataplane"
  cp -a "$STATEDIR/dataplane/." "$BACKUP/dataplane/"
fi
backup_file "$LEGACY_INIT" S99artem-flow
backup_file "$LEGACY_DISABLED" S99artem-flow.razvilka-disabled

rollback_on_error() {
  CODE="$1"
  trap - EXIT HUP INT TERM
  echo "Upgrade failed; restoring $BACKUP" >&2
  sh "$ROLLBACK" "$BACKUP" --auto || echo "Automatic rollback failed; manual intervention required" >&2
  exit "$CODE"
}
trap 'rollback_on_error $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

stage 1 "Останавливаем текущую версию (обычно 10–15 секунд; не прерывайте)..."
if [ "$RAZ_WAS_RUNNING" -eq 1 ]; then
  "$RAZ_INIT" stop
fi
if [ "$FROM_ARTEM" -eq 1 ] && [ "$LEGACY_WAS_RUNNING" -eq 1 ]; then
  "$LEGACY_CONTROL" stop
fi

stage 2 "Устанавливаем проверенные файлы с безопасными правами..."
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
install_atomic "$COMMUNITY_SOURCE" "$APPDIR/community-catalog.json" 600
install_atomic "$SOURCES_SOURCE" "$APPDIR/sources.json" 600

if [ "$FROM_ARTEM" -eq 1 ] && [ "$LEGACY_INIT_PRESENT" -eq 1 ]; then
  [ ! -e "$LEGACY_DISABLED" ] || { echo "Legacy disabled init already exists: $LEGACY_DISABLED" >&2; false; }
  mv "$LEGACY_INIT" "$LEGACY_DISABLED"
fi

stage 3 "Проверяем и при необходимости мигрируем конфигурацию..."
"$BINDIR/razvilka" -migrate-config \
  -config "$APPDIR/config.json" \
  -catalog "$APPDIR/service-catalog.json" \
  -sources "$APPDIR/sources.json" \
  -community-catalog "$APPDIR/community-catalog.json" >/dev/null

# Quiesce only RAZVILKA-owned runtime objects before replacing engine
# binaries. The committed journal is kept, so the new manager can recover the
# same verified plan after components are updated.
stage 4 "Сохраняем и отключаем только принадлежащий RAZVILKA dataplane (до 2 минут)..."
"$BINDIR/razvilka" -deactivate-dataplane \
  -stage "$STATEDIR/staging" \
  -backups "$STATEDIR/backups" \
  -dataplane-state "$STATEDIR/dataplane" >/dev/null

# The base install is UI-only. The optional starter pack is best-effort and
# runs while managed dataplane is quiescent. Exact GitHub assets are checked
# against upstream checksums.txt; opkg packages are selected only from the
# fixed component registry.
if [ "$INSTALL_COMPONENTS" -eq 1 ]; then
  echo "Installing recommended bypass components..."
  COMPONENT_REPORT="$STATEDIR/component-install-$STAMP.json"
  if "$BINDIR/razvilka" -install-components >"$COMPONENT_REPORT"; then
    chmod 600 "$COMPONENT_REPORT"
    echo "Component report: $COMPONENT_REPORT"
  else
    chmod 600 "$COMPONENT_REPORT" 2>/dev/null || true
    echo "Some components could not be installed; RAZVILKA remains installable and the report is at $COMPONENT_REPORT" >&2
  fi
  echo "AmneziaWG remains platform-gated because it requires a matching Keenetic kernel/userspace runtime."
fi

if [ "$INSTALL_COMPONENTS" -eq 0 ]; then
  echo "Bypass runtimes were not installed automatically; existing components were preserved."
  echo "Open the 'Обходы' section to install only what you need."
fi

# Deactivation intentionally removed live objects before component replacement.
# Restore the exact committed runtime metadata/configs so the new process can
# reconcile them and prove the previous route before the upgrade is accepted.
stage 5 "Возвращаем подтверждённое состояние маршрутов для безопасного reconcile..."
if [ "$DATAPLANE_STATE_PRESENT" -eq 1 ]; then
  mkdir -p "$STATEDIR/dataplane"
  cp -a "$BACKUP/dataplane/." "$STATEDIR/dataplane/"
fi

stage 6 "Запускаем новую версию и ждём восстановления маршрутов (до 130 секунд)..."
RAZVILKA_BASE="$BASE" "$RAZ_INIT" clear-guard
RAZVILKA_BASE="$BASE" "$RAZ_INIT" start
RAZVILKA_BASE="$BASE" "$RAZ_INIT" status
RUNNING_PID="$(RAZVILKA_BASE="$BASE" "$RAZ_INIT" pid)"
stage 7 "Проверяем процесс, HTTP и восстановленный dataplane..."
"$BINDIR/razvilka" -healthcheck "http://$(RAZVILKA_BASE="$BASE" "$RAZ_INIT" lan-ip):${RAZVILKA_PORT:-8787}/api/v1/status" \
  -healthcheck-pid "$RUNNING_PID" -healthcheck-require-dataplane >/dev/null

printf '%s\n' "$BACKUP" >"$CURRENT_BACKUP"
chmod 600 "$CURRENT_BACKUP"
trap - EXIT HUP INT TERM

LAN_IP="$(ip -4 -o addr show br0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
[ -n "$LAN_IP" ] || LAN_IP="127.0.0.1"
echo ""
echo "============================================================"
echo " [OK] RAZVILKA $VERSION установлена и запущена"
echo " Панель: http://$LAN_IP:${RAZVILKA_PORT:-8787}"
echo " Rollback: $BACKUP"
echo ""
if [ "$CREDENTIALS_PRESENT" -eq 0 ]; then
  ADMIN_TOKEN="$(tr -d '\r\n' < "$APPDIR/admin.token")"
  echo " ПЕРВЫЙ ВХОД"
  echo " Ключ настройки: $ADMIN_TOKEN"
  echo ""
  echo " Откройте ссылку и создайте свой логин и пароль:"
  echo " http://$LAN_IP:${RAZVILKA_PORT:-8787}/#setup=$ADMIN_TOKEN"
  echo ""
  echo " Важно: сохраните recovery key в менеджере паролей."
  echo " RAZVILKA не использует и не хранит SSH-пароль роутера."
else
  echo " Существующие логин и пароль UI сохранены."
  echo " Recovery key скрыт и повторно в консоль не выводится."
fi
echo "============================================================"
echo " Рекомендация: сначала откройте мастер настройки и оставьте"
echo " Safe Mode включённым до завершения проверки маршрутов."
