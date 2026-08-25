#!/bin/sh
# Minimal network bootstrap for Keenetic / Netcraze routers with Entware.
# Downloads the official release bundle, verifies its SHA-256 and delegates all
# writes to the transactional installer shipped in that exact release.
set -eu
umask 077

PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
REPOSITORY="${RAZVILKA_REPOSITORY:-ArtixSx/RAZVILKA}"
VERSION="${RAZVILKA_VERSION:-latest}"
FROM_ARTEM=0
WITH_COMPONENTS=0

if [ -t 1 ]; then
  C_BLUE='\033[1;36m'; C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'; C_DIM='\033[2m'; C_RESET='\033[0m'
else
  C_BLUE=''; C_GREEN=''; C_YELLOW=''; C_DIM=''; C_RESET=''
fi
step() { printf '%b[%s]%b %s\n' "$C_BLUE" "$1" "$C_RESET" "$2"; }
ok() { printf '%b[OK]%b %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf '%b[! ]%b %s\n' "$C_YELLOW" "$C_RESET" "$1"; }

printf '%b\n' "$C_BLUE"
echo '+============================================================+'
echo '|                    RAZVILKA для Entware                    |'
echo '|        Единая панель сервисов, обходов и маршрутов         |'
echo '+============================================================+'
printf '%b' "$C_RESET"

for ARG in "$@"; do
  case "$ARG" in
    --from-artem-flow) FROM_ARTEM=1 ;;
    --with-components|--starter-pack) WITH_COMPONENTS=1 ;;
    --without-components) WITH_COMPONENTS=0 ;; # legacy compatibility; UI-only is now the default
    -h|--help)
      echo "Usage: sh bootstrap.sh [--from-artem-flow] [--starter-pack]"
      echo "Default: install only the RAZVILKA UI/control plane."
      echo "Optional environment: RAZVILKA_VERSION=v0.16.0 (or latest)"
      exit 0
      ;;
    *) echo "Unknown option: $ARG" >&2; exit 2 ;;
  esac
done

step '1/5' 'Проверяю Entware и системные инструменты…'
[ -d /opt ] || {
  echo "ОШИБКА: раздел Entware /opt не найден." >&2
  echo "Сначала установите Entware для своей модели Keenetic/Netcraze, затем повторите команду." >&2
  exit 10
}
command -v opkg >/dev/null 2>&1 || {
  echo "ОШИБКА: opkg не найден в /opt. Установка Entware не завершена или /opt не подключён." >&2
  exit 11
}
if ! command -v sha256sum >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
  echo "ОШИБКА: не хватает инструментов для безопасной проверки и распаковки релиза." >&2
  echo "Выполните:" >&2
  echo "  opkg update" >&2
  echo "  opkg install ca-certificates coreutils-sha256sum tar" >&2
  exit 12
fi
ok "Entware готов; архитектура: $(uname -m)"

if [ "$VERSION" = latest ]; then
  DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/latest/download"
else
  case "$VERSION" in v*) : ;; *) VERSION="v$VERSION" ;; esac
  DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/download/$VERSION"
fi

TMP_ROOT="${TMPDIR:-/opt/tmp}"
mkdir -p "$TMP_ROOT"
WORKDIR="$(mktemp -d "$TMP_ROOT/razvilka-install.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT HUP INT TERM
BUNDLE="$WORKDIR/RAZVILKA-entware.tar.gz"
CHECKSUM="$WORKDIR/RAZVILKA-entware.tar.gz.sha256"

download() {
  URL="$1"
  DEST="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --retry 2 --output "$DEST" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$DEST" "$URL"
  else
    echo "ОШИБКА: не найден ни curl, ни HTTPS-версия wget." >&2
    echo "Установите один из вариантов:" >&2
    echo "  opkg update && opkg install curl" >&2
    echo "или:" >&2
    echo "  opkg update && opkg install wget-ssl" >&2
    echo "Если wget-ssl конфликтует с wget-nossl: opkg remove wget-nossl && opkg install wget-ssl" >&2
    exit 14
  fi
}

step '2/5' "Загружаю проверенный релиз ${VERSION}…"
download "$DOWNLOAD_BASE/RAZVILKA-entware.tar.gz" "$BUNDLE"
download "$DOWNLOAD_BASE/RAZVILKA-entware.tar.gz.sha256" "$CHECKSUM"

step '3/5' 'Проверяю SHA-256 архива…'
(cd "$WORKDIR" && sha256sum -c "$(basename "$CHECKSUM")")
ok 'Контрольная сумма совпала'

step '4/5' 'Распаковываю релиз во временную папку…'
tar -xzf "$BUNDLE" -C "$WORKDIR"
INSTALLER=""
for CANDIDATE in "$WORKDIR"/RAZVILKA-*/scripts/install-entware.sh; do
  if [ -f "$CANDIDATE" ]; then INSTALLER="$CANDIDATE"; break; fi
done
[ -n "$INSTALLER" ] && [ -f "$INSTALLER" ] || { echo "ОШИБКА: в архиве релиза не найден штатный установщик" >&2; exit 15; }
RELEASE_ROOT="$(CDPATH= cd -- "$(dirname -- "$INSTALLER")/.." && pwd)"
case "$RELEASE_ROOT" in "$WORKDIR"/*) : ;; *) echo "ОШИБКА: небезопасная структура архива" >&2; exit 16 ;; esac

step '5/5' 'Запускаю установку со снимком и автоматическим rollback…'
set --
if [ "$FROM_ARTEM" -eq 1 ]; then set -- "$@" --from-artem-flow; fi
if [ "$WITH_COMPONENTS" -eq 1 ]; then set -- "$@" --with-components; fi
sh "$INSTALLER" "$@"
