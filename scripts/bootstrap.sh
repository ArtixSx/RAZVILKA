#!/bin/sh
# Minimal network bootstrap for Keenetic / Netcraze routers with Entware.
# Downloads the official release bundle, verifies its SHA-256 and delegates all
# writes to the transactional installer shipped in that exact release.
set -eu
umask 077

BASE="${RAZVILKA_BASE:-/opt}"
case "$BASE" in /*) ;; *) echo "RAZVILKA_BASE must be an absolute directory" >&2; exit 1 ;; esac
# Entware commonly exposes /opt through a link. Resolve only this explicit
# installation root; a link resolving to / is never a valid installation.
[ -d "$BASE" ] || { echo "Entware directory is missing: $BASE" >&2; exit 10; }
BASE="$(CDPATH= cd -- "$BASE" && pwd -P)"
[ "$BASE" != / ] || { echo "Refusing to use the filesystem root as RAZVILKA_BASE" >&2; exit 10; }
PATH="$BASE/sbin:$BASE/bin:$BASE/usr/sbin:$BASE/usr/bin:$PATH"
export PATH
export RAZVILKA_BASE="$BASE"
REPOSITORY="${RAZVILKA_REPOSITORY:-ArtixSx/RAZVILKA}"
VERSION="${RAZVILKA_VERSION:-latest}"
FROM_ARTEM=0
WITH_COMPONENTS=0
ACTION=install

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
    --uninstall|--rollback)
      [ "$ACTION" = install ] || { echo "Choose only one action: --uninstall or --rollback" >&2; exit 2; }
      ACTION="${ARG#--}"
      ;;
    --from-artem-flow) FROM_ARTEM=1 ;;
    --with-components|--starter-pack) WITH_COMPONENTS=1 ;;
    --without-components) WITH_COMPONENTS=0 ;; # legacy compatibility; UI-only is now the default
    -h|--help)
      echo "Usage: sh bootstrap.sh [--from-artem-flow] [--starter-pack] | --uninstall | --rollback"
      echo "Default: install/update the panel. --uninstall removes panel/owned routes and keeps data."
      echo "--rollback explicitly restores the last pre-update snapshot."
      echo "Optional environment: RAZVILKA_VERSION=v<release-tag> (or latest)"
      exit 0
      ;;
    *) echo "Unknown option: $ARG" >&2; exit 2 ;;
  esac
done
[ "$ACTION" = install ] || { [ "$FROM_ARTEM" -eq 0 ] && [ "$WITH_COMPONENTS" -eq 0 ]; } || { echo "Component/migration options apply only to installation" >&2; exit 2; }

step '1/5' 'Проверяю Entware и системные инструменты…'
[ "$(id -u)" = 0 ] || { echo "Run this command as the Entware administrator (root)." >&2; exit 10; }
command -v opkg >/dev/null 2>&1 || {
  echo "ОШИБКА: opkg не найден в /opt. Установка Entware не завершена или /opt не подключён." >&2
  exit 11
}
PACKAGES=""
need_package() {
  case " $PACKAGES " in *" $1 "*) ;; *) PACKAGES="${PACKAGES:+$PACKAGES }$1" ;; esac
}
command -v curl >/dev/null 2>&1 || need_package curl
command -v sha256sum >/dev/null 2>&1 || need_package coreutils-sha256sum
command -v tar >/dev/null 2>&1 || need_package tar
command -v gzip >/dev/null 2>&1 || need_package gzip
command -v mktemp >/dev/null 2>&1 || need_package coreutils-mktemp
command -v readlink >/dev/null 2>&1 || need_package coreutils-readlink
for TOOL in awk od pidof grep; do
  command -v "$TOOL" >/dev/null 2>&1 || need_package busybox
done
[ -x "$BASE/sbin/start-stop-daemon" ] || need_package busybox
if ! command -v ip >/dev/null 2>&1 || ! ip -4 -o addr show >/dev/null 2>&1; then
  need_package ip-full
fi
if [ ! -r "$BASE/etc/ssl/certs/ca-certificates.crt" ] && [ ! -r "$BASE/etc/ssl/cert.pem" ]; then
  need_package ca-bundle
fi
if [ -n "$PACKAGES" ]; then
  step '1/5' "Устанавливаю недостающие инструменты: $PACKAGES"
  opkg update
  # Package names are exclusively the fixed allowlist above. No global upgrade.
  opkg install $PACKAGES
fi
for TOOL in curl sha256sum tar gzip mktemp readlink awk od pidof grep ip; do
  command -v "$TOOL" >/dev/null 2>&1 || { echo "Required tool is still unavailable after opkg: $TOOL" >&2; exit 12; }
done
if [ ! -x "$BASE/sbin/start-stop-daemon" ] || ! ip -4 -o addr show >/dev/null 2>&1; then
  echo "Entware service/IP tools are incomplete; check busybox and ip-full packages." >&2
  exit 12
fi
ok "Entware готов; архитектура: $(uname -m)"

if [ "$VERSION" = latest ]; then
  DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/latest/download"
else
  case "$VERSION" in v*) : ;; *) VERSION="v$VERSION" ;; esac
  DOWNLOAD_BASE="https://github.com/$REPOSITORY/releases/download/$VERSION"
fi

TMP_ROOT="${TMPDIR:-$BASE/tmp}"
mkdir -p "$TMP_ROOT"
TMP_ROOT="$(CDPATH= cd -- "$TMP_ROOT" && pwd -P)"
WORKDIR="$(mktemp -d "$TMP_ROOT/razvilka-install.XXXXXX")"
cleanup() {
  case "$WORKDIR" in "$TMP_ROOT"/razvilka-install.*) rm -rf "$WORKDIR" ;; esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
BUNDLE="$WORKDIR/RAZVILKA-entware.tar.gz"
CHECKSUM="$WORKDIR/RAZVILKA-entware.tar.gz.sha256"

download() {
  URL="$1"
  DEST="$2"
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2 --output "$DEST" "$URL"
}

step '2/5' "Загружаю проверенный релиз ${VERSION}…"
download "$DOWNLOAD_BASE/RAZVILKA-entware.tar.gz" "$BUNDLE"
download "$DOWNLOAD_BASE/RAZVILKA-entware.tar.gz.sha256" "$CHECKSUM"

step '3/5' 'Проверяю SHA-256 архива…'
EXPECTED="$(awk '
  NF { sub(/\r$/, ""); count++; name=$2; sub(/^\*/, "", name)
    if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-fA-F]+$/ || name != "RAZVILKA-entware.tar.gz") bad=1
    hash=tolower($1)
  }
  END { if (count != 1 || bad) exit 1; print hash }
' "$CHECKSUM")" || { echo "Invalid release archive checksum manifest" >&2; exit 13; }
ACTUAL="$(sha256sum "$BUNDLE" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "Release archive checksum mismatch" >&2; exit 13; }
ok 'Контрольная сумма совпала'

step '4/5' 'Распаковываю релиз во временную папку…'
# Reject links, special files, path traversal and ambiguous roots before any
# extraction. Release archives contain only one RAZVILKA directory and files.
# BusyBox can normalize dangerous ../ or absolute names while listing them,
# reporting that only on stderr. Never validate its rewritten stdout alone.
if ! tar -tzf "$BUNDLE" >"$WORKDIR/archive.paths" 2>"$WORKDIR/archive.paths.errors" || [ -s "$WORKDIR/archive.paths.errors" ]; then
  echo "Release archive path listing failed or reported unsafe normalization" >&2
  exit 16
fi
RELEASE_NAME="$(awk '
  { if (NF != 1 || $0 ~ /\\/ || $0 ~ /^\// || $0 ~ /(^|\/)\.\.?($|\/)/) bad=1
    split($0, p, "/"); if (p[1] !~ /^RAZVILKA-[0-9A-Za-z._+-]+$/) bad=1
    if (root != "" && root != p[1]) bad=1; root=p[1]
  }
  END { if (bad || root == "") exit 1; print root }
' "$WORKDIR/archive.paths")" || { echo "Unsafe release archive paths" >&2; exit 16; }
if ! tar -tvzf "$BUNDLE" >"$WORKDIR/archive.types" 2>"$WORKDIR/archive.types.errors" || [ -s "$WORKDIR/archive.types.errors" ]; then
  echo "Release archive type listing failed or reported warnings" >&2
  exit 16
fi
awk 'substr($0,1,1) != "-" && substr($0,1,1) != "d" {bad=1} END {exit bad}' "$WORKDIR/archive.types" || { echo "Release archive contains links or special files" >&2; exit 16; }
tar -xzf "$BUNDLE" -C "$WORKDIR"
HELPER="$WORKDIR/$RELEASE_NAME/scripts/$ACTION-entware.sh"
[ -f "$HELPER" ] && [ ! -L "$HELPER" ] || { echo "Release helper is missing: $ACTION" >&2; exit 15; }
if [ "$ACTION" = uninstall ]; then
  grep -q '^# RAZVILKA_UNINSTALL_PRESERVES_DATA=1$' "$HELPER" || {
    echo "This release predates safe panel removal. Select a current release; no uninstall was started." >&2
    exit 15
  }
fi

case "$ACTION" in
  install) step '5/5' 'Устанавливаю панель со снимком и автоматическим возвратом при ошибке…' ;;
  uninstall) step '5/5' 'Удаляю панель и её маршруты; настройки и подключения сохраняются…' ;;
  rollback) step '5/5' 'Возвращаю явно выбранный предыдущий снимок…' ;;
esac
set --
if [ "$FROM_ARTEM" -eq 1 ]; then set -- "$@" --from-artem-flow; fi
if [ "$WITH_COMPONENTS" -eq 1 ]; then set -- "$@" --with-components; fi
sh "$HELPER" "$@"
