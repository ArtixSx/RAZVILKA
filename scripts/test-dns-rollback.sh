#!/bin/sh
set -eu
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) echo 'SKIP DNS rollback: requires Unix permissions and symlinks'; exit 0 ;;
esac
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-dns-rollback.XXXXXX")"
cleanup() {
  case "$TEST_ROOT" in "$TMP_BASE"/razvilka-dns-rollback.*) rm -rf "$TEST_ROOT" ;; *) exit 1 ;; esac
}
trap cleanup EXIT HUP INT TERM

# Test the real rollback script with inert service/executable fixtures. No
# router process, network rule, DNS query or external download is involved.
for MODE in present absent legacy legacy-unsupported missing unsafe-dir unsafe-file invalid; do
  BASE="$TEST_ROOT/$MODE"
  STATE="$BASE/var/lib/razvilka"
  BACKUP="$STATE/update-backups/before"
  mkdir -p "$BACKUP" "$BASE/bin" "$BASE/etc/init.d" "$BASE/etc/razvilka" "$STATE/dns"
  printf '%s\n' '{"schema":5}' >"$STATE/dns/state.json"
  printf '%s\n' retained >"$STATE/dns/unrelated"
  cat >"$BASE/bin/razvilka" <<'BINARY'
#!/bin/sh
if [ "${1:-}" = -check-dns-state ]; then
  [ "$DNS_TEST_MODE" != legacy-unsupported ] || exit 1
  printf '%s\n' '{"ok":true}'
fi
exit 0
BINARY
  cp "$BASE/bin/razvilka" "$BACKUP/razvilka.bin"
  cat >"$BASE/etc/init.d/S99razvilka" <<'INIT'
#!/bin/sh
set -eu
echo "$1" >>"$RAZVILKA_BASE/service-actions"
case "$1" in
  start)
    case "$DNS_TEST_MODE" in
      present) [ "$(cat "$RAZVILKA_BASE/var/lib/razvilka/dns/state.json")" = '{"schema":4}' ] ;;
      absent) [ ! -e "$RAZVILKA_BASE/var/lib/razvilka/dns/state.json" ] ;;
      legacy) [ "$(cat "$RAZVILKA_BASE/var/lib/razvilka/dns/state.json")" = '{"schema":5}' ] ;;
    esac ;;
esac
INIT
  cp "$BASE/etc/init.d/S99razvilka" "$BACKUP/S99razvilka"
  chmod 700 "$BASE/bin/razvilka" "$BASE/etc/init.d/S99razvilka" "$BACKUP/razvilka.bin"
  cat >"$BACKUP/manifest" <<'MANIFEST'
RAZ_BINARY_PRESENT=1
RAZ_INIT_PRESENT=1
CONFIG_PRESENT=0
CATALOG_PRESENT=0
SOURCES_PRESENT=0
TOKEN_PRESENT=0
LEGACY_INIT_PRESENT=0
LEGACY_DISABLED_PRESENT=0
LEGACY_WAS_RUNNING=0
RAZ_WAS_RUNNING=1
MANIFEST
  case "$MODE" in
    absent) echo DNS_STATE_PRESENT=0 >>"$BACKUP/manifest" ;;
    legacy|legacy-unsupported) ;;
    invalid) echo DNS_STATE_PRESENT=2 >>"$BACKUP/manifest" ;;
    *)
      echo DNS_STATE_PRESENT=1 >>"$BACKUP/manifest"
      printf '%s\n' '{"schema":4}' >"$BACKUP/dns-state.json"
      ;;
  esac
  case "$MODE" in
    missing) rm "$BACKUP/dns-state.json" ;;
    unsafe-dir) mv "$STATE/dns" "$BASE/external-dns"; ln -s "$BASE/external-dns" "$STATE/dns" ;;
    unsafe-file) mv "$STATE/dns/state.json" "$BASE/external-state.json"; ln -s "$BASE/external-state.json" "$STATE/dns/state.json" ;;
  esac
  if DNS_TEST_MODE="$MODE" RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/rollback-entware.sh" "$BACKUP" >"$BASE/result" 2>&1; then
    case "$MODE" in present|absent|legacy) ;; *) echo "Unsafe rollback accepted: $MODE"; exit 1 ;; esac
    grep -q '^start$' "$BASE/service-actions"
    [ "$(cat "$STATE/dns/unrelated")" = retained ]
    if [ "$MODE" = present ]; then
      [ "$(ls -ld "$STATE/dns/state.json" | awk '{print $1}')" = -rw------- ]
    fi
  else
    case "$MODE" in legacy-unsupported|missing|unsafe-dir|unsafe-file|invalid) ;; *) cat "$BASE/result"; exit 1 ;; esac
    [ ! -e "$BASE/service-actions" ] || { echo "Refusal came after stopping service: $MODE"; exit 1; }
  fi
  echo "PASS DNS rollback $MODE"
done

# Exercise the actual upgrade snapshot statements independently of platform
# preflight, including absent state; the production daemon test covers all
# other upgrade/restart behavior.
awk '/^backup_file\(\) \{/ {copy=1} copy {print} copy && /^\}$/ {exit}' "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/backup-function.sh"
grep '^backup_file "\$STATEDIR/dns/state.json" dns-state.json$' "$ROOT/scripts/upgrade-entware.sh" >"$TEST_ROOT/backup-call.sh"
grep -q '^DNS_STATE_PRESENT=\$DNS_STATE_PRESENT$' "$ROOT/scripts/upgrade-entware.sh"
STATEDIR="$TEST_ROOT/present/var/lib/razvilka"
BACKUP="$TEST_ROOT/snapshot"
mkdir "$BACKUP"
. "$TEST_ROOT/backup-function.sh"
. "$TEST_ROOT/backup-call.sh"
cmp "$STATEDIR/dns/state.json" "$BACKUP/dns-state.json"
echo 'PASS upgrade snapshots exact DNS schema before starting candidate'
