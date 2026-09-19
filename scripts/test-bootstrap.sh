#!/bin/sh
# The real bootstrap runs against a temporary Entware tree. Every network/opkg
# command is a recording fixture; no host package or live installation is used.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
NATIVE_LINKS=1
case "$(uname -s)" in MINGW*|MSYS*) NATIVE_LINKS=0 ;; esac
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-bootstrap.XXXXXX")"
cleanup() { case "$TEST_ROOT" in "$TMP_BASE"/razvilka-bootstrap.*) rm -rf "$TEST_ROOT" ;; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
HOST_SH="$(command -v sh)"
REAL_CP="$(command -v cp)"
REAL_MKDIR="$(command -v mkdir)"
export REAL_CP REAL_MKDIR
mkdir -p "$TEST_ROOT/essential" "$TEST_ROOT/providers" "$TEST_ROOT/source/RAZVILKA-fixture/scripts"
for TOOL in cat chmod cp mkdir rm mv uname sh; do
  REAL_TOOL="$(command -v "$TOOL")"
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$REAL_TOOL" >"$TEST_ROOT/essential/$TOOL"
  chmod 700 "$TEST_ROOT/essential/$TOOL"
done
printf '#!/bin/sh\nprintf "0\\n"\n' >"$TEST_ROOT/essential/id"
chmod 700 "$TEST_ROOT/essential/id"
for TOOL in sha256sum tar gzip mktemp readlink awk od grep; do
  REAL_TOOL="$(command -v "$TOOL")"
  [ -n "$REAL_TOOL" ] || { echo "Bootstrap test needs host $TOOL" >&2; exit 1; }
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$REAL_TOOL" >"$TEST_ROOT/providers/$TOOL"
  chmod 700 "$TEST_ROOT/providers/$TOOL"
done
REAL_TAR="$(command -v tar)"
export REAL_TAR
cat >"$TEST_ROOT/providers/tar" <<'TAR'
#!/bin/sh
set -eu
case "$CASE_NAME:$1" in
  traversal-warning:-tzf)
    printf '%s\n' 'RAZVILKA-fixture/traversal'
    printf '%s\n' "tar: removing leading '../' from member names" >&2
    exit 0
    ;;
  list-failed:-tzf)
    printf '%s\n' 'RAZVILKA-fixture/'
    exit 2
    ;;
  types-warning:-tvzf)
    "$REAL_TAR" "$@"
    printf '%s\n' 'tar: fixture type-list warning' >&2
    exit 0
    ;;
esac
exec "$REAL_TAR" "$@"
TAR
printf '#!/bin/sh\nexit 1\n' >"$TEST_ROOT/providers/pidof"
printf '#!/bin/sh\nexit 0\n' >"$TEST_ROOT/providers/ip"
printf '#!/bin/sh\nexit 99\n' >"$TEST_ROOT/providers/start-stop-daemon"
cat >"$TEST_ROOT/providers/curl" <<'CURL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$CASE_ROOT/downloads"
[ "$CASE_NAME" != download-failed ] || exit 22
DEST=""
URL=""
while [ "$#" -gt 0 ]; do
  case "$1" in --output) shift; DEST="$1" ;; esac
  URL="$1"
  shift
done
case "$URL" in
  https://github.com/ArtixSx/RAZVILKA/releases/*/RAZVILKA-entware.tar.gz) "$REAL_CP" "$CASE_ROOT/bundle.tar.gz" "$DEST" ;;
  https://github.com/ArtixSx/RAZVILKA/releases/*/RAZVILKA-entware.tar.gz.sha256) "$REAL_CP" "$CASE_ROOT/checksum" "$DEST" ;;
  *) echo "Unexpected download URL" >&2; exit 98 ;;
esac
CURL
chmod 700 "$TEST_ROOT/providers/"*
for ACTION in install uninstall rollback; do
  cat >"$TEST_ROOT/source/RAZVILKA-fixture/scripts/$ACTION-entware.sh" <<'HELPER'
#!/bin/sh
# RAZVILKA_UNINSTALL_PRESERVES_DATA=1
printf '%s\n' "${0##*/}:$*" >"$CASE_ROOT/helper-called"
HELPER
done
cat >"$TEST_ROOT/essential/opkg" <<'OPKG'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$CASE_ROOT/opkg-called"
[ "$CASE_NAME" != opkg-failed ] || exit 41
case "$1" in
  update) exit 0 ;;
  install) shift ;;
  *) echo "Bootstrap attempted a global upgrade or unknown opkg operation" >&2; exit 99 ;;
esac
for PACKAGE in "$@"; do
  case "$PACKAGE" in
    curl|tar|gzip) TOOLS="$PACKAGE" ;;
    coreutils-sha256sum) TOOLS=sha256sum ;;
    coreutils-mktemp) TOOLS=mktemp ;;
    coreutils-readlink) TOOLS=readlink ;;
    busybox) TOOLS='awk od pidof grep'; "$REAL_CP" "$PROVIDERS/start-stop-daemon" "$RAZVILKA_BASE/sbin/start-stop-daemon" ;;
    ip-full) TOOLS=ip ;;
    ca-bundle) TOOLS=; "$REAL_MKDIR" -p "$RAZVILKA_BASE/etc/ssl/certs"; printf ca >"$RAZVILKA_BASE/etc/ssl/certs/ca-certificates.crt" ;;
    *) echo "Unexpected dependency: $PACKAGE" >&2; exit 98 ;;
  esac
  for TOOL in $TOOLS; do "$REAL_CP" "$PROVIDERS/$TOOL" "$RAZVILKA_BASE/bin/$TOOL"; done
done
OPKG
chmod 700 "$TEST_ROOT/essential/opkg"

for CASE_NAME in install-aarch64 install-mips install-mipsel symlink-base missing-dependencies uninstall rollback old-uninstall invalid-options bad-checksum extra-checksum traversal traversal-warning list-failed types-warning multiple-roots archive-link download-failed opkg-failed; do
  [ "$CASE_NAME" != symlink-base ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  CASE_ROOT="$TEST_ROOT/$CASE_NAME"
  BASE="$CASE_ROOT/base"
  mkdir -p "$BASE/bin" "$BASE/sbin" "$BASE/tmp" "$BASE/etc/ssl/certs"
  printf ca >"$BASE/etc/ssl/certs/ca-certificates.crt"
  cp "$TEST_ROOT/providers/"* "$BASE/bin/"
  cp "$TEST_ROOT/providers/start-stop-daemon" "$BASE/sbin/"
  set --
  case "$CASE_NAME" in
    install-aarch64) ARCH=aarch64 ;;
    install-mips) ARCH=mips ;;
    install-mipsel) ARCH=mipsel ;;
    *) ARCH=aarch64 ;;
  esac
  printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$ARCH" >"$BASE/bin/uname"
  chmod 700 "$BASE/bin/uname"
  case "$CASE_NAME" in
    uninstall|old-uninstall) set -- --uninstall ;;
    rollback) set -- --rollback ;;
    invalid-options) set -- --uninstall --rollback ;;
    missing-dependencies|opkg-failed)
      for TOOL in curl sha256sum tar gzip mktemp readlink awk od pidof grep ip; do rm "$BASE/bin/$TOOL"; done
      rm "$BASE/sbin/start-stop-daemon" "$BASE/etc/ssl/certs/ca-certificates.crt"
      ;;
  esac
  cp -R "$TEST_ROOT/source" "$CASE_ROOT/source"
  if [ "$CASE_NAME" = old-uninstall ]; then
    printf '#!/bin/sh\nprintf old-rollback >"$CASE_ROOT/helper-called"\n' >"$CASE_ROOT/source/RAZVILKA-fixture/scripts/uninstall-entware.sh"
  fi
  if [ "$CASE_NAME" = multiple-roots ]; then mkdir "$CASE_ROOT/source/RAZVILKA-extra"; fi
  if [ "$CASE_NAME" = traversal ] || [ "$CASE_NAME" = traversal-warning ]; then
    # A fixed gzip/tar fixture containing ../RAZVILKA-fixture/traversal.
    # BusyBox tar has no GNU --transform option; retain the same unsafe path.
    printf '%s' 'H4sIAAAAAAACCu3RuwrCUBCE4X0UXyDJ5kL6lKJVihR2W5ygICLnIj6+J4II1kEE/6+ZZZoptiyrcThM2/1uKObTPSbvqujt5nyws6xDs77rnpl9pmrTvu+lr1utVTYqX5BCNJ/n5T+lS7DZFVeLx9f/BQAAAAAAAAAAAAAAAADw+x7XcVzUACgAAA==' | base64 -d >"$CASE_ROOT/bundle.tar.gz"
  else
    (cd "$CASE_ROOT/source" && tar -czf "$CASE_ROOT/bundle.tar.gz" RAZVILKA-*)
  fi
  if [ "$CASE_NAME" = archive-link ]; then
    # A fixed gzip/tar fixture containing RAZVILKA-fixture/link -> /outside.
    # Windows Git Bash may copy ln -s targets instead of making a symlink.
    printf '%s' 'H4sIAAAAAAACCu3NMQrCQABE0T2KF5BoDPYpRSuLFHZCIiyKQrILHt/FUlstAu81f7o5tqdud9i3y0t8pjwO1S3er+G3VsW2ad4tPvu915u6ZFFXj5ym2A/hj/KUzmO5DwAAAAAAAAAAADAfL2uSs6gAKAAA' | base64 -d >"$CASE_ROOT/bundle.tar.gz"
  fi
  HASH="$(sha256sum "$CASE_ROOT/bundle.tar.gz" | awk '{print $1}')"
  [ "$CASE_NAME" != bad-checksum ] || HASH=0000000000000000000000000000000000000000000000000000000000000000
  printf '%s  RAZVILKA-entware.tar.gz\n' "$HASH" >"$CASE_ROOT/checksum"
  if [ "$CASE_NAME" = extra-checksum ]; then printf '%s  ../unrelated\n' "$HASH" >>"$CASE_ROOT/checksum"; fi
  PROVIDERS="$TEST_ROOT/providers"
  export CASE_NAME CASE_ROOT PROVIDERS
  RUN_BASE="$BASE"
  if [ "$CASE_NAME" = symlink-base ]; then
    RUN_BASE="$CASE_ROOT/base-link"
    ln -s "$BASE" "$RUN_BASE"
  fi
  CODE=0
  PATH="$TEST_ROOT/essential" RAZVILKA_BASE="$RUN_BASE" TMPDIR="$BASE/tmp" \
    "$HOST_SH" "$ROOT/scripts/bootstrap.sh" "$@" >"$CASE_ROOT/output" 2>&1 || CODE=$?
  case "$CASE_NAME" in
    install-*|symlink-base|missing-dependencies|uninstall|rollback)
      [ "$CODE" = 0 ] && [ -f "$CASE_ROOT/helper-called" ] || { cat "$CASE_ROOT/output" >&2; echo "Bootstrap failed: $CASE_NAME" >&2; exit 1; }
      EXPECTED=install
      case "$CASE_NAME" in uninstall|rollback) EXPECTED="$CASE_NAME" ;; esac
      [ "$(cat "$CASE_ROOT/helper-called")" = "$EXPECTED-entware.sh:" ] || { echo "Wrong helper/action: $CASE_NAME" >&2; exit 1; }
      if [ "$CASE_NAME" = missing-dependencies ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 2 ] || { echo "Dependencies were not installed in one bounded batch" >&2; exit 1; }
        for PACKAGE in curl coreutils-sha256sum tar gzip coreutils-mktemp coreutils-readlink busybox ip-full ca-bundle; do
          grep -q " $PACKAGE" "$CASE_ROOT/opkg-called" || { echo "Missing dependency: $PACKAGE" >&2; exit 1; }
        done
      else
        [ ! -e "$CASE_ROOT/opkg-called" ] || { echo "Complete Entware was modified unnecessarily" >&2; exit 1; }
      fi
      ;;
    *)
      [ "$CODE" != 0 ] && [ ! -e "$CASE_ROOT/helper-called" ] || { echo "Unsafe bootstrap accepted: $CASE_NAME" >&2; cat "$CASE_ROOT/output" >&2; exit 1; }
      case "$CASE_NAME" in
        traversal|traversal-warning|list-failed|types-warning)
          [ "$CODE" = 16 ] || { echo "Fixture did not reach the archive listing refusal: $CASE_NAME" >&2; cat "$CASE_ROOT/output" >&2; exit 1; }
          ;;
      esac
      ;;
  esac
  [ -z "$(find "$BASE/tmp" -mindepth 1 -print)" ] || { echo "Bootstrap leaked extracted release files: $CASE_NAME" >&2; exit 1; }
done
echo "Isolated Entware bootstrap tests: PASS"
