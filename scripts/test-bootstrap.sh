#!/bin/sh
# The real bootstrap runs against a temporary Entware tree. Every network/opkg
# command is a recording fixture; no host package or live installation is used.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
NATIVE_LINKS=1
case "$(uname -s)" in MINGW*|MSYS*) NATIVE_LINKS=0 ;; esac
export NATIVE_LINKS
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-bootstrap.XXXXXX")"
cleanup() { case "$TEST_ROOT" in "$TMP_BASE"/razvilka-bootstrap.*) rm -rf "$TEST_ROOT" ;; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
HOST_SH="$(command -v sh)"
BUSYBOX="$(command -v busybox || true)"
REAL_CP="$(command -v cp)"
REAL_MKDIR="$(command -v mkdir)"
REAL_RM="$(command -v rm)"
export REAL_CP REAL_MKDIR REAL_RM
# The bootstrap published with a tag must fetch exactly that release by default.
RELEASE_VERSION="$(tr -d '\r\n' <"$ROOT/VERSION")"
RELEASE_VERSION="${RELEASE_VERSION%-dev}"
RELEASE_TAG="v$RELEASE_VERSION"
RELEASE_DIR="RAZVILKA-$RELEASE_VERSION"
mkdir -p "$TEST_ROOT/essential" "$TEST_ROOT/providers" "$TEST_ROOT/source/$RELEASE_DIR/scripts"
for TOOL in cat chmod cp mkdir rm mv ln uname sh ls; do
  REAL_TOOL="$(command -v "$TOOL")"
  if [ -n "$BUSYBOX" ]; then
    printf '#!/bin/sh\nexec "%s" %s "$@"\n' "$BUSYBOX" "$TOOL" >"$TEST_ROOT/essential/$TOOL"
  else
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$REAL_TOOL" >"$TEST_ROOT/essential/$TOOL"
  fi
  chmod 700 "$TEST_ROOT/essential/$TOOL"
done
if [ -n "$BUSYBOX" ]; then
  cp "$TEST_ROOT/essential/mkdir" "$TEST_ROOT/host-mkdir"
  cp "$TEST_ROOT/essential/rm" "$TEST_ROOT/host-rm"
  REAL_MKDIR="$TEST_ROOT/host-mkdir"
  REAL_RM="$TEST_ROOT/host-rm"
  export REAL_MKDIR REAL_RM
  cat >"$TEST_ROOT/busybox-bootstrap" <<'BUSYBOX_SHELL'
#!/bin/sh
# Standalone ash resolves built-in applets before PATH. These two fixture
# providers must remain explicit: wget never touches the network, and timeout
# does not leave the standalone applet's orphan watchdog holding the test cwd.
# All other shell/app commands in these two cases use actual BusyBox behavior.
exec "$BOOTSTRAP_TEST_BUSYBOX" sh -c '
  wget() { "$RAZVILKA_BASE/bin/wget" "$@"; }
  timeout() { "$RAZVILKA_BASE/bin/timeout" "$@"; }
  fixture_script=$1
  shift
  . "$fixture_script"
' bootstrap-busybox-fixture "$@"
BUSYBOX_SHELL
  chmod 700 "$TEST_ROOT/busybox-bootstrap"
fi
printf '#!/bin/sh\nprintf "0\\n"\n' >"$TEST_ROOT/essential/id"
chmod 700 "$TEST_ROOT/essential/id"
cat >"$TEST_ROOT/essential/mkdir" <<'MKDIR'
#!/bin/sh
set -eu
case "${CASE_NAME:-}:$1" in
  opkg-collision:*/.razvilka-opkg.*)
    "$REAL_MKDIR" "$1"
    printf foreign >"$1/foreign"
    printf '%s\n' "$1" >"$CASE_ROOT/collision-path"
    ;;
esac
exec "$REAL_MKDIR" "$@"
MKDIR
chmod 700 "$TEST_ROOT/essential/mkdir"
cat >"$TEST_ROOT/essential/rm" <<'RM'
#!/bin/sh
case "${CASE_NAME:-}:$*" in opkg-cleanup-failed:*'/.razvilka-opkg.'*) exit 45 ;; esac
exec "$REAL_RM" "$@"
RM
chmod 700 "$TEST_ROOT/essential/rm"
for TOOL in sha256sum tar gzip mktemp readlink timeout awk dd od grep; do
  REAL_TOOL="$(command -v "$TOOL")"
  [ -n "$REAL_TOOL" ] || { echo "Bootstrap test needs host $TOOL" >&2; exit 1; }
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$REAL_TOOL" >"$TEST_ROOT/providers/$TOOL"
  chmod 700 "$TEST_ROOT/providers/$TOOL"
done
REAL_READLINK="$(command -v readlink)"
export REAL_READLINK
cat >"$TEST_ROOT/providers/readlink" <<'READLINK'
#!/bin/sh
# Git Bash does not provide real symlinks here. Only this Windows path is
# modeled; Linux and actual BusyBox ash must resolve the real fixture links.
if [ "$NATIVE_LINKS" = 0 ] && [ "$#" = 2 ] && [ "$1" = -f ] && [ "$2" = "$RAZVILKA_BASE/sbin/ip" ]; then
  if [ -f "$CASE_ROOT/ip-alias-ready" ]; then
    exec "$REAL_READLINK" -f "$RAZVILKA_BASE/libexec/ip-full"
  fi
  exec "$REAL_READLINK" -f "$RAZVILKA_BASE/bin/ip"
fi
exec "$REAL_READLINK" "$@"
READLINK
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
printf '#!/bin/sh\nif [ "$1" = -Version ]; then printf "ip utility, iproute2-ss4.4.0-11-entware\\n"; fi\nexit 0\n' >"$TEST_ROOT/providers/ip-full"
printf '#!/bin/sh\nexit 99\n' >"$TEST_ROOT/providers/start-stop-daemon"
printf '#!/bin/sh\nprintf "GNU Wget +https\\n"\n' >"$TEST_ROOT/providers/wget"
cat >"$TEST_ROOT/providers/curl" <<'CURL'
#!/bin/sh
set -eu
[ "${TMPDIR:-}" = "$EXPECTED_DOWNLOAD_TMP" ] || { echo "Dependency TMPDIR leaked to download" >&2; exit 97; }
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
  cat >"$TEST_ROOT/source/$RELEASE_DIR/scripts/$ACTION-entware.sh" <<'HELPER'
#!/bin/sh
# RAZVILKA_UNINSTALL_PRESERVES_DATA=1
# RAZVILKA_UNINSTALL_PURGE_MOVES_DATA=1
printf '%s\n' "${0##*/}:$*" >"$CASE_ROOT/helper-called"
printf '%s\n' "${RAZVILKA_ARCH:-}" >"$CASE_ROOT/helper-architecture"
printf '%s\n' "$0" >"$CASE_ROOT/helper-path"
HELPER
done
cat >"$TEST_ROOT/essential/opkg" <<'OPKG'
#!/bin/sh
set -eu
case "${TMPDIR:-}" in "$RAZVILKA_BASE"/.razvilka-opkg.*) ;; *) echo "opkg has no private TMPDIR" >&2; exit 97 ;; esac
[ -d "$TMPDIR" ] && [ ! -L "$TMPDIR" ] && [ "$PWD" = "$TMPDIR" ] || exit 96
# Both package extraction and getcwd fallback must be writable. These files
# also prove that recursive cleanup handles a failed package operation.
printf scratch >"$TMPDIR/package.tmp"
printf cwd >package-cwd.tmp
printf '%s\n' "$TMPDIR" >>"$CASE_ROOT/opkg-workspaces"
printf '%s\n' "$*" >>"$CASE_ROOT/opkg-called"
[ "$CASE_NAME" != opkg-failed ] || exit 41
[ "$CASE_NAME" != opkg-install-failed ] || [ "$1" != install ] || exit 42
[ "$CASE_NAME" != opkg-wget-failed ] || [ "$*" != 'install wget-ssl' ] || exit 43
if [ "$CASE_NAME" = opkg-signal ]; then kill -TERM "$PPID"; exit 44; fi
case "$1" in
  update)
    case "$CASE_NAME" in https-bootstrap|opkg-wget-failed) [ -f "$CASE_ROOT/tls-installed" ] || exit 2 ;; esac
    exit 0 ;;
  install) shift ;;
  *) echo "Bootstrap attempted a global upgrade or unknown opkg operation" >&2; exit 99 ;;
esac
for PACKAGE in "$@"; do
  case "$PACKAGE" in
    curl|tar|gzip) TOOLS="$PACKAGE" ;;
    wget-ssl) TOOLS=wget; : >"$CASE_ROOT/tls-installed" ;;
    coreutils-sha256sum) TOOLS=sha256sum ;;
    coreutils-mktemp) TOOLS=mktemp ;;
    coreutils-readlink) TOOLS=readlink ;;
    coreutils-timeout)
      TOOLS=timeout
      [ "$CASE_NAME" != timeout-still-incompatible ] || TOOLS=
      ;;
    busybox) TOOLS='awk dd od pidof grep'; "$REAL_CP" "$PROVIDERS/start-stop-daemon" "$RAZVILKA_BASE/sbin/start-stop-daemon" ;;
    ip-full)
      TOOLS=
      "$REAL_MKDIR" -p "$RAZVILKA_BASE/libexec"
      [ "$CASE_NAME" = ip-version-unrepaired ] || "$REAL_CP" "$PROVIDERS/ip-full" "$RAZVILKA_BASE/libexec/ip-full"
      if [ "$CASE_NAME" != ip-alias-unrepaired ]; then
        if [ "$NATIVE_LINKS" = 1 ]; then
          ln -sf ../libexec/ip-full "$RAZVILKA_BASE/sbin/ip"
        else
          "$REAL_CP" "$PROVIDERS/ip-full" "$RAZVILKA_BASE/sbin/ip"
        fi
        : >"$CASE_ROOT/ip-alias-ready"
      fi
      ;;
    ca-bundle) TOOLS=; "$REAL_MKDIR" -p "$RAZVILKA_BASE/etc/ssl/certs"; printf ca >"$RAZVILKA_BASE/etc/ssl/certs/ca-certificates.crt" ;;
    *) echo "Unexpected dependency: $PACKAGE" >&2; exit 98 ;;
  esac
  for TOOL in $TOOLS; do "$REAL_CP" "$PROVIDERS/$TOOL" "$RAZVILKA_BASE/bin/$TOOL"; done
done
OPKG
chmod 700 "$TEST_ROOT/essential/opkg"

BUSYBOX_CASES=0
for CASE_NAME in install-aarch64 install-mips install-mipsel install-explicit-mipsel install-default-cache install-latest install-pinned private-owner private-writable private-type symlink-base missing-dependencies missing-dependencies-unset busybox-shell busybox-shell-unset ip-full-missing ip-alias-wrong ip-version-wrong ip-version-failed ip-alias-unrepaired ip-version-unrepaired incompatible-timeout timeout-still-incompatible https-bootstrap uninstall rollback old-uninstall invalid-options latest-uninstall latest-rollback invalid-version wrong-root uninstall-purge purge-default-tmp purge-old-release purge-without-uninstall purge-rollback bad-checksum extra-checksum traversal traversal-warning list-failed types-warning multiple-roots archive-link download-failed opkg-failed opkg-install-failed opkg-wget-failed opkg-collision opkg-signal opkg-cleanup-failed; do
  [ "$CASE_NAME" != symlink-base ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  [ "$CASE_NAME" != opkg-signal ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
  case "$CASE_NAME" in busybox-shell*) [ -n "$BUSYBOX" ] || continue ;; esac
  case "$CASE_NAME" in install-default-cache|private-owner|private-writable)
    [ "$NATIVE_LINKS" -eq 1 ] && [ "$(id -u)" = 0 ] || continue ;;
  esac
  CASE_ROOT="$TEST_ROOT/$CASE_NAME"
  BASE="$CASE_ROOT/base"
  mkdir -p "$BASE/bin" "$BASE/sbin" "$BASE/libexec" "$BASE/tmp" "$BASE/etc/ssl/certs"
  RUN_TMP="$BASE/tmp"
  case "$CASE_NAME" in
    install-default-cache|missing-dependencies-unset|busybox-shell-unset) RUN_TMP='' ;;
    private-owner) mkdir "$BASE/razvilka"; chown 1001 "$BASE/razvilka" ;;
    private-writable) mkdir "$BASE/razvilka"; chmod 777 "$BASE/razvilka" ;;
    private-type) printf foreign >"$BASE/razvilka" ;;
  esac
  printf ca >"$BASE/etc/ssl/certs/ca-certificates.crt"
  cp "$TEST_ROOT/providers/"* "$BASE/bin/"
  cp "$TEST_ROOT/providers/start-stop-daemon" "$BASE/sbin/"
  cp "$TEST_ROOT/providers/ip-full" "$BASE/libexec/ip-full"
  if [ "$NATIVE_LINKS" = 1 ]; then ln -s ../libexec/ip-full "$BASE/sbin/ip"; else cp "$TEST_ROOT/providers/ip-full" "$BASE/sbin/ip"; fi
  : >"$CASE_ROOT/ip-alias-ready"
  set --
  case "$CASE_NAME" in
    install-aarch64) ARCH=aarch64 ;;
    install-mips|install-explicit-mipsel) ARCH=mips ;;
    install-mipsel) ARCH=mipsel ;;
    *) ARCH=aarch64 ;;
  esac
  printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$ARCH" >"$BASE/bin/uname"
  chmod 700 "$BASE/bin/uname"
  case "$CASE_NAME" in
    uninstall|old-uninstall) set -- --uninstall ;;
    rollback) set -- --rollback ;;
    invalid-options) set -- --uninstall --rollback ;;
    missing-dependencies|missing-dependencies-unset|opkg-failed|opkg-install-failed|opkg-collision|opkg-signal|opkg-cleanup-failed)
      [ "$CASE_NAME" != missing-dependencies-unset ] || set -- --uninstall --purge
      for TOOL in curl wget sha256sum tar gzip mktemp readlink timeout awk dd od pidof grep ip; do rm "$BASE/bin/$TOOL"; done
      rm "$BASE/sbin/start-stop-daemon" "$BASE/sbin/ip" "$BASE/libexec/ip-full" "$CASE_ROOT/ip-alias-ready" "$BASE/etc/ssl/certs/ca-certificates.crt"
      ;;
    ip-full-missing|ip-alias-wrong|ip-alias-unrepaired)
      # Exact observed router defect: BusyBox-shaped ip passes addr but not
      # -Version. Full may already exist while its alternative remains wrong.
      printf '#!/bin/sh\n[ "$1" != -Version ] || exit 1\nexit 0\n' >"$BASE/bin/ip"
      rm "$BASE/sbin/ip" "$CASE_ROOT/ip-alias-ready"
      if [ "$NATIVE_LINKS" = 1 ]; then ln -s ../bin/ip "$BASE/sbin/ip"; else cp "$BASE/bin/ip" "$BASE/sbin/ip"; fi
      [ "$CASE_NAME" != ip-full-missing ] || rm "$BASE/libexec/ip-full"
      ;;
    ip-version-wrong|ip-version-unrepaired)
      printf '#!/bin/sh\nprintf "ip utility, foreign-version\\n"\nexit 0\n' >"$BASE/libexec/ip-full"
      ;;
    ip-version-failed)
      printf '#!/bin/sh\nprintf "ip utility, iproute2-ss4.4.0-11-entware\\n"\nexit 1\n' >"$BASE/libexec/ip-full"
      ;;
    https-bootstrap|opkg-wget-failed)
      printf '#!/bin/sh\nprintf "BusyBox wget HTTP only\\n"\n' >"$BASE/bin/wget"
      ;;
    busybox-shell|busybox-shell-unset)
      rm "$BASE/bin/curl"
      [ "$CASE_NAME" != busybox-shell-unset ] || set -- --uninstall --purge
      ;;
    incompatible-timeout|timeout-still-incompatible)
      printf '#!/bin/sh\n[ "$1" != -k ] || exit 2\nexit 0\n' >"$BASE/bin/timeout"
      ;;
  esac
  cp -R "$TEST_ROOT/source" "$CASE_ROOT/source"
  if [ "$CASE_NAME" = old-uninstall ]; then
    printf '#!/bin/sh\nprintf old-rollback >"$CASE_ROOT/helper-called"\n' >"$CASE_ROOT/source/$RELEASE_DIR/scripts/uninstall-entware.sh"
  fi
  if [ "$CASE_NAME" = purge-old-release ]; then
    # Safe removal exists, but this release cannot move data aside.
    printf '#!/bin/sh\n# RAZVILKA_UNINSTALL_PRESERVES_DATA=1\nprintf old-purge >"$CASE_ROOT/helper-called"\n' >"$CASE_ROOT/source/$RELEASE_DIR/scripts/uninstall-entware.sh"
  fi
  if [ "$CASE_NAME" = multiple-roots ]; then mkdir "$CASE_ROOT/source/RAZVILKA-extra"; fi
  # A pinned release must contain exactly its own top directory. Only an
  # explicit installation from "latest" has no version to compare.
  VERSION_OVERRIDE=""
  EXPECTED_DOWNLOAD="https://github.com/ArtixSx/RAZVILKA/releases/download/$RELEASE_TAG/"
  case "$CASE_NAME" in
    install-latest|wrong-root) mv "$CASE_ROOT/source/$RELEASE_DIR" "$CASE_ROOT/source/RAZVILKA-9.9.9" ;;
    install-pinned) mv "$CASE_ROOT/source/$RELEASE_DIR" "$CASE_ROOT/source/RAZVILKA-0.20.0-rc.7" ;;
  esac
  case "$CASE_NAME" in
    install-latest|latest-uninstall|latest-rollback)
      VERSION_OVERRIDE=latest
      EXPECTED_DOWNLOAD=https://github.com/ArtixSx/RAZVILKA/releases/latest/download/ ;;
    install-pinned)
      VERSION_OVERRIDE=0.20.0-rc.7
      EXPECTED_DOWNLOAD=https://github.com/ArtixSx/RAZVILKA/releases/download/v0.20.0-rc.7/ ;;
    invalid-version) VERSION_OVERRIDE='v1.0/../../x' ;;
  esac
  case "$CASE_NAME" in
    latest-uninstall) set -- --uninstall ;;
    latest-rollback) set -- --rollback ;;
    uninstall-purge|purge-old-release) set -- --uninstall --purge ;;
    purge-default-tmp) set -- --purge --uninstall; RUN_TMP='' ;;
    purge-without-uninstall) set -- --purge ;;
    purge-rollback) set -- --rollback --purge ;;
  esac
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
  ARCH_OVERRIDE=""
  [ "$CASE_NAME" != install-explicit-mipsel ] || ARCH_OVERRIDE=mipsle
  EXPECTED_DOWNLOAD_TMP="$RUN_TMP"
  export EXPECTED_DOWNLOAD_TMP
  mkdir "$CASE_ROOT/read only cwd"
  chmod 500 "$CASE_ROOT/read only cwd"
  # Optional CI harness supplies an actually read-only bind mount in its own
  # mount namespace. chmod alone does not constrain root or Windows hosts.
  CALLER_CWD="${RAZVILKA_BOOTSTRAP_TEST_CWD:-$CASE_ROOT/read only cwd}"
  CASE_SH="$HOST_SH"
  case "$CASE_NAME" in
    busybox-shell*) CASE_SH="$TEST_ROOT/busybox-bootstrap"; BUSYBOX_CASES=$((BUSYBOX_CASES + 1)) ;;
  esac
  (
    cd "$CALLER_CWD"
    if [ -n "$RUN_TMP" ]; then TMPDIR="$RUN_TMP"; export TMPDIR; else unset TMPDIR; fi
    PATH="$TEST_ROOT/essential" RAZVILKA_BASE="$RUN_BASE" RAZVILKA_ARCH="$ARCH_OVERRIDE" \
      BOOTSTRAP_TEST_BUSYBOX="$BUSYBOX" RAZVILKA_VERSION="$VERSION_OVERRIDE" "$CASE_SH" "$ROOT/scripts/bootstrap.sh" "$@"
  ) >"$CASE_ROOT/output" 2>&1 || CODE=$?
  chmod 700 "$CASE_ROOT/read only cwd"
  [ -z "$(find "$CASE_ROOT/read only cwd" -mindepth 1 -print)" ] || { echo "Bootstrap wrote into caller cwd" >&2; exit 1; }
  for OPKG_DIR in "$BASE"/.razvilka-opkg.*; do
    [ -e "$OPKG_DIR" ] || continue
    case "$CASE_NAME" in
      opkg-collision) [ "$(cat "$OPKG_DIR/foreign")" = foreign ] || exit 1 ;;
      opkg-cleanup-failed) [ -f "$OPKG_DIR/package.tmp" ] && grep -F "Cannot clean private Entware package workspace: $OPKG_DIR" "$CASE_ROOT/output" >/dev/null || exit 1 ;;
      *) echo "Package workspace leaked: $CASE_NAME" >&2; exit 1 ;;
    esac
  done
  if [ "$CASE_NAME" = opkg-collision ]; then
    [ -f "$CASE_ROOT/collision-path" ] && [ -f "$(cat "$CASE_ROOT/collision-path")/foreign" ] && [ ! -e "$CASE_ROOT/opkg-called" ] || { echo "Colliding package workspace was adopted" >&2; exit 1; }
  fi
  case "$CASE_NAME" in
    install-*|symlink-base|missing-dependencies|missing-dependencies-unset|busybox-shell*|ip-full-missing|ip-alias-wrong|ip-version-wrong|ip-version-failed|incompatible-timeout|https-bootstrap|uninstall|rollback|uninstall-purge|purge-default-tmp)
      [ "$CODE" = 0 ] && [ -f "$CASE_ROOT/helper-called" ] || { cat "$CASE_ROOT/output" >&2; echo "Bootstrap failed: $CASE_NAME" >&2; exit 1; }
      EXPECTED=install
      EXPECTED_ARGS=""
      case "$CASE_NAME" in
        uninstall|rollback) EXPECTED="$CASE_NAME" ;;
        uninstall-purge|purge-default-tmp|missing-dependencies-unset|busybox-shell-unset) EXPECTED=uninstall; EXPECTED_ARGS=--purge ;;
      esac
      [ "$(cat "$CASE_ROOT/helper-called")" = "$EXPECTED-entware.sh:$EXPECTED_ARGS" ] || { echo "Wrong helper/action: $CASE_NAME" >&2; exit 1; }
      if [ "$CASE_NAME" = purge-default-tmp ]; then
        # Purge moves /opt/razvilka aside; its release must run from outside.
        case "$(cat "$CASE_ROOT/helper-path")" in
          "$BASE/tmp/razvilka-install."*) ;;
          *) echo "Purge release was not extracted into Entware tmp" >&2; cat "$CASE_ROOT/helper-path" >&2; exit 1 ;;
        esac
        [ ! -e "$BASE/razvilka" ] || { echo "Purge bootstrap created the private tree it moves" >&2; exit 1; }
      fi
      [ "$(cat "$CASE_ROOT/helper-architecture")" = "$ARCH_OVERRIDE" ] || { echo "Architecture override was lost before the release helper" >&2; exit 1; }
      awk -v base="$EXPECTED_DOWNLOAD" 'index($NF, base) != 1 {bad=1} END {exit bad || NR != 2}' "$CASE_ROOT/downloads" || {
        echo "Bootstrap fetched another release than requested: $CASE_NAME" >&2; cat "$CASE_ROOT/downloads" >&2; exit 1;
      }
      if [ "$CASE_NAME" = install-default-cache ]; then
        [ -d "$BASE/razvilka/cache" ] && [ -z "$(find "$BASE/razvilka/cache" -mindepth 1 -print)" ] &&
          [ "$(ls -nd "$BASE/razvilka" | awk '{print $1,$3}')" = 'drwx------ 0' ] || { echo "Bootstrap default cache is not private/root-owned/clean" >&2; exit 1; }
      fi
      if [ "$ARCH" = mips ]; then
        grep -q 'платформа ядра: mips' "$CASE_ROOT/output" || { echo "Kernel identity is mislabeled as selected architecture" >&2; exit 1; }
      fi
      if [ "$CASE_NAME" = missing-dependencies ] || [ "$CASE_NAME" = missing-dependencies-unset ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 2 ] || { echo "Dependencies were not installed in one bounded batch" >&2; exit 1; }
        for PACKAGE in curl wget-ssl coreutils-sha256sum tar gzip coreutils-mktemp coreutils-readlink coreutils-timeout busybox ip-full ca-bundle; do
          grep -q " $PACKAGE" "$CASE_ROOT/opkg-called" || { echo "Missing dependency: $PACKAGE" >&2; exit 1; }
        done
      elif [ "$CASE_NAME" = ip-full-missing ] || [ "$CASE_NAME" = ip-alias-wrong ] || [ "$CASE_NAME" = ip-version-wrong ] || [ "$CASE_NAME" = ip-version-failed ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 2 ] &&
          grep -q '^install ip-full$' "$CASE_ROOT/opkg-called" || { echo "Missing/incompatible full IP was not repaired in one package operation" >&2; exit 1; }
      elif [ "$CASE_NAME" = incompatible-timeout ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 2 ] &&
          grep -q '^install coreutils-timeout$' "$CASE_ROOT/opkg-called" || { echo "Incompatible timeout was not replaced before release download" >&2; exit 1; }
      elif [ "$CASE_NAME" = https-bootstrap ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 4 ] || { echo "HTTPS bootstrap was not bounded" >&2; exit 1; }
        [ -f "$CASE_ROOT/tls-installed" ] || { echo "HTTPS downloader was not installed" >&2; exit 1; }
      elif [ "$CASE_NAME" = busybox-shell ] || [ "$CASE_NAME" = busybox-shell-unset ]; then
        [ "$(wc -l <"$CASE_ROOT/opkg-called" | tr -d ' ')" = 2 ] &&
          grep -q '^install curl$' "$CASE_ROOT/opkg-called" || { echo "BusyBox shell did not exercise exact missing-curl package scope" >&2; exit 1; }
      else
        [ ! -e "$CASE_ROOT/opkg-called" ] || { echo "Complete Entware was modified unnecessarily" >&2; exit 1; }
      fi
      ;;
    *)
      [ "$CODE" != 0 ] && [ ! -e "$CASE_ROOT/helper-called" ] || { echo "Unsafe bootstrap accepted: $CASE_NAME" >&2; cat "$CASE_ROOT/output" >&2; exit 1; }
      case "$CASE_NAME" in
        opkg-failed|opkg-install-failed|opkg-wget-failed|opkg-signal|opkg-collision|opkg-cleanup-failed)
          [ ! -e "$CASE_ROOT/downloads" ] || { echo "Failed package preparation reached download" >&2; exit 1; }
          case "$CASE_NAME:$CODE" in
            opkg-failed:41|opkg-install-failed:42|opkg-wget-failed:43|opkg-signal:143|opkg-collision:12|opkg-cleanup-failed:12) ;;
            *) echo "Package failure status changed: $CASE_NAME/$CODE" >&2; cat "$CASE_ROOT/output" >&2; exit 1 ;;
          esac
          ;;
        private-owner|private-writable|private-type)
          [ "$CODE" = 12 ] && [ ! -e "$CASE_ROOT/downloads" ] || { echo "Foreign private tree reached a download/helper" >&2; exit 1; }
          ;;
        ip-alias-unrepaired|ip-version-unrepaired)
          [ "$CODE" = 12 ] && [ ! -e "$CASE_ROOT/downloads" ] &&
            grep -q '^install ip-full$' "$CASE_ROOT/opkg-called" || { echo "Unrepaired full IP reached release download/helper" >&2; exit 1; }
          ;;
        timeout-still-incompatible)
          [ "$CODE" = 12 ] && [ ! -e "$CASE_ROOT/downloads" ] || { echo "Unusable timeout reached release download/helper" >&2; exit 1; }
          ;;
        traversal|traversal-warning|list-failed|types-warning)
          [ "$CODE" = 16 ] || { echo "Fixture did not reach the archive listing refusal: $CASE_NAME" >&2; cat "$CASE_ROOT/output" >&2; exit 1; }
          ;;
        wrong-root)
          [ "$CODE" = 16 ] && grep -q '^Release archive version does not match the requested release' "$CASE_ROOT/output" || {
            echo "Archive of another release was accepted or refused elsewhere" >&2; cat "$CASE_ROOT/output" >&2; exit 1;
          }
          ;;
        purge-old-release)
          [ "$CODE" = 15 ] && grep -q '^This release has no purge option' "$CASE_ROOT/output" || {
            echo "Release without purge support was started" >&2; cat "$CASE_ROOT/output" >&2; exit 1;
          }
          ;;
        latest-uninstall|latest-rollback|invalid-version|purge-without-uninstall|purge-rollback)
          [ "$CODE" = 2 ] && [ ! -e "$CASE_ROOT/downloads" ] && [ ! -e "$CASE_ROOT/opkg-called" ] || {
            echo "Unpinned or invalid release reached Entware or a download: $CASE_NAME" >&2; cat "$CASE_ROOT/output" >&2; exit 1;
          }
          ;;
      esac
      ;;
  esac
  [ -z "$(find "$BASE/tmp" -mindepth 1 -print)" ] || { echo "Bootstrap leaked extracted release files: $CASE_NAME" >&2; exit 1; }
done
[ -z "$BUSYBOX" ] || [ "$BUSYBOX_CASES" -eq 2 ] || exit 1
echo "Isolated Entware bootstrap tests: PASS (BusyBox early tools: ${BUSYBOX:-unavailable}; actual ash package-temp cases: $BUSYBOX_CASES; wget/timeout controlled; real IP alias links: $NATIVE_LINKS)"
