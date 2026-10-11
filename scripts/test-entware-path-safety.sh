#!/bin/sh
# Actual script entrypoints, physical fixture paths and retained foreign bytes.
# No daemon, binary, network or host installation is executed or modified.
set -eu
umask 077
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
NATIVE_LINKS=1
case "$(uname -s)" in MINGW*|MSYS*) NATIVE_LINKS=0 ;; esac
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-path-safety.XXXXXX")"
cleanup() { case "$TEST_ROOT" in "$TMP_BASE"/razvilka-path-safety.*) rm -rf "$TEST_ROOT" ;; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for SCRIPT in upgrade-entware.sh rollback-entware.sh uninstall-entware.sh; do
  DIRECTORIES='bin etc etc/init.d etc/razvilka razvilka razvilka/run razvilka/state'
  if [ "$SCRIPT" = upgrade-entware.sh ]; then
    DIRECTORIES="$DIRECTORIES razvilka/cache razvilka/log"
  fi
  for RELATIVE in $DIRECTORIES; do
    for KIND in file link broken-link; do
      [ "$KIND" = file ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
      CASE_ROOT="$TEST_ROOT/$SCRIPT-$KIND-$(printf '%s' "$RELATIVE" | tr '/' '_')"
      BASE="$CASE_ROOT/opt"
      FOREIGN="$CASE_ROOT/unrelated-entware"
      mkdir -p "$BASE" "$(dirname "$BASE/$RELATIVE")" "$FOREIGN"
      printf '%s\n' keep-other-app >"$FOREIGN/other-app.conf"
      cp "$FOREIGN/other-app.conf" "$CASE_ROOT/before"
      case "$KIND" in
        file) printf '%s\n' foreign-file >"$BASE/$RELATIVE" ;;
        link) ln -s "$FOREIGN" "$BASE/$RELATIVE" ;;
        broken-link) ln -s "$CASE_ROOT/missing" "$BASE/$RELATIVE" ;;
      esac
      CODE=0
      RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/$SCRIPT" >"$CASE_ROOT/output" 2>&1 || CODE=$?
      [ "$CODE" != 0 ] && grep -q '^Unsafe installation directory:' "$CASE_ROOT/output" || {
        echo "Unsafe ancestor did not refuse before producer/snapshot: $SCRIPT $RELATIVE $KIND" >&2
        cat "$CASE_ROOT/output" >&2
        exit 1
      }
      cmp -s "$CASE_ROOT/before" "$FOREIGN/other-app.conf" &&
        [ "$(find "$FOREIGN" -mindepth 1 -print | wc -l | tr -d ' ')" = 1 ] || {
        echo "Refusal changed unrelated Entware files" >&2; exit 1;
      }
      [ ! -e "$BASE/bin/razvilka" ] && [ ! -e "$BASE/etc/init.d/S99razvilka" ] || {
        echo "Refusal created panel files" >&2; exit 1;
      }
    done
  done
done

# Real Unix metadata only: Windows ACL emulation cannot prove UID or chmod.
if [ "$NATIVE_LINKS" -eq 1 ]; then
  for SCRIPT in upgrade-entware.sh rollback-entware.sh uninstall-entware.sh S99razvilka; do
    for RELATIVE in razvilka razvilka/run razvilka/state; do
      for KIND in writable foreign-owner; do
        [ "$KIND" != foreign-owner ] || [ "$(id -u)" = 0 ] || continue
        CASE_ROOT="$TEST_ROOT/owner-$SCRIPT-$KIND-$(printf '%s' "$RELATIVE" | tr '/' '_')"
        BASE="$CASE_ROOT/opt"
        mkdir -p "$BASE/$RELATIVE"
        printf retained >"$BASE/$RELATIVE/other-app.conf"
        if [ "$KIND" = foreign-owner ]; then chown 1001 "$BASE/$RELATIVE"; else chmod 777 "$BASE/$RELATIVE"; fi
        BEFORE="$(ls -nd "$BASE/$RELATIVE")"
        CODE=0
        set --
        [ "$SCRIPT" != S99razvilka ] || set -- status
        RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/$SCRIPT" "$@" >"$CASE_ROOT/output" 2>&1 || CODE=$?
        [ "$CODE" != 0 ] && grep -q '^Unsafe private installation owner or permissions:' "$CASE_ROOT/output" || {
          echo "Private foreign/writable tree reached a producer: $SCRIPT $RELATIVE $KIND" >&2; exit 1;
        }
        [ "$(cat "$BASE/$RELATIVE/other-app.conf")" = retained ] && [ "$(ls -nd "$BASE/$RELATIVE")" = "$BEFORE" ] || {
          echo "Private owner refusal changed foreign bytes or permissions" >&2; exit 1;
        }
      done
    done
  done
fi

# These paths are read/written by install and rollback, and are preserved by
# uninstall. Refuse a linked backup root/pointer before selecting a snapshot.
for SCRIPT in upgrade-entware.sh rollback-entware.sh; do
  for RELATIVE in razvilka/state/update-backups razvilka/state/current-backup; do
    for KIND in wrong-type link broken-link; do
      [ "$KIND" = wrong-type ] || [ "$NATIVE_LINKS" -eq 1 ] || continue
      CASE_ROOT="$TEST_ROOT/$SCRIPT-$KIND-$(printf '%s' "$RELATIVE" | tr '/' '_')"
      BASE="$CASE_ROOT/opt"
      mkdir -p "$BASE/razvilka/state" "$CASE_ROOT/foreign"
      printf retained >"$CASE_ROOT/foreign/pointer"
      case "$KIND" in
        wrong-type)
          if [ "$RELATIVE" = razvilka/state/update-backups ]; then
            printf foreign >"$BASE/$RELATIVE"
          else
            mkdir "$BASE/$RELATIVE"
          fi ;;
        link)
          TARGET="$CASE_ROOT/foreign"
          [ "$RELATIVE" = razvilka/state/update-backups ] || TARGET="$TARGET/pointer"
          ln -s "$TARGET" "$BASE/$RELATIVE" ;;
        broken-link) ln -s "$CASE_ROOT/missing" "$BASE/$RELATIVE" ;;
      esac
      CODE=0
      RAZVILKA_BASE="$BASE" sh "$ROOT/scripts/$SCRIPT" >"$BASE/output" 2>&1 || CODE=$?
      [ "$CODE" != 0 ] && grep -q '^Unsafe ' "$BASE/output" || { echo "Unsafe backup path was adopted" >&2; exit 1; }
      [ "$(cat "$CASE_ROOT/foreign/pointer")" = retained ] || { echo "Foreign backup bytes changed" >&2; exit 1; }
    done
  done
done
echo "Isolated Entware ancestor path refusal: PASS"
