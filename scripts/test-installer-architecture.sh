#!/bin/sh
# Runs the real installer preflight with recording binaries, a mocked uname
# and ELF-header reader. No live installation, process or network is touched.
set -eu
umask 077

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
TEST_ROOT="$(mktemp -d "$TMP_BASE/razvilka-architecture.XXXXXX")"
cleanup() {
  case "$TEST_ROOT" in
    "$TMP_BASE"/razvilka-architecture.*) rm -rf "$TEST_ROOT" ;;
    *) echo "Refusing unsafe architecture-test cleanup" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

BUNDLE="$TEST_ROOT/bundle"
BASE="$TEST_ROOT/base"
mkdir -p "$BUNDLE/scripts" "$BUNDLE/dist" "$BUNDLE/configs" "$BASE/sbin" "$TEST_ROOT/mocks"
cp "$ROOT/scripts/upgrade-entware.sh" "$BUNDLE/scripts/upgrade-entware.sh"
for NAME in S99razvilka rollback-entware.sh; do
  printf '#!/bin/sh\nexit 97\n' >"$BUNDLE/scripts/$NAME"
done
printf '#!/bin/sh\nexit 98\n' >"$BASE/sbin/start-stop-daemon"
chmod 700 "$BASE/sbin/start-stop-daemon"
for NAME in service-catalog community-catalog sources config.example; do
  printf '{}\n' >"$BUNDLE/configs/$NAME.json"
done
cat >"$TEST_ROOT/mocks/uname" <<'EOF'
#!/bin/sh
[ "$1" = -m ] || exit 99
printf '%s\n' "$TEST_UNAME"
EOF
cat >"$TEST_ROOT/mocks/od" <<'EOF'
#!/bin/sh
[ "$1 $2 $3 $4 $5" = '-An -t u1 -N 6' ] || exit 99
printf 'read\n' >>"$TEST_OD_CAPTURE"
[ "${TEST_OD_FAIL:-0}" = 0 ] || exit 1
printf '%s\n' "$TEST_ELF_HEADER"
EOF
chmod 700 "$TEST_ROOT/mocks/uname" "$TEST_ROOT/mocks/od"
for ARCH in amd64 arm64 mips mipsle; do
  cat >"$BUNDLE/dist/razvilka-linux-$ARCH" <<'EOF'
#!/bin/sh
printf '%s\n' "${0##*/}" >>"$TEST_BINARY_CAPTURE"
case "$1" in
  -version) printf '0.18.1-rc.2\n' ;;
  -check) printf '{"ok": true}\n' ;;
  *) exit 99 ;;
esac
EOF
  chmod 700 "$BUNDLE/dist/razvilka-linux-$ARCH"
done
(cd "$BUNDLE" && sha256sum dist/razvilka-linux-* >dist/SHA256SUMS)
PATH="$TEST_ROOT/mocks:$PATH"
TEST_BINARY_CAPTURE="$TEST_ROOT/executed"
TEST_OD_CAPTURE="$TEST_ROOT/elf-read"
export PATH TEST_BINARY_CAPTURE TEST_OD_CAPTURE

run_case() {
  TEST_UNAME="$1"
  TEST_ELF_HEADER="$2"
  RAZVILKA_ARCH="$3"
  EXPECTED="$4"
  TEST_OD_FAIL="${5:-0}"
  export TEST_UNAME TEST_ELF_HEADER RAZVILKA_ARCH TEST_OD_FAIL
  rm -f "$TEST_BINARY_CAPTURE" "$TEST_OD_CAPTURE"
  if RAZVILKA_BASE="$BASE" sh "$BUNDLE/scripts/upgrade-entware.sh" --dry-run >"$TEST_ROOT/output" 2>&1; then
    [ "$EXPECTED" != refuse ] || { echo "Unknown architecture/header was accepted" >&2; exit 1; }
    [ "$(sort -u "$TEST_BINARY_CAPTURE")" = "razvilka-linux-$EXPECTED" ] || { echo "Installer selected the wrong binary for $TEST_UNAME" >&2; exit 1; }
    [ "$(wc -l <"$TEST_BINARY_CAPTURE" | tr -d ' ')" = 2 ] || { echo "Expected only candidate version and preflight checks" >&2; exit 1; }
  else
    [ "$EXPECTED" = refuse ] || { cat "$TEST_ROOT/output" >&2; echo "Expected architecture $EXPECTED to pass preflight" >&2; exit 1; }
    [ ! -e "$TEST_BINARY_CAPTURE" ] || { echo "Invalid architecture executed a candidate binary" >&2; exit 1; }
  fi
  [ ! -e "$BASE/bin" ] && [ ! -e "$BASE/etc" ] || { echo "Architecture preflight changed installation" >&2; exit 1; }
  if [ "$TEST_UNAME" != mips ] || [ -n "$RAZVILKA_ARCH" ]; then
    [ ! -e "$TEST_OD_CAPTURE" ] || { echo "Unambiguous/explicit architecture was overwritten by ELF detection" >&2; exit 1; }
  else
    [ -e "$TEST_OD_CAPTURE" ] || { echo "Ambiguous MIPS architecture did not inspect ELF identity" >&2; exit 1; }
  fi
}

run_case mips ' 127 69 76 70 1 1 ' '' mipsle
run_case mips '127 69 76 70 1 2' '' mips
run_case mips '127 69 76 70 1 0' '' refuse
run_case mips '127 69 76 70 2 1' '' refuse
run_case mips '0 69 76 70 1 1' '' refuse
run_case mips '' '' refuse
run_case mips '127 69 76 70 1 1' '' refuse 1
run_case mips unknown mipsle mipsle
run_case mips '127 69 76 70 1 1' mips mips
run_case mips unknown mipsel mipsle
run_case mipsel unknown '' mipsle
run_case mipsle unknown '' mipsle
run_case aarch64 unknown '' arm64
run_case arm64 unknown '' arm64
run_case x86_64 unknown '' amd64
run_case amd64 unknown '' amd64
run_case unsupported unknown '' refuse
run_case mips unknown invalid refuse

# A release checksum is mandatory even for dry-run. Refusal must happen before
# the candidate executes, normalization or any live installation directory is
# created. The recording candidate and init scripts keep these tests isolated.
CHECKSUM="$BUNDLE/dist/SHA256SUMS"
CHECKSUM_NAME=razvilka-linux-amd64
CHECKSUM_HASH="$(sha256sum "$BUNDLE/dist/$CHECKSUM_NAME" | awk '{print $1}')"
run_checksum_case() {
  LABEL="$1"
  EXPECTED="$2"
  TEST_UNAME=amd64
  TEST_ELF_HEADER=unknown
  TEST_OD_FAIL=0
  RAZVILKA_ARCH=amd64
  export TEST_UNAME TEST_ELF_HEADER TEST_OD_FAIL RAZVILKA_ARCH
  rm -f "$TEST_BINARY_CAPTURE"
  if [ "$EXPECTED" = pass ]; then MODE=--dry-run; else MODE=--apply; fi
  if RAZVILKA_BASE="$BASE" sh "$BUNDLE/scripts/upgrade-entware.sh" "$MODE" >"$TEST_ROOT/output" 2>&1; then
    [ "$EXPECTED" = pass ] || { echo "Invalid checksum accepted: $LABEL" >&2; exit 1; }
    [ "$(wc -l <"$TEST_BINARY_CAPTURE" | tr -d ' ')" = 2 ] || { echo "Expected only candidate version and preflight checks: $LABEL" >&2; exit 1; }
  else
    [ "$EXPECTED" = refuse ] || { cat "$TEST_ROOT/output" >&2; echo "Valid checksum refused: $LABEL" >&2; exit 1; }
    [ ! -e "$TEST_BINARY_CAPTURE" ] || { echo "Unverified candidate was executed: $LABEL" >&2; exit 1; }
  fi
  [ ! -e "$BASE/bin" ] && [ ! -e "$BASE/etc" ] && [ ! -e "$BASE/var" ] || { echo "Checksum preflight changed installation: $LABEL" >&2; exit 1; }
}

rm -f "$CHECKSUM"
run_checksum_case missing-manifest refuse
: >"$CHECKSUM"
run_checksum_case empty-manifest refuse
printf '%s  razvilka-linux-arm64\n' "$CHECKSUM_HASH" >"$CHECKSUM"
run_checksum_case missing-current-architecture refuse
printf '  dist/%s\n' "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case missing-digest refuse
printf '%s  dist/%s\n' short "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case short-digest refuse
printf '%s  dist/%s\n' 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg' "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case non-hex-digest refuse
printf '%s  dist/%s\n' '0000000000000000000000000000000000000000000000000000000000000000' "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case wrong-digest refuse
printf '%s  dist/%s extra\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case extra-field refuse
printf '%s  dist/%s\n%s  %s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" "$CHECKSUM_HASH" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case duplicate-path-spellings refuse
printf '%s  dist/%s\n  %s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case valid-plus-empty-digest refuse
printf '%s  dist/%s\n%s  dist/%s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" wrong "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case valid-plus-invalid-duplicate refuse

printf '%s  dist/%s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case release-relative-path pass
printf '%s  %s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case legacy-bare-name pass
printf '%s *dist/%s\n' "$CHECKSUM_HASH" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case sha256sum-binary-marker pass
printf '%s  dist/%s\r\n' "$(printf '%s' "$CHECKSUM_HASH" | tr 'a-f' 'A-F')" "$CHECKSUM_NAME" >"$CHECKSUM"
run_checksum_case uppercase-hex-crlf pass

echo "Installer architecture selection tests: PASS"
echo "Installer mandatory checksum tests: PASS"
