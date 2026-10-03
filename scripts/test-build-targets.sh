#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_BASE="$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)"
WORK="$(mktemp -d "$TMP_BASE/razvilka-build-targets.XXXXXX")"
cleanup() {
  case "$WORK" in
    "$TMP_BASE"/razvilka-build-targets.*) rm -rf "$WORK" ;;
    *) echo 'Refusing cleanup outside the test directory' >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$WORK/bin" "$WORK/project/dist"
cp "$ROOT/build.sh" "$ROOT/VERSION" "$WORK/project/"
cat > "$WORK/bin/go" <<'FAKE_GO'
#!/bin/sh
set -eu
printf '%s %s %s\n' "$GOOS" "$GOARCH" "${GOMIPS:-}" >> "$BUILD_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then
    shift
    printf '%s\n' "$GOARCH" > "$1"
    exit 0
  fi
  shift
done
exit 1
FAKE_GO
chmod 700 "$WORK/bin/go"
PATH="$WORK/bin:$PATH"
export PATH
BUILD_LOG="$WORK/build.log"
export BUILD_LOG
cd "$WORK/project"
# All release targets remain the default, including soft-float MIPS variants.
unset RAZVILKA_BUILD_TARGETS GOMIPS
sh ./build.sh
[ "$(wc -l < "$BUILD_LOG" | tr -d ' ')" = 4 ]
grep -q '^linux mips softfloat$' "$BUILD_LOG"
grep -q '^linux mipsle softfloat$' "$BUILD_LOG"
[ "$(wc -l < dist/SHA256SUMS | tr -d ' ')" = 4 ]
# Existing outputs of other architectures must not enter an AArch64 manifest.
: > "$BUILD_LOG"
RAZVILKA_BUILD_TARGETS=arm64 sh ./build.sh
[ "$(wc -l < "$BUILD_LOG" | tr -d ' ')" = 1 ]
grep -q '^linux arm64 ' "$BUILD_LOG"
[ "$(wc -l < dist/SHA256SUMS | tr -d ' ')" = 1 ]
grep -q 'dist/razvilka-linux-arm64$' dist/SHA256SUMS
sha256sum -c dist/SHA256SUMS
# Development composition must rebuild both binaries and exclude stale MIPS.
: > "$BUILD_LOG"
RAZVILKA_BUILD_TARGETS=arm64+amd64 sh ./build.sh
printf 'linux arm64 \nlinux amd64 \n' > "$WORK/expected.log"
cmp "$WORK/expected.log" "$BUILD_LOG"
[ "$(wc -l < dist/SHA256SUMS | tr -d ' ')" = 2 ]
grep -q 'dist/razvilka-linux-arm64$' dist/SHA256SUMS
grep -q 'dist/razvilka-linux-amd64$' dist/SHA256SUMS
sha256sum -c dist/SHA256SUMS
# Exercise the production check composition without running Go or daemons.
mkdir -p scripts
awk '/^# Build the native executable required/ {copy=1} copy {print}' \
  "$ROOT/scripts/check.sh" > "$WORK/project/check-build.sh"
cat > "$WORK/bin/uname" <<'FAKE_UNAME'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "$TEST_SYSTEM" ;;
  -m) printf '%s\n' "$TEST_MACHINE" ;;
  *) exit 1 ;;
esac
FAKE_UNAME
cat > scripts/test-entware-transaction.sh <<'FAKE_TRANSACTION'
#!/bin/sh
set -eu
printf 'transaction\n' >> "$BUILD_LOG"
FAKE_TRANSACTION
chmod 700 "$WORK/bin/uname" ./build.sh
for scenario in linux-amd64 linux-arm64 other-amd64 default; do
  : > "$BUILD_LOG"
  TEST_SYSTEM=Linux TEST_MACHINE=x86_64 RAZVILKA_BUILD_TARGETS=arm64
  case "$scenario" in
    linux-amd64) printf 'linux arm64 \nlinux amd64 \n' > "$WORK/expected.log" ;;
    linux-arm64) TEST_MACHINE=aarch64; printf 'linux arm64 \n' > "$WORK/expected.log" ;;
    other-amd64) TEST_SYSTEM=Other; printf 'linux arm64 \n' > "$WORK/expected.log" ;;
    default) unset RAZVILKA_BUILD_TARGETS
      printf 'linux amd64 \nlinux arm64 \nlinux mips softfloat\nlinux mipsle softfloat\n' > "$WORK/expected.log" ;;
  esac
  export TEST_SYSTEM TEST_MACHINE RAZVILKA_BUILD_TARGETS
  printf 'transaction\n' >> "$WORK/expected.log"
  sh ./check-build.sh
  cmp "$WORK/expected.log" "$BUILD_LOG"
done
: > "$BUILD_LOG"
if RAZVILKA_BUILD_TARGETS=unknown sh ./build.sh >/dev/null 2>&1; then
  echo 'Invalid build target was accepted' >&2
  exit 1
fi
[ ! -s "$BUILD_LOG" ]
echo 'Build targets: PASS'
