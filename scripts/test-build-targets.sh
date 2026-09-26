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
: > "$BUILD_LOG"
if RAZVILKA_BUILD_TARGETS=unknown sh ./build.sh >/dev/null 2>&1; then
  echo 'Invalid build target was accepted' >&2
  exit 1
fi
[ ! -s "$BUILD_LOG" ]
echo 'Build targets: PASS'
