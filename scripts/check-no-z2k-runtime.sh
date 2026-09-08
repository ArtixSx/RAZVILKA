#!/bin/sh
set -eu

for tool in dirname grep; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Required runtime dependency check tool is unavailable: $tool" >&2
    exit 2
  }
done
script_dir="$(dirname "$0")" || exit 2
cd "$script_dir/.."
scan_status=0
grep -R -n -E 'github\.com/necronicle/z2k|raw\.githubusercontent\.com/necronicle/z2k|codeload\.github\.com/necronicle/z2k' \
  cmd configs internal scripts .github \
  --exclude='check-no-z2k-runtime.sh' \
  --exclude='check-no-z2k-runtime.ps1' \
  --exclude-dir=testdata || scan_status=$?
case "$scan_status" in
  0) echo "Forbidden z2k runtime/download dependency found" >&2; exit 1 ;;
  1) ;; # grep found no matches; all other statuses are scan errors.
  *) echo "Runtime dependency scan failed (status $scan_status)" >&2; exit 2 ;;
esac
echo "NO_Z2K_RUNTIME_DEPENDENCY: PASS"
