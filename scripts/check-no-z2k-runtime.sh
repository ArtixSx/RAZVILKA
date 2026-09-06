#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
if grep -R -n -E 'github\.com/necronicle/z2k|raw\.githubusercontent\.com/necronicle/z2k|codeload\.github\.com/necronicle/z2k' \
  cmd configs internal scripts .github \
  --exclude='check-no-z2k-runtime.sh' \
  --exclude='check-no-z2k-runtime.ps1' \
  --exclude-dir=testdata; then
  echo "Forbidden z2k runtime/download dependency found" >&2
  exit 1
fi
echo "NO_Z2K_RUNTIME_DEPENDENCY: PASS"
