#!/bin/sh
# Opt-in native opkg integration, using only Go test temporary directories.
# The caller owns the VM/router window. This is not a physical power-cut test.
set -eu
cd "$(dirname "$0")/.."
OPKG="${RAZVILKA_TEST_OPKG:-opkg}"
command -v "$OPKG" >/dev/null 2>&1 || { echo "Native opkg is required; no test was run" >&2; exit 2; }
command -v ar >/dev/null 2>&1 || { echo "ar is required to build disposable test packages" >&2; exit 2; }
case "$(uname -s)" in Linux) ;; *) echo "Native opkg test requires Linux" >&2; exit 2 ;; esac
RAZVILKA_NATIVE_OPKG_TEST=1 RAZVILKA_TEST_OPKG="$OPKG" go test ./internal/components -run '^TestNativeOpkgManagedUpdateJournal$' -count=1 -v
