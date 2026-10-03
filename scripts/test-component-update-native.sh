#!/bin/sh
# Opt-in native opkg integration, using only Go test temporary directories.
# The caller owns the VM/router window. This is not a physical power-cut test.
set -eu
cd "$(dirname "$0")/.."
OPKG="${RAZVILKA_TEST_OPKG:-opkg}"
command -v "$OPKG" >/dev/null 2>&1 || { echo "Native opkg is required; no test was run" >&2; exit 2; }
command -v ar >/dev/null 2>&1 || { echo "ar is required to build disposable test packages" >&2; exit 2; }
case "$(uname -s)" in Linux) ;; *) echo "Native opkg test requires Linux" >&2; exit 2 ;; esac
GO="${GO:-go}"
command -v "$GO" >/dev/null 2>&1 || { echo "Go is required; set GO to the pinned Go 1.26.5 executable" >&2; exit 2; }
GOTOOLCHAIN=local GOMAXPROCS="${GOMAXPROCS:-2}" GOFLAGS="${GOFLAGS:--p=2}" \
  RAZVILKA_NATIVE_OPKG_TEST=1 RAZVILKA_TEST_OPKG="$OPKG" \
  "$GO" test ./internal/components -run '^TestNativeOpkgManagedUpdateJournal$' -count=1 -timeout=3m -v
