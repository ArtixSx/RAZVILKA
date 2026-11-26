#!/bin/sh
set -eu

# Coordinator-only localhost TCP/SOCKS/TLS regression. No UDP, USQUE process,
# WARP account, registration, router or public network endpoint is contacted.
[ "${RAZVILKA_NATIVE_CLOUD_OWNED_DIAL:-}" = 1 ] || {
  echo "Set RAZVILKA_NATIVE_CLOUD_OWNED_DIAL=1 for the localhost owned HTTP dial harness" >&2
  exit 2
}
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
GO=${GO:-go}
export GOTOOLCHAIN=local
export GOMAXPROCS=${GOMAXPROCS:-2}
export GOFLAGS=${GOFLAGS:--p=2}
exec "$GO" test ./internal/usquediag -run '^TestNativeOwnedHTTPDialContextHarness$' -count=1 -v -timeout=60s
