#!/bin/sh
set -eu

# Coordinator-owned filesystem/subprocess window; no daemon, remote API,
# router, namespace, account or root privilege is used.
[ "${RAZVILKA_NATIVE_CLOUD_RETENTION:-}" = 1 ] || {
  echo "Set RAZVILKA_NATIVE_CLOUD_RETENTION=1 for the retention harness" >&2
  exit 2
}
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
GO=${GO:-go}
export GOTOOLCHAIN=local
export GOMAXPROCS=${GOMAXPROCS:-2}
export GOFLAGS=${GOFLAGS:--p=2}
exec "$GO" test ./internal/warp -run '^TestNativeLocalCloudRetentionHarness$' -count=1 -v -timeout=120s
