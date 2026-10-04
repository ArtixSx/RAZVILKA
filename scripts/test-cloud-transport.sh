#!/bin/sh
set -eu

# Only the coordinator opens this localhost TCP/UDP window. No registration,
# router, namespace, root privilege, USQUE binary or WARP account is needed.
[ "${RAZVILKA_NATIVE_CLOUD_TRANSPORT:-}" = 1 ] || {
  echo "Set RAZVILKA_NATIVE_CLOUD_TRANSPORT=1 for the localhost H2/H3 harness" >&2
  exit 2
}
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
GO=${GO:-go}
export GOTOOLCHAIN=local
export GOMAXPROCS=${GOMAXPROCS:-2}
export GOFLAGS=${GOFLAGS:--p=2}
exec "$GO" test ./internal/usquediag -run '^TestNativeLocalCloudTransportHarness$' -count=1 -v -timeout=60s
