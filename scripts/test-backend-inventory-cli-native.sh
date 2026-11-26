#!/bin/sh
set -eu

# ROOT-only process/pipe fixture. No CLI firewall/kernel/module/router access.
if [ "$(id -u)" != 0 ]; then
  echo "Run as ROOT in the exclusive Linux VM." >&2
  exit 2
fi
command -v unshare >/dev/null 2>&1
command -v readlink >/dev/null 2>&1
backend_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
backend_work=$(mktemp -d /tmp/razvilka-backend-cli.XXXXXX)
chmod 700 "$backend_work"
export TMPDIR="$backend_work"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2 GOOS=linux
case "$(uname -m)" in
  x86_64) export GOARCH=amd64 ;;
  aarch64) export GOARCH=arm64 ;;
  *) echo "This checkpoint supports Linux amd64/arm64 only." >&2; exit 2 ;;
esac
unset RAZVILKA_BACKEND_CLI_ROLE RAZVILKA_BACKEND_CLI_CASE RAZVILKA_BACKEND_CLI_STATE
export RAZVILKA_BACKEND_CLI_NATIVE=1
RAZVILKA_BACKEND_CLI_BASE_PIDNS=$(readlink /proc/self/ns/pid)
export RAZVILKA_BACKEND_CLI_BASE_PIDNS
cd "$backend_repo"
go test -c -o "$backend_work/dataplane.test" ./internal/dataplane
chmod 500 "$backend_work/dataplane.test"
ln "$backend_work/dataplane.test" "$backend_work/backend-read-cli"
export RAZVILKA_BACKEND_CLI_PROGRAM="$backend_work/backend-read-cli"
echo "Private native CLI artifacts: $backend_work"
# PID namespace init exiting kills every namespace descendant on test failure.
# pidfd + dedicated worker subreaper are fixture-only; no production API change.
unshare --fork --pid --mount-proc --kill-child=SIGKILL "$backend_work/dataplane.test" \
  -test.run='^TestBackendInventoryCLILimitsNative$' -test.count=1 -test.timeout=60s -test.v
echo "Retained private artifacts: $backend_work"
