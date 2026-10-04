#!/bin/sh
set -eu

# ROOT-only isolated native harness. Keeps private artifacts for inspection.
# No host package init, NFQUEUE rules, queue allocation or runtime activation.
if [ "$(id -u)" != 0 ]; then
  echo "Run as ROOT in an exclusive Linux VM/netns." >&2
  exit 2
fi
command -v unshare >/dev/null 2>&1
nfqws_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
nfqws_work=$(mktemp -d /tmp/razvilka-nfqws-managed-process.XXXXXX)
chmod 700 "$nfqws_work"
export TMPDIR="$nfqws_work"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_NFQWS_MANAGED_PROCESS_NATIVE=1
unset RAZVILKA_NFQWS_PROCESS_FIXTURE RAZVILKA_NFQWS_NATIVE_REVIEW RAZVILKA_NFQWS_SUPERVISED_FIXTURE
cd "$nfqws_repo"
go test -c -o "$nfqws_work/dataplane.test" ./internal/dataplane
chmod 500 "$nfqws_work/dataplane.test"
unshare --net "$nfqws_work/dataplane.test" -test.run='^TestNFQWSManaged(ProcessLifecycleNative|GenuineNoInterceptNative)$' -test.count=1 -test.v
echo "Retained private artifacts: $nfqws_work"
