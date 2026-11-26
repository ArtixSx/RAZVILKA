#!/bin/sh
set -eu

# ROOT ONLY: actual NFQUEUE/iptables/LAN packets in a new disposable netns.
# Requires an explicit pinned genuine review; never downloads or controls stock.
if [ "$(id -u)" != 0 ]; then
  echo "Run as ROOT in an exclusive Linux VM." >&2
  exit 2
fi
: "${RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW:?ROOT must supply pinned genuine bytes review}"
for nfqws_tool in unshare nsenter ip iptables-legacy ip6tables-legacy nft; do
  command -v "$nfqws_tool" >/dev/null 2>&1
done
nfqws_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
nfqws_work=$(mktemp -d /tmp/razvilka-nfqws-scoped-kernel.XXXXXX)
chmod 700 "$nfqws_work"
export TMPDIR="$nfqws_work"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_NFQWS_MANAGED_PROCESS_NATIVE=1 RAZVILKA_NFQWS_SCOPED_NATIVE=1
cd "$nfqws_repo"
go test -c -o "$nfqws_work/dataplane.test" ./internal/dataplane
chmod 500 "$nfqws_work/dataplane.test"
unshare --net "$nfqws_work/dataplane.test" -test.run='^TestNFQWSScopedKernelNative$' -test.count=1 -test.v -test.timeout=45s
echo "Retained private artifacts: $nfqws_work"
