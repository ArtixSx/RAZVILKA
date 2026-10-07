#!/bin/sh
set -eu

# ROOT ONLY: paired Manager/managed Start/queue/LAN in a disposable netns.
# No downloads, module loading, stock service control or production launch.
if [ "$(id -u)" != 0 ]; then
  echo "Run as ROOT in an exclusive Linux VM." >&2
  exit 2
fi
: "${RAZVILKA_NFQWS_MANAGED_GENUINE_REVIEW:?ROOT must supply pinned genuine bytes review}"
for paired_tool in unshare nsenter ip iptables-legacy ip6tables-legacy nft; do
  command -v "$paired_tool" >/dev/null 2>&1
done
paired_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
paired_work=$(mktemp -d /tmp/razvilka-nfqws-manager-paired.XXXXXX)
chmod 700 "$paired_work"
export TMPDIR="$paired_work"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=2
export RAZVILKA_NFQWS_MANAGED_PROCESS_NATIVE=1 RAZVILKA_NFQWS_MANAGER_PAIRED_NATIVE=1
cd "$paired_repo"
go test -c -o "$paired_work/dataplane.test" ./internal/dataplane
chmod 500 "$paired_work/dataplane.test"
unshare --net "$paired_work/dataplane.test" -test.run='^TestNetworkPolicyManagerNFQWSPairedNative$' -test.count=1 -test.v -test.timeout=90s
echo "Retained private artifacts: $paired_work"
