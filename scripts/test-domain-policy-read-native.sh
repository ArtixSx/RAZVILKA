#!/bin/sh
set -eu
umask 022
cd "$(dirname "$0")/.."
case "${1:-normal}" in
  normal) race_flag= ;;
  race) race_flag=-race ;;
  *) echo 'usage: test-domain-policy-read-native.sh [normal|race]' >&2; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
  echo 'This fixture needs root to create its isolated network namespace.' >&2
  exit 2
fi
command -v ip >/dev/null
command -v unshare >/dev/null
test "$(go env GOVERSION)" = "$(sed -n 's/^toolchain //p' go.mod)"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/razvilka-policy-read.XXXXXX")
trap 'rm -f "$fixture/policy.test"; rmdir "$fixture"' EXIT HUP INT TERM
# Compile before entering the private namespace; the test has no WAN access.
go test $race_flag -c -o "$fixture/policy.test" ./internal/physicalscope
unshare --net --fork sh -eu -c '
  ip link set lo up
  ip link add rz-domain-in type dummy
  ip link add rz-domain-out type dummy
  ip addr add 192.168.71.1/24 dev rz-domain-in
  ip addr add 192.168.72.1/24 dev rz-domain-out
  ip link set rz-domain-in up
  ip link set rz-domain-out up
  printf "1\n" > /proc/sys/net/ipv4/ip_forward
  ip route add default via 192.168.72.2 dev rz-domain-out
  ip route add table 10037 192.168.72.0/24 dev rz-domain-out scope link
  ip route add table 10037 default via 192.168.72.2 dev rz-domain-out
  for mark in 42 43 44 45; do
    ip rule add priority "$((100 + mark))" fwmark "$mark/0xff" lookup 10037
  done
  RAZVILKA_DOMAIN_POLICY_READ=1 RAZVILKA_DOMAIN_POLICY_LOOKUP_FIXTURE=1 RAZVILKA_DOMAIN_POLICY_WINDOW_NATIVE=1 \
    "$1" -test.v -test.count=1 -test.timeout=60s \
    -test.run="^TestNativeDomainIPv4Policy(Inventory|MarkedLookup|WindowRejectsRestoredRule)$"
' sh "$fixture/policy.test"
