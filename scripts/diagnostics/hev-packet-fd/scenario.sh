#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
if [ "${1:-}" != --private ]; then
    : "${RAZVILKA_XRAY_NATIVE:?Xray fixture executable required}"
    : "${RAZVILKA_FIXTURE_ORIGIN:?project home-egress origin executable required}"
    : "${RAZVILKA_HEV_RELAY:?compiled packet-fd relay required}"
    for bin in "$RAZVILKA_XRAY_NATIVE" "$RAZVILKA_FIXTURE_ORIGIN" "$RAZVILKA_HEV_RELAY"; do
        case "$bin" in /*) test -x "$bin";; *) exit 2;; esac
    done
    base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
    dir=$(mktemp -d /tmp/rz-packet-fd.XXXXXX)
    trap 'rm -rf "$dir"' EXIT
    exec 7</proc/self/ns/pid 8</proc/self/ns/net 9</proc/self/ns/mnt
    timeout -k 4 80 unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private sh "$base/scenario.sh" --private "$dir"
    exit
fi
test "$$" -eq 1
for entry in pid:7 net:8 mnt:9; do
    ns=${entry%:*}; fd=${entry#*:}; parent=$(readlink "/proc/self/fd/$fd")
    case "$parent" in "$ns":'['*']') ;; *) exit 2;; esac
    test "$(readlink "/proc/self/ns/$ns")" != "$parent"
done
test "$(ip -o link show | wc -l)" = 1
work=$2
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
pids=""; relay=""
cleanup() {
    rc=$?
    if test "$rc" -ne 0 && test -f "$work/relay.log"; then cat "$work/relay.log"; fi
    trap - EXIT
    if [ -n "$relay" ]; then kill "$relay" 2>/dev/null || :; wait "$relay" || rc=1; fi
    for c in $pids; do kill "$c" 2>/dev/null || :; wait "$c" 2>/dev/null || :; done
    if ip link show dev rzfd0 >/dev/null 2>&1; then rc=1; fi
    for ns in lan wan; do
        if test -e "/run/netns/$ns"; then
            test -z "$(ip netns pids "$ns")" || rc=1
            if ip link show dev "$ns" >/dev/null 2>&1; then ip link del dev "$ns" || rc=1; fi
            ip netns del "$ns" || rc=1
        fi
    done
    test -z "$(ip netns list)" && test "$(ip -o link | wc -l)" -eq 1 || rc=1
    test "$rc" -ne 0 || echo "cleanup=joined-children-and-removed-interfaces"
    exit "$rc"
}
trap cleanup EXIT
ip link set lo up
for pair in lan:192.168.70 wan:10.31.1; do
    ns=${pair%:*}; net=${pair#*:}
    ip netns add "$ns"; ip -n "$ns" link set lo up
    ip link add "$ns" type veth peer name peer; ip link set peer netns "$ns"
    ip -n "$ns" link set peer up; ip link set "$ns" up
    ip addr add "$net.1/24" dev "$ns"; ip -n "$ns" addr add "$net.2/24" dev peer
    ip -n "$ns" route add default via "$net.1"
done
ip -n wan addr add 192.0.2.12/32 dev lo
ip route add 192.0.2.12/32 via 10.31.1.2
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=1
uuid=$(cat /proc/sys/kernel/random/uuid)
cat >"$work/server.json" <<EOF
{"inbounds":[{"listen":"10.31.1.2","port":24000,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}]}
EOF
cat >"$work/client.json" <<EOF
{"inbounds":[{"listen":"127.0.0.1","port":11508,"protocol":"socks"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"10.31.1.2","port":24000,"users":[{"id":"$uuid","encryption":"none"}]}]}}]}
EOF
cat >"$work/hev.yml" <<EOF
tunnel: {name: rzfd0, mtu: 1500, ipv4: 198.18.77.1}
socks5: {address: 127.0.0.1, port: 11508, udp: tcp}
misc: {log-level: warn}
EOF
ip netns exec wan "$RAZVILKA_FIXTURE_ORIGIN" 192.0.2.12:443 wan >"$work/origin.log" 2>&1 & pids="$! $pids"
ip netns exec wan "$RAZVILKA_XRAY_NATIVE" run -config "$work/server.json" >"$work/server.log" 2>&1 & pids="$! $pids"
"$RAZVILKA_XRAY_NATIVE" run -config "$work/client.json" >"$work/client.log" 2>&1 & pids="$! $pids"
sleep 1
bulk() { ip netns exec lan "$RAZVILKA_FIXTURE_ORIGIN" check-bulk 192.0.2.12:443 "$1"; }
bulk wan
ip -n lan addr add 192.168.70.22/24 dev peer
ip -n lan route replace 192.0.2.12/32 via 192.168.70.1 dev peer src 192.168.70.22
# The independent WAN peer observes *all* selected packets, including FIN/ACK.
# Source .22 distinguishes proxy tests from baseline and restored requests.
ip netns exec wan nft -f - <<'EOF'
table netdev observation {
  chain wire {
    type filter hook ingress device "peer" priority -500;
    ip saddr 192.168.70.22 ip daddr 192.0.2.12 tcp dport 443 counter
  }
}
EOF
wire_packets() {
    ip netns exec wan nft list chain netdev observation wire | awk '/counter packets/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}'
}
set -- "$work/hev.yml"
if [ -n "${RAZVILKA_QUEUE_SOURCE:-}" ]; then
    case "$RAZVILKA_QUEUE_SOURCE" in /*) test -x "$RAZVILKA_QUEUE_SOURCE";; *) exit 2;; esac
    set -- "$@" "$RAZVILKA_QUEUE_SOURCE"
fi
"$RAZVILKA_HEV_RELAY" "$@" >"$work/relay.log" 2>&1 & relay=$!
for i in $(seq 1 50); do ip link show dev rzfd0 >/dev/null 2>&1 && break; sleep .1; done
sysctl -qw net.ipv6.conf.rzfd0.disable_ipv6=1
ip link set rzfd0 mtu 1500 up
ip addr add 198.18.77.1/32 dev rzfd0
ip route replace 192.0.2.12/32 dev rzfd0
if [ -n "${RAZVILKA_QUEUE_SOURCE:-}" ]; then
    for i in $(seq 1 50); do grep -q nfqueue-ready "$work/relay.log" && break; sleep .1; done
    grep -q nfqueue-ready "$work/relay.log"
    nft -f - <<'EOF'
table ip fd_source {
  chain feed {
    type filter hook postrouting priority 90;
    iifname "lan" oifname "rzfd0" ip saddr 192.168.70.22 ip daddr 192.0.2.12 tcp dport 443 counter queue num 17747
  }
}
EOF
fi
if ! bulk xray; then cat "$work/relay.log"; exit 1; fi
sleep 1
test "$(wire_packets)" = 0
echo "selected-target-on-WAN-wire=0"
ip -n lan route del 192.0.2.12/32
ip -n lan addr del 192.168.70.22/24 dev peer
ip route replace 192.0.2.12/32 via 10.31.1.2
if [ -n "${RAZVILKA_QUEUE_SOURCE:-}" ]; then nft delete table ip fd_source; fi
kill "$relay"; wait "$relay"; relay=""
cat "$work/relay.log"
if [ -n "${RAZVILKA_QUEUE_SOURCE:-}" ]; then
    grep -Eq '^nfqueue-complete-packets=[1-9][0-9]*$' "$work/relay.log"
    grep -Eq '^relay_packets_to_hev=0 relay_packets_to_original_tun=[1-9][0-9]*$' "$work/relay.log"
else
    grep -Eq '^relay_packets_to_hev=[1-9][0-9]* relay_packets_to_original_tun=[1-9][0-9]*$' "$work/relay.log"
fi
if ip link show rzfd0 >/dev/null 2>&1; then exit 1; fi
bulk wan
test "$(wire_packets)" = 0
# Positive control demonstrates that the independent observer sees traffic
# from the exact same source, destination and port on restored native WAN.
ip -n lan addr add 192.168.70.22/24 dev peer
ip -n lan route replace 192.0.2.12/32 via 192.168.70.1 dev peer src 192.168.70.22
bulk wan
observed=$(wire_packets)
test "$observed" -gt 0
echo "restored-native-WAN-wire=$observed"
