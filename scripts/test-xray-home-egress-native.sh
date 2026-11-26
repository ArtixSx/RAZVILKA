#!/bin/sh
# Real HTTP/VLESS/HEV path fixture for a synthetic, disconnected Linux network.
# Requires iproute2, iptables, BusyBox wget, util-linux and a working /dev/net/tun.
# Set RAZVILKA_TEST_TC_EGRESS=1 to test the additional tc path and its collision limit.
# Set RAZVILKA_TEST_NFT_EGRESS=1 to also test nft postrouting in a fresh namespace.
# Set RAZVILKA_TEST_NFQUEUE_EGRESS=1 for the packet-fd variant of the nft test.
# Stock HEV uses RAZVILKA_HEV_NATIVE. The packet-fd test uses RAZVILKA_HEV_RELAY
# and RAZVILKA_QUEUE_SOURCE. Both need an absolute RAZVILKA_XRAY_NATIVE path.
set -eu

if [ "${1:-}" != "--private" ]; then
    test "$(id -u)" = 0
    : "${RAZVILKA_XRAY_NATIVE:?Xray binary required}"
    if [ "${RAZVILKA_TEST_NFQUEUE_EGRESS:-0}" = 1 ]; then
        : "${RAZVILKA_HEV_RELAY:?packet-fd relay required}" "${RAZVILKA_QUEUE_SOURCE:?NFQUEUE source required}"
        set -- "$RAZVILKA_XRAY_NATIVE" "$RAZVILKA_HEV_RELAY" "$RAZVILKA_QUEUE_SOURCE"
    else
        : "${RAZVILKA_HEV_NATIVE:?HEV binary required}"
        set -- "$RAZVILKA_XRAY_NATIVE" "$RAZVILKA_HEV_NATIVE"
    fi
    for binary do
        case "$binary" in /*) test -x "$binary";; *) exit 2;; esac
    done
    base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
    work=$(mktemp -d /tmp/razvilka-home-egress.XXXXXX)
    trap 'rm -rf -- "$work"' EXIT
    if [ -n "${RAZVILKA_FIXTURE_ORIGIN:-}" ]; then
        # A diskless guest may use the same fixture cross-compiled on its host.
        case "$RAZVILKA_FIXTURE_ORIGIN" in /*) test -x "$RAZVILKA_FIXTURE_ORIGIN";; *) exit 2;; esac
    else
        RAZVILKA_FIXTURE_ORIGIN=$work/origin
        CGO_ENABLED=0 go build -o "$RAZVILKA_FIXTURE_ORIGIN" "$base/testdata/home-egress/origin.go"
    fi
    export RAZVILKA_FIXTURE_ORIGIN
    exec 7</proc/self/ns/pid 8</proc/self/ns/net 9</proc/self/ns/mnt
    modes=native
    if [ "${RAZVILKA_TEST_NFT_EGRESS:-0}" = 1 ]; then modes="native nft"; fi
    if [ "${RAZVILKA_TEST_NFQUEUE_EGRESS:-0}" = 1 ]; then modes=nft-queue; fi
    if [ "${RAZVILKA_TEST_NFT_RETENTION:-0}" = 1 ]; then
        test "${RAZVILKA_TEST_NFQUEUE_EGRESS:-0}" = 1
        modes=nft-queue-retention
    fi
    for mode in $modes; do
        limit=90
        if [ "$mode" = nft-queue-retention ]; then limit=165; fi
        mkdir "$work/$mode"
        timeout -k 5 "$limit" unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private \
            sh "$base/test-xray-home-egress-native.sh" --private "$work/$mode" "$mode"
    done
    exit
fi

test "$$" -eq 1
for pair in pid:7 net:8 mnt:9; do
    kind=${pair%:*}
    origin=$(readlink "/proc/self/fd/${pair#*:}")
    case "$origin" in "$kind":'['*']') ;; *) exit 2;; esac
    test "$(readlink "/proc/self/ns/$kind")" != "$origin"
done
test "$(ip -o link show | wc -l)" -eq 1
ip link show dev lo >/dev/null
test -c /dev/net/tun
work=$2
case "$work" in /tmp/razvilka-home-egress.*) test -d "$work";; *) exit 2;; esac
# ip netns accesses /run/netns, which must be private even on early exit.
mount -t tmpfs tmpfs /run
mkdir /run/netns
ip link set lo up
pids=""
namespaces='home wan vpn'
mode=$3
packet_source=tun
set_size=1024
if [ "$mode" = nft-queue-retention ]; then mode=nft-queue; set_size=1; fi
if [ "$mode" = nft-queue ]; then mode=nft; packet_source=queue; fi
relay_pid=""
idle_pid=""
case "$mode" in
    native) ;;
    nft) namespaces="$namespaces other"; command -v nft >/dev/null ;;
    *) exit 2 ;;
esac
for n in $namespaces; do
    ip netns add "$n"
    ip -n "$n" link set lo up
    ip link add "$n" type veth peer name peer
    ip link set peer netns "$n"
    ip -n "$n" link set peer up
    ip link set "$n" up
done
cleanup() {
    fail=0
    if [ -n "$idle_pid" ]; then
        kill "$idle_pid" 2>/dev/null || :
        wait "$idle_pid" || :
    fi
    if [ -n "$relay_pid" ]; then
        if nft list table ip rzlab >/dev/null 2>&1; then nft delete table ip rzlab || fail=1; fi
        kill "$relay_pid" 2>/dev/null || :
        wait "$relay_pid" || fail=1
        if ip link show dev rzfd0 >/dev/null 2>&1; then fail=1; fi
    fi
    for pid in $pids; do
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
    if [ "$mode" = nft ]; then ip link del lanport || fail=1; fi
    for n in $namespaces; do
        test -z "$(ip netns pids "$n")" || fail=1
        ip link del "$n" || fail=1
        ip netns del "$n" || fail=1
    done
    test "$(ip -o link show | wc -l)" -eq 1 && ip link show dev lo >/dev/null || fail=1
    test -z "$(ip netns list)" || fail=1
    return "$fail"
}
trap 'rc=$?; cleanup || rc=1; exit "$rc"' EXIT
if [ "$mode" = nft ]; then
    ip link set home down
    ip link set home name lanport
    ip link add home type bridge
    ip link set lanport master home
    ip link set lanport up
    ip link set home up
fi
ip addr add 192.168.70.1/24 dev home
ip -n home addr add 192.168.70.20/24 dev peer
ip -n home route add default via 192.168.70.1
for entry in wan:10.31.1 vpn:10.31.2; do
    n=${entry%:*}
    net=${entry#*:}
    ip addr add "$net.1/30" dev "$n"
    ip -n "$n" addr add "$net.2/30" dev peer
    ip -n "$n" addr add 192.0.2.12/32 dev lo
    ip -n "$n" route add 192.168.70.0/24 via "$net.1"
    ip netns exec "$n" "$RAZVILKA_FIXTURE_ORIGIN" 192.0.2.12:443 "$n" &
    pids="$pids $!"
done
ip route add 192.0.2.12/32 via 10.31.1.2
ip route add table 102 192.0.2.12/32 via 10.31.2.2 dev vpn
sysctl -qw net.ipv4.ip_forward=1
for n in all default home vpn wan; do sysctl -qw "net.ipv4.conf.$n.rp_filter=0"; done

# An ephemeral test-only identifier; all traffic stays within the namespaces.
uuid=$(cat /proc/sys/kernel/random/uuid)
cat > "$work/server.json" <<EOF
{"inbounds":[{"listen":"10.31.1.2","port":24000,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}]}
EOF
cat > "$work/client.json" <<EOF
{"inbounds":[{"listen":"127.0.0.1","port":11508,"protocol":"socks"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"10.31.1.2","port":24000,"users":[{"id":"$uuid","encryption":"none"}]}]}}]}
EOF
cat > "$work/hev.yml" <<EOF
tunnel: {name: rzh0, mtu: 1500, ipv4: 198.18.77.1}
socks5: {address: 127.0.0.1, port: 11508, udp: tcp}
misc: {log-level: warn}
EOF
ip netns exec wan "$RAZVILKA_XRAY_NATIVE" run -config "$work/server.json" > "$work/server.log" 2>&1 &
pids="$pids $!"
"$RAZVILKA_XRAY_NATIVE" run -config "$work/client.json" > "$work/client.log" 2>&1 &
pids="$pids $!"
if [ "$packet_source" = queue ]; then
    "$RAZVILKA_HEV_RELAY" "$work/hev.yml" "$RAZVILKA_QUEUE_SOURCE" > "$work/hev.log" 2>&1 &
    relay_pid=$!
    for i in $(seq 1 50); do grep -q '^nfqueue-ready$' "$work/hev.log" && break; sleep .1; done
    grep -q '^nfqueue-ready$' "$work/hev.log"
    sysctl -qw net.ipv6.conf.rzfd0.disable_ipv6=1 net.ipv4.conf.rzfd0.rp_filter=0
    ip link set rzfd0 mtu 1500 up
    ip addr add 198.18.77.1/32 dev rzfd0
    ip route get 192.0.2.12 from 192.168.70.20 iif home | grep 'dev wan'
else
    "$RAZVILKA_HEV_NATIVE" "$work/hev.yml" > "$work/hev.log" 2>&1 &
    pids="$pids $!"
    for i in $(seq 1 50); do ip -o -4 addr show dev rzh0 2>/dev/null | grep -q '198.18.77.1/32' && break; sleep .1; done
    ip route add 198.18.77.2/32 dev rzh0
fi

get() { ip netns exec home busybox wget -Y off -q -T 2 -O - http://192.0.2.12:443/; }
expect() {
    observed=$(get)
    printf '%s expected=%s observed=%s\n' "$1" "$2" "$observed"
    test "$observed" = "$2"
}
swap() {
    ip -n home addr flush dev peer
    ip -n home link set peer address "$1"
    ip -n home addr add "192.168.70.$2/24" dev peer
    ip -n home route replace default via 192.168.70.1
    ip neigh flush dev home
}
jump() {
    iptables -t security "$1" FORWARD -i home -o wan -s 192.168.70.0/24 \
        -d 192.0.2.12/32 -p tcp --dport 443 -j RZLAB
}
# This synthetic topology owns every hook. Real drivers/hooks require a
# separate platform proof. A late forwarding restriction invalidates the test layout.
empty_late_hooks() {
    for tuple in security:FORWARD mangle:POSTROUTING nat:POSTROUTING; do
        chain=${tuple#*:}
        rules=$(iptables -t "${tuple%:*}" -S "$chain") || return 1
        test "$rules" = "-P $chain ACCEPT" || return 1
    done
}

sleep 1
expect baseline wan
if [ "$mode" = nft ]; then
    # The isolated router owns this hook order: native filter (85), diversion (90), SNAT (100).
    # Verify the same packet's Home ingress, WAN choice and individual source MAC before SNAT.
    iptables -t nat -A POSTROUTING -s 192.168.70.0/24 -o wan -j SNAT --to-source 10.31.1.1
    expect nft-native-snat wan-snat
    ip netns exec home "$RAZVILKA_FIXTURE_ORIGIN" check-bulk 192.0.2.12:443 wan-snat
    diversion='dup to 198.18.77.2 device "rzh0" drop'
    if [ "$packet_source" = queue ]; then diversion='queue num 17747'; fi
    nft -f - <<EOF
table ip rzlab {
    set selected_tcp {
        type ether_addr . ipv4_addr . inet_service . ipv4_addr . inet_service
        # Bounded by this trial generation. Retain membership until detach.
        flags dynamic
        size $set_size
    }
    chain before_snat {
        type filter hook postrouting priority 90; policy accept;
        iifname "home" oifname "wan" ip saddr 192.168.70.0/24 ip saddr != 192.168.70.64/26 ip daddr 192.0.2.12 ip protocol tcp tcp dport 443 ether saddr & 01:00:00:00:00:00 == 00:00:00:00:00:00 ether saddr != 00:00:00:00:00:00 ether saddr != 02:00:00:00:00:55 jump selected
    }
    chain selected {
        # Admit new connections only after checking both sides of native DNAT.
        ct direction original ct original ip daddr 192.0.2.12 ct original proto-dst 443 tcp flags & (syn | ack) == syn add @selected_tcp { ether saddr . ip saddr . tcp sport . ip daddr . tcp dport }
        ct direction original ct original ip daddr 192.0.2.12 ct original proto-dst 443 jump admitted
        ct direction original ct original ip daddr 192.0.2.12 ct original proto-dst 443 tcp flags & (syn | ack) == syn counter drop
        # The original stopped before confirmation. HEV's return can create
        # the reverse tuple. A final FIN may also be INVALID. A reverse or
        # terminal packet cannot open a new path or qualify native DNAT.
        ct direction reply ct original ip saddr 192.0.2.12 ct original proto-src 443 ct status & dnat == 0 ct status & snat == 0 tcp flags & syn == 0 jump admitted
        ct state invalid tcp flags & syn == 0 jump admitted
    }
    chain admitted {
        ether saddr . ip saddr . tcp sport . ip daddr . tcp dport @selected_tcp counter $diversion
    }
}
EOF
    # Count packets reaching the simulated ISP outside the VLESS connection.
    observe_wan() {
        ip netns exec wan nft -f - <<'EOF'
table netdev observe {
    chain ingress {
        type filter hook ingress device "peer" priority -500; policy accept;
        ip daddr 192.0.2.12 tcp dport 443 counter
    }
}
EOF
    }
    wire_packets() {
        ip netns exec wan nft list chain netdev observe ingress | awk '/counter packets/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}'
    }
    observe_wan
    if [ "$set_size" -eq 1 ]; then
        ip netns exec home "$RAZVILKA_FIXTURE_ORIGIN" check-retained 192.0.2.12:443 xray >"$work/retained.log" 2>&1 &
        idle_pid=$!
        for tick in $(seq 1 50); do
            grep -q '^retention-first-response-and-capacity-refusal$' "$work/retained.log" && break
            sleep .1
        done
        grep -q '^retention-first-response-and-capacity-refusal$' "$work/retained.log"
        admitted_packets() {
            nft list chain ip rzlab admitted | awk '/counter packets/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}'
        }
        sleep 1
        first_count=$(admitted_packets)
        test "$first_count" -gt 0
        sleep 117
        test "$(admitted_packets)" = "$first_count"
        wait "$idle_pid"
        idle_pid=""
        echo admission-count-unchanged-for=117s
        cat "$work/retained.log"
        sleep 1
        test "$(wire_packets)" = 0
        echo nft-idle-and-full-direct-packets=0
        nft list chain ip rzlab selected | grep -Eq 'counter packets [1-9][0-9]* bytes [0-9]+ drop'
        nft delete table ip rzlab
        kill "$relay_pid"; wait "$relay_pid"; relay_pid=""
        grep -E '^nfqueue-complete-packets=[1-9][0-9]*$' "$work/hev.log"
        if ip link show dev rzfd0 >/dev/null 2>&1; then exit 1; fi
        expect nft-detached wan-snat
        test "$(wire_packets)" -gt 0
        ip netns exec wan nft delete table netdev observe
        exit 0
    fi
    expect nft-allowed xray
    ip netns exec home "$RAZVILKA_FIXTURE_ORIGIN" check-bulk 192.0.2.12:443 xray
    sleep 1
    test "$(wire_packets)" = 0
    echo nft-selected-direct-packets=0
    # Native DNAT may map a different site address or port to the selected endpoint.
    for addrport in 192.0.2.13:443 192.0.2.12:444; do
        iptables -t nat -A PREROUTING -i home -d "${addrport%:*}" -p tcp --dport "${addrport#*:}" -j DNAT --to-destination 192.0.2.12:443
        observed=$(ip netns exec home busybox wget -Y off -q -T 2 -O - "http://$addrport/")
        echo "nft-native-dnat $addrport observed=$observed"
        test "$observed" = wan-snat
        iptables -t nat -D PREROUTING -i home -d "${addrport%:*}" -p tcp --dport "${addrport#*:}" -j DNAT --to-destination 192.0.2.12:443
    done
    # The same observer must see the independent native DNAT controls.
    direct_packets=$(wire_packets)
    test "$direct_packets" -gt 0
    echo "nft-native-control-direct-packets=$direct_packets"
    ip netns exec wan nft delete table netdev observe
    swap 02:00:00:00:00:55 22; expect nft-excluded-mac wan-snat
    swap 02:00:00:00:00:55 23; expect nft-excluded-mac-new-ip wan-snat
    swap 02:00:00:00:00:88 75; expect nft-excluded-prefix wan-snat
    swap 02:00:00:00:00:41 41
    observe_wan
    expect nft-new-device xray
    ip netns exec home "$RAZVILKA_FIXTURE_ORIGIN" check-bulk 192.0.2.12:443 xray
    sleep 1
    test "$(wire_packets)" = 0
    echo nft-new-device-direct-packets=0
    ip netns exec wan nft delete table netdev observe
    swap 02:00:00:00:00:33 25; expect nft-next-device xray

    # Give another ingress the admitted client's MAC and a source inside Home.
    ip -n other link set peer address 02:00:00:00:00:33
    ip addr add 10.20.40.1/24 dev other
    ip -n other addr add 10.20.40.2/24 dev peer
    ip -n other addr add 192.168.70.27/32 dev peer
    ip -n other route add default via 10.20.40.1 src 192.168.70.27
    ip route add 192.168.70.27/32 via 10.20.40.2
    observed=$(ip netns exec other busybox wget -Y off -q -T 2 -O - http://192.0.2.12:443/)
    echo "nft-other-ingress expected=wan-snat observed=$observed"
    test "$observed" = wan-snat

    ip route replace 192.0.2.12/32 via 10.31.1.2 src 192.168.70.1
    observed=$(busybox wget -Y off -q -T 2 -O - http://192.0.2.12:443/)
    echo "nft-router-local expected=wan-snat observed=$observed"
    test "$observed" = wan-snat
    ip route replace 192.0.2.12/32 via 10.31.1.2
    ip rule add pref 95 from 192.168.70.25/32 to 192.0.2.12/32 lookup 102
    expect nft-native-vpn vpn
    ip rule del pref 95 from 192.168.70.25/32 to 192.0.2.12/32 lookup 102

    nft -f - <<'EOF'
table ip fixture_firewall {
    chain late {
        type filter hook postrouting priority 85; policy accept;
        iifname "home" oifname "wan" ct original ip saddr 192.168.70.25 ip daddr 192.0.2.12 ip protocol tcp tcp dport 443 counter drop
    }
}
EOF
    if get > "$work/denied" 2>/dev/null; then exit 1; fi
    test ! -s "$work/denied"
    nft list table ip fixture_firewall | grep -Eq 'counter packets [1-9][0-9]* bytes'
    echo nft-native-postrouting-drop
    nft delete table ip fixture_firewall
    observe_wan
    expect nft-restored-allow xray
    sleep 1
    test "$(wire_packets)" = 0
    echo nft-before-detach-direct-packets=0
    nft list table ip rzlab | grep -Eq 'counter packets [1-9][0-9]* bytes'
    nft delete table ip rzlab
    if [ "$packet_source" = queue ]; then
        kill "$relay_pid"
        wait "$relay_pid"
        relay_pid=""
        grep -E '^nfqueue-complete-packets=[1-9][0-9]*$' "$work/hev.log"
        grep -E '^relay_packets_to_hev=0 relay_packets_to_original_tun=[1-9][0-9]*$' "$work/hev.log"
        if ip link show dev rzfd0 >/dev/null 2>&1; then exit 1; fi
    fi
    expect nft-detached wan-snat
    detached_packets=$(wire_packets)
    test "$detached_packets" -gt 0
    echo "nft-detached-direct-packets=$detached_packets"
    ip netns exec wan nft delete table netdev observe
    exit 0
fi
iptables -t mangle -A POSTROUTING -o wan -p tcp --dport 443 -j DROP
if empty_late_hooks; then echo 'foreign late policy was accepted' >&2; exit 1; fi
test -z "$(get 2>/dev/null || :)"
echo late-native-policy-refused
iptables -t mangle -D POSTROUTING -o wan -p tcp --dport 443 -j DROP
empty_late_hooks

iptables -t security -N RZLAB
iptables -t security -A RZLAB -s 192.168.70.64/26 -j RETURN
iptables -t security -A RZLAB -m mac --mac-source 02:00:00:00:00:55 -j RETURN
iptables -t security -A RZLAB -j TEE --gateway 198.18.77.2 --oif rzh0
iptables -t security -A RZLAB -j DROP
jump -A
expect allowed xray
swap 02:00:00:00:00:55 22; expect excluded-mac wan
swap 02:00:00:00:00:55 23; expect changed-ip-excluded-mac wan
swap 02:00:00:00:00:88 75; expect excluded-cidr wan
swap 02:00:00:00:00:33 21; expect new-home-client xray
ip rule add pref 95 from 192.168.70.21/32 to 192.0.2.12/32 lookup 102
ip route get 192.0.2.12 from 192.168.70.21 iif home | grep 'dev vpn'
expect new-native-unmarked-rule vpn
ip rule del pref 95 from 192.168.70.21/32 to 192.0.2.12/32 lookup 102
iptables -A FORWARD -i home -o wan -s 192.168.70.21 -p tcp --dport 443 -j DROP
if get > "$work/denied" 2>/dev/null; then exit 1; fi
test ! -s "$work/denied"
iptables -nvxL FORWARD | awk '$3=="DROP" && $1+0>0 {hit=1} END {exit !hit}'
echo native-filter-denied
iptables -D FORWARD -i home -o wan -s 192.168.70.21 -p tcp --dport 443 -j DROP
expect restored-allow xray
jump -D
iptables -t security -F RZLAB
iptables -t security -X RZLAB
empty_late_hooks
expect detached wan

# Optional second packet path: native routing and all netfilter hooks complete
# before the WAN egress classifier redirects a positively qualified packet.
if [ "${RAZVILKA_TEST_TC_EGRESS:-0}" = 1 ]; then
    command -v tc >/dev/null
    home_iif=$(ip -o link show dev home | cut -d: -f1)
    qualifier='-s 192.168.70.0/24 -d 192.0.2.12/32 -p tcp --dport 443'
    # The fixture creates this namespace. Unknown priority writers on a real
    # host require separate ownership evidence across the whole packet path.
    slot_free() {
        forward=$(iptables -t mangle -S FORWARD) || return 1
        filters=$(tc filter show dev wan egress) || return 1
        test "$forward" = '-P FORWARD ACCEPT' && test -z "$filters"
    }
    tc qdisc add dev wan clsact
    iptables -t mangle -A FORWARD -j CLASSIFY --set-class 1234:1
    if slot_free; then echo 'priority collision accepted' >&2; exit 1; fi
    iptables -t mangle -D FORWARD -j CLASSIFY --set-class 1234:1
    echo preexisting-priority-writer-refused
    slot_free

    iptables -t mangle -N RZQUAL
    iptables -t mangle -A RZQUAL -s 192.168.70.64/26 -j RETURN
    iptables -t mangle -A RZQUAL -m mac --mac-source 02:00:00:00:00:55 -j RETURN
    iptables -t mangle -A RZQUAL -j CLASSIFY --set-class 1234:1
    iptables -t mangle -A FORWARD -i home -o wan $qualifier -j RZQUAL
    match="meta(priority eq 0x12340001) and meta(rt_iif eq $home_iif)"
    match="$match and cmp(u32 at 16 layer network eq 0xc000020c)"
    match="$match and cmp(u8 at 9 layer network eq 6) and cmp(u16 at 2 layer transport eq 443)"
    tc filter add dev wan egress protocol ip pref 200 basic match "$match" action mirred egress redirect dev rzh0
    expect tc-before-snat xray
    iptables -t nat -A POSTROUTING -s 192.168.70.0/24 -o wan -j SNAT --to-source 10.31.1.1

    # The reconstructed reply enters TUN addressed to SNAT, then conntrack
    # reverses the mapping and forwards that reply to the actual LAN client.
    iptables -t mangle -A PREROUTING -i rzh0 -s 192.0.2.12 -d 10.31.1.1 -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED --ctdir REPLY
    iptables -A FORWARD -i rzh0 -o home -s 192.0.2.12 -d 192.168.70.21 -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED --ctdir REPLY
    expect tc-after-snat xray
    for chain in 'mangle PREROUTING' 'filter FORWARD'; do
        set -- $chain
        iptables -t "$1" -nvxL "$2" | awk '/ctdir REPLY/ && $1+0>0 {hit=1} END {exit !hit}'
    done
    echo snat-reply-restored-to-lan
    swap 02:00:00:00:00:55 22; expect tc-excluded-mac wan-snat
    swap 02:00:00:00:00:55 23; expect tc-excluded-mac-new-ip wan-snat
    swap 02:00:00:00:00:88 75; expect tc-excluded-cidr wan-snat
    swap 02:00:00:00:00:33 25; expect tc-new-client xray
    ip rule add pref 95 from 192.168.70.25/32 to 192.0.2.12/32 lookup 102
    expect tc-new-native-unmarked-rule vpn
    ip rule del pref 95 from 192.168.70.25/32 to 192.0.2.12/32 lookup 102
    iptables -t mangle -A POSTROUTING -s 192.168.70.25 -d 192.0.2.12 -o wan -p tcp --dport 443 -j DROP
    if get > "$work/late-deny" 2>/dev/null; then exit 1; fi
    test ! -s "$work/late-deny"
    iptables -t mangle -nvxL POSTROUTING | awk '$3=="DROP" && $1+0>0 {hit=1} END {exit !hit}'
    echo tc-native-postrouting-drop
    iptables -t mangle -D POSTROUTING -s 192.168.70.25 -d 192.0.2.12 -o wan -p tcp --dport 443 -j DROP
    expect tc-restored-allow xray
    iptables -t mangle -D FORWARD -i home -o wan $qualifier -j RZQUAL
    tc qdisc del dev wan clsact
    iptables -t mangle -F RZQUAL
    iptables -t mangle -X RZQUAL
    expect tc-detached wan-snat

    # A second policy may independently choose the same priority after setup.
    # Observe the candidate selector with a pass-only counter on the native
    # WAN path. No tunnel action or positive qualifier is installed here.
    tc qdisc add dev wan clsact
    tc filter add dev wan egress protocol ip pref 200 basic match "$match" action gact pass
    swap 02:00:00:00:00:55 23
    expect excluded-untagged-native wan-snat
    tc -s filter show dev wan egress | awk '/Sent/ && $4==0 {zero=1} END {exit !zero}'
    iptables -t mangle -A FORWARD -i home -o wan -s 192.168.70.23 -j CLASSIFY --set-class 1234:1
    expect excluded-with-foreign-priority-native wan-snat
    tc -s filter show dev wan egress | awk '/Sent/ && $4+0>0 {hit=1} END {exit !hit}'
    echo 'UNSUPPORTED: priority collision matches excluded hardware address'
    iptables -t mangle -D FORWARD -i home -o wan -s 192.168.70.23 -j CLASSIFY --set-class 1234:1
    tc qdisc del dev wan clsact
fi
