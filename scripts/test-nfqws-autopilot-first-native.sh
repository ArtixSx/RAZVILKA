#!/bin/sh
set -eu

# Run only inside a disposable no-NIC Linux guest with real classic iptables,
# backend queue visibility and the tagged native tool classifier available.
: "${RAZVILKA_NFQ_AUTOPILOT_TEST:?provide the tagged Linux cmd/razvilka test ELF}"
: "${RAZVILKA_NFQWS_INITIAL_IPK:?provide the exact upstream NFQWS2 1.3.1 IPK}"
: "${RAZVILKA_NFQ_AUTOPILOT_ENTWARE:?provide the verified tool tree containing opt/}"
for path in "$RAZVILKA_NFQ_AUTOPILOT_TEST" "$RAZVILKA_NFQWS_INITIAL_IPK" "$RAZVILKA_NFQ_AUTOPILOT_ENTWARE"; do
    case "$path" in /*) ;; *) exit 2 ;; esac
done
test "$(id -u)" = 0 && test "$(ls /sys/class/net)" = lo
test -d /opt && test -r /proc/net/netfilter/nfnetlink_queue
test -x "$RAZVILKA_NFQ_AUTOPILOT_ENTWARE/opt/bin/opkg"
test -x "$RAZVILKA_NFQ_AUTOPILOT_ENTWARE/opt/bin/busybox"
printf "49f3d1e047483dc068fcc8985d64dcd28d0041044434de2cb3ccd616f2fc0b10  %s\n" \
    "$RAZVILKA_NFQ_AUTOPILOT_ENTWARE/opt/bin/opkg" | sha256sum -c -
work=$(mktemp -d /tmp/razvilka-nfq-autopilot.XXXXXX)
case "$work" in /tmp/razvilka-nfq-autopilot.??????) ;; *) exit 2 ;; esac
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work" GOMAXPROCS=2
export RAZVILKA_NFQ_AUTOPILOT_NATIVE=1 RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD=3
export RAZVILKA_RUNTIME_NATIVE_REVIEW="$work/runtime-native-tool-review.json"
xt_hash=$(sha256sum /usr/sbin/xtables-legacy-multi | cut -d' ' -f1)
ip_hash=$(sha256sum /usr/bin/ip | cut -d' ' -f1)
xt_version=$(/usr/sbin/iptables-legacy --version | sed 's/^iptables v//')
ip_version=$(/usr/bin/ip -Version)
printf '{"XTablesSHA256":"%s","IPToolSHA256":"%s","Version":"%s","IPVersion":"%s\\n"}\n' \
    "$xt_hash" "$ip_hash" "$xt_version" "$ip_version" > "$RAZVILKA_RUNTIME_NATIVE_REVIEW"
chmod 600 "$RAZVILKA_RUNTIME_NATIVE_REVIEW"
exec 3</proc/self/ns/net 4</proc/self/ns/mnt
unshare --mount --net --fork sh -eu -c '
    mount --make-rprivate /
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /opt
    cp -a "$RAZVILKA_NFQ_AUTOPILOT_ENTWARE/opt/." /opt/
    install -m 500 "$RAZVILKA_NFQ_AUTOPILOT_TEST" /opt/bin/razvilka
    mkdir -p /opt/etc/init.d /opt/usr/bin /opt/var/run /opt/var/log /opt/tmp /opt/lib/opkg/info
    ln -s busybox /opt/bin/route
    ln -s /usr/bin/ip /opt/bin/ip
    ln -s /usr/sbin/iptables-legacy /opt/bin/iptables
    ln -s /usr/sbin/ip6tables-legacy /opt/bin/ip6tables
    # Entware archives and real host tools are already present. The two
    # dependency records seed only this disposable database; no feed is used.
    printf "dest root /\nlists_dir ext /opt/var/opkg-lists\narch all 1\narch x86_64 10\narch x64-3.2 20\n" > /opt/etc/opkg.conf
    printf "Package: iptables\nVersion: 1.8.10-3\nArchitecture: all\nStatus: install user installed\n\nPackage: busybox\nVersion: 1.38.0-5\nArchitecture: x64-3.2\nStatus: install ok installed\n" > /opt/lib/opkg/status
    touch /opt/lib/opkg/info/iptables.list /opt/lib/opkg/info/busybox.list
    export PATH=/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
    /opt/bin/opkg --version
    /usr/sbin/ip link add eth3 type veth peer name nfq-lab-peer
    /usr/sbin/ip link set eth3 addrgenmode none
    /usr/sbin/ip link set nfq-lab-peer addrgenmode none
    /usr/sbin/ip addr add 198.18.15.2/24 dev eth3
    /usr/sbin/ip link set eth3 up
    /usr/sbin/ip link set nfq-lab-peer up
    /usr/sbin/ip link set lo up
    /usr/sbin/ip route add default via 198.18.15.1 dev eth3
    printf "nameserver 198.18.15.1\n" > "$TMPDIR/resolv.conf"
    mount --bind "$TMPDIR/resolv.conf" /etc/resolv.conf
    /opt/bin/route -n
    for table in raw mangle nat filter; do
        /usr/sbin/iptables-legacy -t "$table" -S > /dev/null
        /usr/sbin/ip6tables-legacy -t "$table" -S > /dev/null
    done
    grep -x NFQUEUE /proc/net/ip_tables_targets
    capture() {
        /usr/sbin/iptables-legacy-save | sed -E "/^#/d; s/\[[0-9]+:[0-9]+\]$/[0:0]/"
        /usr/sbin/ip6tables-legacy-save | sed -E "/^#/d; s/\[[0-9]+:[0-9]+\]$/[0:0]/"
        /usr/sbin/ip -o link show
        /usr/sbin/ip route show table all
        /usr/sbin/ip rule show
        sha256sum /etc/resolv.conf
        cat /proc/net/netfilter/nfnetlink_queue
    }
    test -z "$(cat /proc/net/netfilter/nfnetlink_queue)"
    capture > "$TMPDIR/network.before"
    result=0
    /opt/bin/razvilka -test.run="^TestNFQWSAutoInitialNativeStockScopeRefusal$" -test.count=1 -test.v -test.timeout=170s || result=$?
    capture > "$TMPDIR/network.after"
    diff -u "$TMPDIR/network.before" "$TMPDIR/network.after" || result=1
    test -z "$(cat /proc/net/netfilter/nfnetlink_queue)" || result=1
    for proc in /proc/[0-9]*/comm; do
        read -r name < "$proc" || continue
        case "$name" in nfqws|nfqws2|opkg|razvilka) printf "remaining process %s %s\n" "$proc" "$name"; result=1 ;; esac
    done
    if test "$result" != 0; then
        for journal in "$TMPDIR"/*.autonomy.json /opt/razvilka/state/components/update-journal/*/install.output; do
            if test -f "$journal"; then tail -c 8192 "$journal"; fi
        done
    fi
    printf "post-run routes, DNS configuration, classic netfilter, and NFQUEUE checked; result=%s\n" "$result"
    exit "$result"
'
