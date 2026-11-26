#!/bin/sh
# SPDX-License-Identifier: MIT
# A four-packet loopback experiment. No namespace has an external link.
set -eu
if [ "${1:-}" != --private ]; then
    : "${RAZVILKA_QUEUE_SOURCE:?compiled queue source required}"
    case "$RAZVILKA_QUEUE_SOURCE" in /*) test -x "$RAZVILKA_QUEUE_SOURCE";; *) exit 2;; esac
    exec 8</proc/self/ns/net
    exec timeout -k 3 20 unshare --net --pid --fork --kill-child --mount-proc --propagation private sh "$0" --private
fi
test "$$" = 1
test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/self/fd/8)"
test "$(ls /sys/class/net)" = lo
ip link set lo up
work=$(mktemp -d /tmp/rz-queue-capacity.XXXXXX)
listener=""
cleanup() {
    rc=$?
    trap - EXIT
    if test -n "$listener"; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" || rc=1
    fi
    rm -rf -- "$work"
    exit "$rc"
}
trap cleanup EXIT
nft -f - <<'EOF'
table ip capacity {
    chain select_packet {
        type filter hook output priority 0;
        oifname "lo" ip daddr 127.0.0.2 icmp type echo-request counter queue num 17747
    }
    chain observe {
        type filter hook input priority 0;
        iifname "lo" ip daddr 127.0.0.2 icmp type echo-request counter
    }
}
EOF
packets() { nft list chain ip capacity "$1" | awk '/counter packets/ {for(i=1;i<=NF;i++) if($i=="packets") print $(i+1)}'; }
if ping -n -c 1 -W 1 127.0.0.2 > "$work/no-listener"; then exit 1; fi
test "$(packets select_packet)" -eq 1 && test "$(packets observe)" -eq 0
echo without-listener=one-dropped
"$RAZVILKA_QUEUE_SOURCE" --hold-one > "$work/listener" 2>&1 & listener=$!
for tick in $(seq 1 40); do grep -q '^nfqueue-ready$' "$work/listener" && break; sleep .1; done
grep -q '^nfqueue-ready$' "$work/listener"
if ping -n -c 4 -i .1 -W 1 127.0.0.2 > "$work/full"; then exit 1; fi
awk '$1==17747 {if($3==1 && $6==3 && $7==0) print "capacity=1 held=1 dropped=3"}' /proc/net/netfilter/nfnetlink_queue > "$work/result"
grep -x 'capacity=1 held=1 dropped=3' "$work/result"
test "$(packets select_packet)" -eq 5 && test "$(packets observe)" -eq 0
kill "$listener"; wait "$listener"; listener=""
if awk '$1==17747 {found=1} END {exit !found}' /proc/net/netfilter/nfnetlink_queue; then exit 1; fi
# The queue selector is still installed when its listener exits with one packet held.
if ping -n -c 1 -W 1 127.0.0.2 > "$work/closed"; then exit 1; fi
test "$(packets select_packet)" -eq 6 && test "$(packets observe)" -eq 0
nft flush chain ip capacity select_packet
ping -n -c 1 -W 1 127.0.0.2 > "$work/restored"
test "$(packets observe)" -eq 1
echo closed-listener=zero-delivered detached=one-delivered
nft delete table ip capacity
