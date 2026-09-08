#!/bin/sh
# RAZVILKA Test Lab preflight. Read-only: it does not alter routing, DNS or firewall.
set -u
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
OUTDIR=/opt/var/log/razvilka
mkdir -p "$OUTDIR" 2>/dev/null || OUTDIR=/tmp
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)"
OUT="$OUTDIR/preflight-$STAMP.txt"
LATEST="$OUTDIR/preflight-latest.txt"

have(){ command -v "$1" >/dev/null 2>&1; }
section(){ printf '\n===== %s =====\n' "$1"; }
run(){ printf '\n$ %s\n' "$*"; "$@" 2>&1 || printf '[exit=%s]\n' "$?"; }
shrun(){ printf '\n$ %s\n' "$1"; sh -c "$1" 2>&1 || printf '[exit=%s]\n' "$?"; }

{
section "RAZVILKA TEST LAB PREFLIGHT"
echo "generated=$(date 2>/dev/null || true)"
echo "safe_mode=read-only"

section "IDENTITY"
run uname -a
run uname -m
[ -r /etc/os-release ] && run cat /etc/os-release

section "ENTWARE / OPT"
if [ -d /opt ]; then echo "/opt=present"; else echo "/opt=MISSING"; fi
shrun "mount | grep -E '(/opt|/tmp/mnt|storage)' || mount"
run df -h /opt
if have opkg; then
  run opkg --version
  run opkg print-architecture
  shrun "opkg list-installed | sed -n '1,120p'"
else
  echo "opkg=MISSING"
fi
[ -x /opt/etc/init.d/rc.unslung ] && echo "rc.unslung=present" || echo "rc.unslung=MISSING"

section "CPU / MEMORY"
shrun "sed -n '1,100p' /proc/cpuinfo"
shrun "sed -n '1,40p' /proc/meminfo"

section "NETWORK INTERFACES"
if have ip; then
  run ip link show
  run ip -4 -o addr show
  run ip -6 -o addr show
  run ip route show
  run ip -6 route show
  run ip rule show
  shrun "ip route get 1.1.1.1"
else
  echo "ip=MISSING"
  have ifconfig && run ifconfig -a
  have route && run route -n
fi

section "DNS"
[ -r /etc/resolv.conf ] && run cat /etc/resolv.conf
[ -r /opt/etc/resolv.conf ] && run cat /opt/etc/resolv.conf

section "TUN / NETFILTER CAPABILITIES"
[ -c /dev/net/tun ] && echo "/dev/net/tun=present" || echo "/dev/net/tun=MISSING"
if have lsmod; then
  shrun "lsmod | grep -Ei 'tun|nfqueue|nfnetlink|tproxy|xt_|iptable|nft' || true"
fi
for c in iptables ip6tables nft; do
  if have "$c"; then echo "$c=$(command -v "$c")"; else echo "$c=MISSING"; fi
done
[ -r /proc/net/ip_tables_names ] && run cat /proc/net/ip_tables_names

section "LISTENING PORTS"
if have ss; then run ss -lntu; elif have netstat; then run netstat -lntu; else echo "ss/netstat=MISSING"; fi

section "ENGINE PRESENCE"
for c in nfqws nfqws2 usque sing-box xray awg awg-quick wg warp-cli byedpi ciadpi; do
  if have "$c"; then printf '%-12s %s\n' "$c" "$(command -v "$c")"; else printf '%-12s %s\n' "$c" "not-found"; fi
done
for p in /opt/etc/nfqws2 /opt/etc/usque /opt/etc/sing-box /opt/etc/xray /opt/etc/wireguard /opt/etc/amneziawg; do
  [ -e "$p" ] && echo "path-present=$p" || true
done

section "ENGINE PACKAGES / CONTROL FILES"
if have opkg; then
  shrun "opkg list-installed | grep -Ei 'nfqws|usque|sing-box|xray|amnezia|wireguard|mihomo' || true"
fi
for p in /opt/etc/init.d/S51nfqws2 /opt/etc/init.d/S51usque /opt/etc/nfqws2/nfqws2.conf /opt/etc/nfqws2/lists/user.list /opt/etc/usque/usque.conf /opt/etc/sing-box/config.json /opt/etc/xray/config.json; do
  if [ -e "$p" ]; then
    shrun "ls -l '$p'"
  else
    echo "missing=$p"
  fi
done

section "PROCESS SNAPSHOT"
shrun "ps w 2>/dev/null || ps"

section "RAZVILKA"
if have razvilka; then
  echo "binary=$(command -v razvilka)"
else
  echo "binary=not-installed"
fi
[ -f /opt/etc/razvilka/config.json ] && run cat /opt/etc/razvilka/config.json

section "EXTERNAL ROUTING CONTAMINATION"
TUNNEL_DEVS=""
if have ip; then
  TUNNEL_DEVS="$(ip route show 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev" && (($(i+1) ~ /^nwg[0-9]*$/) || ($(i+1) ~ /^wg[0-9]*$/) || ($(i+1) ~ /^tun[0-9]*$/) || ($(i+1) ~ /^tap[0-9]*$/) || ($(i+1) ~ /^opkgtun[0-9]*$/) || ($(i+1) ~ /^awg[0-9]*$/))) print $(i+1)}' | sort -u | tr '\n' ',' | sed 's/,$//')"
fi
if [ -n "$TUNNEL_DEVS" ]; then
  echo "external_tunnel_state=detected:$TUNNEL_DEVS"
  echo "route_test_contamination=possible"
else
  echo "external_tunnel_state=none-detected"
  echo "route_test_contamination=none-detected"
fi

section "SAFETY SUMMARY"
WAN_DEV=""
if have ip; then WAN_DEV="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"; fi
[ -n "$WAN_DEV" ] && echo "detected_wan=$WAN_DEV" || echo "detected_wan=unknown"
[ -n "$WAN_DEV" ] && echo "wan_route_detected=yes" || echo "wan_route_detected=no"
[ -c /dev/net/tun ] && echo "tun_ready=yes" || echo "tun_ready=no"
if have opkg && [ -x /opt/etc/init.d/rc.unslung ]; then echo "entware_ready=yes"; else echo "entware_ready=no"; fi
if have nfqws || have nfqws2 || have usque || have sing-box || have xray; then echo "clean_engine_state=no"; else echo "clean_engine_state=yes"; fi
} > "$OUT"

cp "$OUT" "$LATEST" 2>/dev/null || true
cat "$OUT"
printf '\nREPORT=%s\n' "$OUT"
