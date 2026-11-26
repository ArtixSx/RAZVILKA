#!/bin/sh
# Passive local platform inventory. No network calls, engine launches, service
# changes, module loading, firewall/route operations, or configuration exports.
# Adapted from the supplied RAZVILKA_KEENETIC_CODEX_2026_10_12 materials.
# Source/archive SHA256 and diagnostic limits are recorded in README.md.
# Usage: sh collect-platform-fingerprint.sh [--model KN-xxxx] [--firmware VERSION]
#        [--binary /absolute/path/to/program] ... > platform-fingerprint.txt
# Output redirection is performed by the caller. This script creates no files.

kac_section() {
    KAC_SECTION_KEY=$1
    shift
    printf '@section|%s\n' "$KAC_SECTION_KEY"
    "$@" 2>&1
    KAC_SECTION_RC=$?
    printf '\n@end|%s|%s\n' "$KAC_SECTION_KEY" "$KAC_SECTION_RC"
}

kac_value() { printf '%s\n' "$1" | tr '\t\r\n' '   '; printf '\n'; }

kac_cpu() {
    if [ ! -r /proc/cpuinfo ]; then return 3; fi
    awk 'BEGIN {n=0}
      /^(system type|machine|cpu model|model name|CPU architecture|CPU implementer|CPU part|Features|flags|isa|ASEs implemented|processor)[ \t]*:/ {
        if (n++ < 80) print
      }' /proc/cpuinfo
}

kac_memory() {
    if [ ! -r /proc/meminfo ]; then return 3; fi
    awk '/^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree|Slab|SReclaimable|SUnreclaim):/ {print}' /proc/meminfo
}

kac_status() {
    if [ ! -r /proc/self/status ]; then return 3; fi
    awk '/^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|NoNewPrivs|Seccomp):/ {print}' /proc/self/status
}

kac_mounts() {
    if [ ! -r /proc/mounts ]; then return 3; fi
    # Mount source/device names are deliberately omitted.
    awk '$2=="/" || $2=="/opt" || $2=="/tmp" || $2=="/run" {
      print "mountpoint=" $2, "fstype=" $3, "options=" $4
    }' /proc/mounts
}

kac_space() {
    for KAC_DIR in /opt /tmp; do
        if [ -d "$KAC_DIR" ]; then
            df -Pk "$KAC_DIR" 2>/dev/null | awk -v label="$KAC_DIR" 'NR==2 {
              print "path=" label, "total_kib=" $2, "used_kib=" $3, "available_kib=" $4
            }'
        else
            printf 'path=%s missing\n' "$KAC_DIR"
        fi
    done
}

kac_tools() {
    for KAC_TOOL in sh busybox ip iptables ip6tables iptables-legacy iptables-nft \
        ipset nft conntrack opkg curl wget readelf dd od awk sha256sum timeout flock \
        ndmc xray nfqws2 nfqws wg wireguard-go awg amneziawg-go usque \
        hev-socks5-tunnel sing-box mihomo; do
        KAC_TOOL_PATH=$(command -v "$KAC_TOOL" 2>/dev/null)
        if [ -n "$KAC_TOOL_PATH" ]; then
            printf '%s=%s\n' "$KAC_TOOL" "$KAC_TOOL_PATH"
        else
            printf '%s=NOT_FOUND_IN_CURRENT_PATH\n' "$KAC_TOOL"
        fi
    done
}

kac_feeds() {
    KAC_FEED_SEEN=0
    for KAC_CONF in /opt/etc/opkg.conf /opt/etc/opkg/*.conf; do
        if [ -r "$KAC_CONF" ]; then
            KAC_FEED_SEEN=1
            awk '$1=="src" || $1=="src/gz" {
              if ($3 ~ /^https?:\/\/bin\.entware\.net\//) {
                u=$3; sub(/^https?:\/\/bin\.entware\.net\//,"",u)
                sub(/[?#].*$/, "",u); split(u,a,"/")
                print "official_entware_feed=" a[1]
              } else { print "custom_feed_present=true (URL omitted)" }
            }' "$KAC_CONF"
        fi
    done
    [ "$KAC_FEED_SEEN" -eq 1 ] || return 3
}

kac_kernel_config() {
    if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
        zcat /proc/config.gz 2>/dev/null | awk '
          /^CONFIG_(FUTEX|EPOLL|TUN|NET_NS|NAMESPACES|VETH|IP_MULTIPLE_TABLES|IPV6_MULTIPLE_TABLES|NETFILTER|NF_CONNTRACK|NETFILTER_NETLINK_QUEUE|NETFILTER_XT_TARGET_NFQUEUE|NETFILTER_XT_TARGET_TPROXY|NETFILTER_XT_MATCH_SOCKET|NETFILTER_XT_MATCH_CONNBYTES|NETFILTER_XT_TARGET_CONNMARK|NF_TABLES|NFT_QUEUE|NFT_TPROXY|BPF|BPF_SYSCALL|DEBUG_INFO_BTF|WIREGUARD|BRIDGE_NETFILTER)=/ {print}
          /^# CONFIG_(FUTEX|EPOLL|TUN|NET_NS|NAMESPACES|VETH|IP_MULTIPLE_TABLES|IPV6_MULTIPLE_TABLES|NETFILTER|NF_CONNTRACK|NETFILTER_NETLINK_QUEUE|NETFILTER_XT_TARGET_NFQUEUE|NETFILTER_XT_TARGET_TPROXY|NETFILTER_XT_MATCH_SOCKET|NETFILTER_XT_MATCH_CONNBYTES|NETFILTER_XT_TARGET_CONNMARK|NF_TABLES|NFT_QUEUE|NFT_TPROXY|BPF|BPF_SYSCALL|DEBUG_INFO_BTF|WIREGUARD|BRIDGE_NETFILTER) is not set/ {print}'
    else
        printf 'NOT_EXPOSED: absence of /proc/config.gz does not prove missing support\n'
        return 3
    fi
}

kac_modules() {
    if [ ! -r /proc/modules ]; then return 3; fi
    awk '{print $1}' /proc/modules
}

kac_system_modules() {
    # Firmware may list built-in features here; do not require lsmod entries.
    if [ -f /lib/system-modules ] && [ -r /lib/system-modules ]; then
        awk 'NR<=300 {print}' /lib/system-modules
    elif [ -d /lib/system-modules ]; then
        printf 'directory_present\n'
    else
        printf 'NOT_EXPOSED\n'
        return 3
    fi
}

kac_primitives() {
    if [ -c /dev/net/tun ]; then printf 'tun_device_node=character_device\n'; else printf 'tun_device_node=not_observed\n'; fi
    if [ -d /sys/module/tun ]; then printf 'tun_sys_module=present\n'; fi
    if [ -d /sys/module/wireguard ]; then printf 'wireguard_sys_module=present\n'; fi
    if [ -e /proc/self/ns/net ]; then printf 'net_namespace_entry=present\n'; else printf 'net_namespace_entry=not_observed\n'; fi
    if [ -r /sys/kernel/btf/vmlinux ]; then printf 'kernel_btf_file=readable\n'; else printf 'kernel_btf_file=not_observed\n'; fi
    printf 'note=presence is not a successful ioctl/netns/forwarding test\n'
}

kac_sysctls() {
    for KAC_REL in net/ipv4/ip_forward net/ipv6/conf/all/forwarding \
        net/ipv4/conf/all/rp_filter net/ipv4/conf/default/rp_filter \
        net/ipv4/conf/all/src_valid_mark net/netfilter/nf_conntrack_count \
        net/netfilter/nf_conntrack_max net/core/rmem_max net/core/wmem_max; do
        if [ -r "/proc/sys/$KAC_REL" ]; then
            KAC_VAL=$(cat "/proc/sys/$KAC_REL")
            printf '%s=%s\n' "$KAC_REL" "$KAC_VAL"
        else
            printf '%s=NOT_EXPOSED\n' "$KAC_REL"
        fi
    done
}

# Only portable short od options. Keep dd's exit status independently: POSIX
# pipelines otherwise hide a failed producer behind a successful od. FD 3 is
# a copy of stdout inside this subshell, never a file or a persisted resource.
kac_header() {
    command -v dd >/dev/null 2>&1 || return 3
    command -v od >/dev/null 2>&1 || return 3
    command -v awk >/dev/null 2>&1 || return 3
    KAC_OCTAL=$(
        exec 3>&1
        { dd if="$1" bs=64 count=1 2>/dev/null; printf '@reader_exit|%s\n' "$?" >&3; } |
            od -b -v 2>/dev/null
    ) || return 3
    printf '%s\n' "$KAC_OCTAL" | awk '
      function octal(s, i, n) {
        n=0; for (i=1; i<=length(s); i++) n=n*8+substr(s,i,1); return n
      }
      /^@reader_exit[|][0-9]+$/ {
        split($0,a,"[|]"); if (++seen_reader!=1 || a[2]!=0) bad=1; next
      }
      {
        if (NF<1 || $1 !~ /^[0-7]+$/ || length($1)>8 || seen_footer) {bad=1; next}
        if (octal($1)!=count) {bad=1; next}
        if (NF==1) {seen_footer=1; next}
        if (NF>17) {bad=1; next}
        for (i=2; i<=NF; i++) {
          if (length($i)!=3 || $i !~ /^[0-7]+$/ || octal($i)>255 || count>=64) {bad=1; next}
          bytes=bytes (count ? " " : "") octal($i); count++
        }
      }
      END {if (bad || seen_reader!=1 || !seen_footer) exit 3; print bytes}
    '
}

kac_elf() {
    case "$1" in /*) ;; *) printf 'absolute_path_required\n'; return 2;; esac
    if [ ! -f "$1" ] || [ ! -r "$1" ]; then printf 'not_readable_regular_file\n'; return 3; fi
    printf 'path=%s\n' "$1"
    KAC_ELF_RC=0
    if KAC_DECIMAL=$(kac_header "$1"); then
        printf 'header_decimal_bytes:\n%s\n' "$KAC_DECIMAL"
    else
        printf 'header_status=UNKNOWN_READER_UNAVAILABLE_OR_FAILED\n'
        KAC_ELF_RC=3
    fi
    # Only an explicitly requested --binary may cause a full binary read.
    # The running shell is automatically observed through its <=64-byte header.
    if [ "$2" = hash ]; then
        if command -v sha256sum >/dev/null 2>&1 && KAC_HASH=$(sha256sum "$1" 2>/dev/null); then
            if KAC_DIGEST=$(printf '%s\n' "$KAC_HASH" | awk '
              NR==1 && length($1)==64 && $1 !~ /[^0-9a-f]/ {digest=$1; next}
              {bad=1} END {if (bad || !digest) exit 3; print digest}
            '); then printf 'sha256=%s\n' "$KAC_DIGEST";
            else printf 'sha256=NOT_COLLECTED\n'; fi
        else printf 'sha256=NOT_COLLECTED\n'; fi
    else printf 'sha256=NOT_REQUESTED\n'; fi
    return "$KAC_ELF_RC"
}

printf 'KAFINGERPRINT|1\n'
kac_section collection_mode kac_value PASSIVE_INVENTORY_NOT_FUNCTIONAL_ACCEPTANCE
kac_section collected_at_utc date -u '+%Y-%m-%dT%H:%M:%SZ'
kac_section kernel_os uname -s
kac_section kernel_release uname -r
kac_section uname_machine uname -m
kac_section shell_elf kac_elf "/proc/$$/exe" header-only
kac_section cpuinfo kac_cpu
kac_section memory kac_memory
kac_section collector_credentials kac_status
kac_section mount_metadata kac_mounts
kac_section storage_capacity kac_space
kac_section executable_resolution kac_tools
kac_section opkg_architecture opkg print-architecture
kac_section official_entware_feeds kac_feeds
kac_section ip_version ip -V
kac_section iptables_version iptables --version
kac_section ip6tables_version ip6tables --version
kac_section nft_version nft --version
kac_section curl_features curl --version
kac_section resolved_getconf_libc getconf GNU_LIBC_VERSION
kac_section kernel_config_subset kac_kernel_config
kac_section loaded_module_names kac_modules
kac_section system_modules_metadata kac_system_modules
kac_section primitive_presence kac_primitives
kac_section passive_sysctls kac_sysctls

KAC_BINARY_INDEX=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --model|--firmware)
            KAC_ARG=$1
            shift
            if [ "$#" -eq 0 ]; then printf 'missing value for %s\n' "$KAC_ARG"; exit 2; fi
            case "$KAC_ARG" in
                --model) kac_section declared_model kac_value "$1";;
                --firmware) kac_section declared_firmware kac_value "$1";;
            esac
            ;;
        --binary)
            shift
            if [ "$#" -eq 0 ]; then printf 'missing binary path\n'; exit 2; fi
            KAC_BINARY_INDEX=$((KAC_BINARY_INDEX + 1))
            if [ "$KAC_BINARY_INDEX" -gt 12 ]; then printf 'maximum 12 explicit binaries\n'; exit 2; fi
            kac_section "binary_$KAC_BINARY_INDEX" kac_elf "$1" hash
            ;;
        *) printf 'unknown argument: %s\n' "$1"; exit 2;;
    esac
    shift
done
printf 'KAFINGERPRINT_END|1\n'
exit 0
