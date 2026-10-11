package dataplane

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

var ErrXraySelectedTCPConntrackPending = errors.New("original selected TCP redirect conntrack settlement is pending")

// Read-only whole-table comparison. No tuple becomes a delete permission or
// an accepted-flow owner. A possibly selected old REDIRECT keeps Stop pending.
func xraySelectedTCPConntrackSettled(data []byte, legacy bool, spec XraySelectedTCPRedirectSpec) error {
	if spec.LAN == nil || len(spec.LAN.Ingress) != 1 || len(spec.Destinations) == 0 || len(spec.Ports) == 0 || !spec.Listener.IsValid() {
		return errXraySelectedTCPRuntime
	}
	if len(data) > 32<<20 || len(data) != 0 && data[len(data)-1] != '\n' || strings.ContainsAny(string(data), "\x00\r") {
		return errXraySelectedTCPRuntime
	}
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 262144 {
		return errXraySelectedTCPRuntime
	}
	pending := false
	for _, line := range lines {
		if len(line) == 0 || len(line) > 4096 {
			return errXraySelectedTCPRuntime
		}
		f := strings.Fields(line)
		family4 := legacy
		if !legacy {
			if len(f) < 4 || f[0] != "ipv4" && f[0] != "ipv6" || f[0] == "ipv4" && f[1] != "2" || f[0] == "ipv6" && f[1] != "10" {
				return errXraySelectedTCPRuntime
			}
			family4 = f[0] == "ipv4"
			f = f[2:]
		}
		if len(f) < 3 {
			return errXraySelectedTCPRuntime
		}
		protocols := map[string]string{"tcp": "6", "udp": "17", "udplite": "136", "icmp": "1", "icmpv6": "58", "sctp": "132", "dccp": "33", "gre": "47", "esp": "50", "ah": "51"}
		if protocols[f[0]] != f[1] || protocols[f[0]] == "" {
			return errXraySelectedTCPRuntime
		}
		if _, err := strconv.ParseUint(f[2], 10, 64); err != nil || !xraySelectedTCPDigits(f[2], false) {
			return errXraySelectedTCPRuntime
		}
		tcp := f[0] == "tcp"
		f = f[3:]
		if tcp {
			if len(f) == 0 || !strings.Contains("|NONE|SYN_SENT|SYN_RECV|ESTABLISHED|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE|LISTEN|", "|"+f[0]+"|") {
				return errXraySelectedTCPRuntime
			}
			f = f[1:]
		}
		addresses := map[string][]netip.Addr{}
		ports := map[string][]uint16{}
		counts := map[string]int{}
		for _, token := range f {
			if strings.HasPrefix(token, "[") {
				if token != "[UNREPLIED]" && token != "[ASSURED]" && token != "[OFFLOAD]" && token != "[HW_OFFLOAD]" || counts[token] != 0 {
					return errXraySelectedTCPRuntime
				}
				counts[token]++
				continue
			}
			key, value, ok := strings.Cut(token, "=")
			if !ok || value == "" {
				return errXraySelectedTCPRuntime
			}
			counts[key]++
			switch key {
			case "src", "dst":
				address, err := netip.ParseAddr(value)
				if err != nil || counts[key] > 2 || address.Is4() != family4 {
					return errXraySelectedTCPRuntime
				}
				addresses[key] = append(addresses[key], address)
			case "sport", "dport":
				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil || counts[key] > 2 || !xraySelectedTCPDigits(value, false) {
					return errXraySelectedTCPRuntime
				}
				ports[key] = append(ports[key], uint16(port))
			case "packets", "bytes", "type", "code", "id", "mark", "use", "zone", "timeout", "status":
				maximum := 1
				if key == "packets" || key == "bytes" || key == "type" || key == "code" || key == "id" {
					maximum = 2 // Actual original/reply tuple counters or fields.
				}
				if counts[key] > maximum || !xraySelectedTCPDigits(value, false) {
					return errXraySelectedTCPRuntime
				}
				if _, err := strconv.ParseUint(value, 10, 64); err != nil {
					return errXraySelectedTCPRuntime
				}
			default:
				return errXraySelectedTCPRuntime
			}
		}
		if len(addresses["src"]) != 2 || len(addresses["dst"]) != 2 || tcp && (len(ports["sport"]) != 2 || len(ports["dport"]) != 2) {
			return errXraySelectedTCPRuntime
		}
		if !tcp || !addresses["src"][0].Is4() || addresses["src"][1] != spec.Listener.Addr() || ports["sport"][1] != spec.Listener.Port() {
			continue
		}
		selectedSource, selectedDestination, selectedPort := false, false, false
		for _, raw := range spec.LAN.Ingress[0].Sources {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return errXraySelectedTCPRuntime
			}
			selectedSource = selectedSource || prefix.Contains(addresses["src"][0])
		}
		for _, raw := range spec.Destinations {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return errXraySelectedTCPRuntime
			}
			selectedDestination = selectedDestination || prefix.Contains(addresses["dst"][0])
		}
		for _, span := range spec.Ports {
			selectedPort = selectedPort || ports["dport"][0] >= span.First && ports["dport"][0] <= span.Last
		}
		pending = pending || selectedSource && selectedDestination && selectedPort
	}
	if pending {
		return ErrXraySelectedTCPConntrackPending
	}
	return nil
}
