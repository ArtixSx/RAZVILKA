package dataplane

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Only the selected-TCP compiler's closed NAT vocabulary is canonicalized.
// Kernel -S may insert the tcp module, print host prefixes without /32 and
// normalize MAC case. Unknown syntax never receives a comparable key.
func xraySelectedTCPNATRuleKey(row BackendInventoryRow) (string, error) {
	if row.Family != 4 || row.Table != "nat" || len(row.Tokens) < 2 || len(row.Tokens) > 32 {
		return "", ErrNetworkPolicyConsumers
	}
	tokens := row.Tokens
	chain := func(s string) bool {
		if len(s) != 24 || !strings.HasPrefix(s, "RZX_") {
			return false
		}
		for _, c := range s[4:] {
			if c < '0' || c > '9' {
				if c < 'a' || c > 'f' {
					return false
				}
			}
		}
		return true
	}
	if tokens[0] == "-N" {
		if len(tokens) != 2 || !chain(tokens[1]) {
			return "", ErrNetworkPolicyConsumers
		}
		return "nat4\x00-N\x00" + tokens[1], nil
	}
	if tokens[0] != "-A" || tokens[1] != "PREROUTING" && !chain(tokens[1]) {
		return "", ErrNetworkPolicyConsumers
	}
	values := make(map[string]string)
	modules := make(map[string]bool)
	for i := 2; i < len(tokens); i += 2 {
		if i+1 >= len(tokens) || len(tokens[i+1]) == 0 || len(tokens[i+1]) > 256 || strings.ContainsAny(tokens[i+1], "\x00\r\n") {
			return "", ErrNetworkPolicyConsumers
		}
		name, value := tokens[i], tokens[i+1]
		if name == "-m" {
			if value != "tcp" && value != "mac" || modules[value] {
				return "", ErrNetworkPolicyConsumers
			}
			modules[value] = true
			continue
		}
		if _, duplicate := values[name]; duplicate {
			return "", ErrNetworkPolicyConsumers
		}
		switch name {
		case "-i":
			if len(value) > 15 || strings.ContainsAny(value, " /:\\\t+!") {
				return "", ErrNetworkPolicyConsumers
			}
		case "-s", "-d":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, parseErr := netip.ParseAddr(value)
				if parseErr != nil || !address.Is4() {
					return "", ErrNetworkPolicyConsumers
				}
				prefix = netip.PrefixFrom(address, 32)
			}
			if !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return "", ErrNetworkPolicyConsumers
			}
			value = prefix.String()
		case "-p":
			if value != "tcp" {
				return "", ErrNetworkPolicyConsumers
			}
		case "--mac-source":
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 {
				return "", ErrNetworkPolicyConsumers
			}
			value = mac.String()
		case "--dport":
			parts := strings.Split(value, ":")
			if len(parts) > 2 {
				return "", ErrNetworkPolicyConsumers
			}
			first, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil || first == 0 {
				return "", ErrNetworkPolicyConsumers
			}
			last := first
			if len(parts) == 2 {
				last, err = strconv.ParseUint(parts[1], 10, 16)
				if err != nil || last < first {
					return "", ErrNetworkPolicyConsumers
				}
			}
			value = strconv.FormatUint(first, 10)
			if first != last {
				value += ":" + strconv.FormatUint(last, 10)
			}
		case "--to-ports":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port < 1024 {
				return "", ErrNetworkPolicyConsumers
			}
			value = strconv.FormatUint(port, 10)
		case "-j":
			if value != "RETURN" && value != "REDIRECT" && !chain(value) {
				return "", ErrNetworkPolicyConsumers
			}
		default:
			return "", ErrNetworkPolicyConsumers
		}
		values[name] = value
	}
	if values["-j"] == "" || modules["tcp"] && values["-p"] != "tcp" || (values["--mac-source"] != "") != modules["mac"] ||
		values["--dport"] != "" && values["-p"] != "tcp" || (values["--to-ports"] != "") != (values["-j"] == "REDIRECT") {
		return "", ErrNetworkPolicyConsumers
	}
	key := []string{"nat4", "-A", tokens[1]}
	for _, name := range []string{"-i", "-s", "-d", "-p", "--mac-source", "--dport", "-j", "--to-ports"} {
		key = append(key, values[name])
	}
	data, err := json.Marshal(key)
	return string(data), err
}
