package startuptools

import (
	"encoding/base64"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The original owner compares the precise private compiler invocation. This
// independently limits the tool ABI: no shell/helper, batch, flush, private-key
// readback, arbitrary set option or companion-backend mutation is available.
func wgArguments(index int, engine string, args []string) bool {
	if !boundedArguments(args) {
		return false
	}
	if index == 0 || index == 1 {
		if readArguments(args) || effectArguments(index, args) {
			return true
		}
		return len(args) >= 4 && args[0] == "-t" && readArguments([]string{"-t", args[1], "-S"}) && args[2] == "-C"
	}
	if index == 2 {
		return wgIPArguments(args)
	}
	if index != 3 && index != 4 {
		return false
	}
	if len(args) == 3 && args[0] == "show" && (args[1] == "all" && args[2] == "public-key" || wgInterface(args[1]) && slices.Contains([]string{"latest-handshakes", "fwmark", "endpoints", "public-key", "allowed-ips"}, args[2])) {
		return true
	}
	if index == 3 && engine != "wireguard" || index == 4 && engine != "amneziawg" {
		return false
	}
	if len(args) == 3 && args[0] == "setconf" && wgInterface(args[1]) {
		return path.IsAbs(args[2]) && path.Clean(args[2]) == args[2]
	}
	if len(args) == 4 && args[0] == "set" && wgInterface(args[1]) && args[2] == "fwmark" {
		return wgNumber(args[3], 32, true)
	}
	if len(args) == 6 && args[0] == "set" && wgInterface(args[1]) && args[2] == "peer" && args[4] == "endpoint" {
		key, err := base64.StdEncoding.DecodeString(args[3])
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != args[3] {
			return false
		}
		endpoint, err := netip.ParseAddrPort(args[5])
		return err == nil && endpoint.Port() != 0 && !endpoint.Addr().Is4In6() && endpoint.Addr().Zone() == "" && endpoint.Addr().IsGlobalUnicast()
	}
	return false
}

func wgInterface(value string) bool {
	if len(value) == 0 || len(value) > 15 || value[0] == '-' || value == "all" {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return value != "." && value != ".."
}
func wgNumber(value string, bits int, zero bool) bool {
	n, err := strconv.ParseUint(value, 0, bits)
	return err == nil && (zero || n > 0)
}
func wgIPArguments(original []string) bool {
	args := original
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if !slices.Contains([]string{"-4", "-6", "-N", "-details", "-j", "-d", "-o", "-s"}, args[0]) {
			return false
		}
		args = args[1:]
	}
	if len(args) < 2 {
		return false
	}
	if slices.Contains([]string{"link", "addr", "address", "rule", "route"}, args[0]) && (args[1] == "show" || args[0] == "route" && args[1] == "get") {
		for _, value := range args[2:] {
			if strings.HasPrefix(value, "-") {
				return false
			}
		}
		return true
	}
	if args[0] == "route" || args[0] == "rule" {
		return len(args) >= 4 && (args[1] == "add" || args[1] == "del" || args[0] == "route" && args[1] == "replace") && !slices.Contains(args[2:], "flush")
	}
	if args[0] == "link" {
		if len(args) < 4 || args[2] != "dev" || !wgInterface(args[3]) {
			return false
		}
		switch args[1] {
		case "add":
			return len(args) == 6 && args[4] == "type" && (args[5] == "wireguard" || args[5] == "amneziawg")
		case "delete":
			return len(args) == 4
		case "set":
			return len(args) == 5 && args[4] == "up" || len(args) == 6 && args[4] == "mtu" && wgNumber(args[5], 16, false)
		}
	}
	if (args[0] == "address" || args[0] == "addr") && len(args) >= 5 && args[1] == "add" && args[3] == "dev" && wgInterface(args[4]) {
		prefix, err := netip.ParsePrefix(args[2])
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return false
		}
		return len(args) == 5 || len(args) == 6 && args[5] == "noprefixroute" || len(args) == 7 && args[5] == "noprefixroute" && args[6] == "nodad" && prefix.Addr().Is6()
	}
	return false
}
