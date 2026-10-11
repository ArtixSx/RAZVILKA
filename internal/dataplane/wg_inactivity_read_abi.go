package dataplane

import (
	"net/netip"
	"slices"
	"strconv"
)

// This ABI is negative inspection only. It does not reuse the broad effect
// runner vocabulary, accept shell/batch inputs or read private WG keys.
func wgInactivityReadArguments(a *WARPWireGuardAdapter, tools WGCommandTools, name string, original []string) ([]string, bool) {
	if a == nil || name == "" || !validPolicyEffectArgs(original) {
		return nil, false
	}
	args := slices.Clone(original)
	if name == tools.WG || name == tools.AWG {
		return args, slices.Equal(args, []string{"show", "all", "public-key"})
	}
	if name == tools.IPTables || name == tools.IP6Tables {
		return args, len(args) == 3 && args[0] == "-t" && (args[1] == "filter" || args[1] == "nat") && args[2] == "-S"
	}
	if name != tools.IP {
		return nil, false
	}
	if slices.Equal(args, []string{"-j", "link", "show"}) {
		return args, true
	}
	flags := map[string]bool{}
	offset := 0
	for offset < len(args) && len(args[offset]) > 0 && args[offset][0] == '-' {
		flag := args[offset]
		if !slices.Contains([]string{"-N", "-4", "-6", "-j", "-details"}, flag) || flags[flag] {
			return nil, false
		}
		flags[flag] = true
		offset++
	}
	if flags["-4"] && flags["-6"] {
		return nil, false
	}
	body := args[offset:]
	if slices.Equal(body, []string{"rule", "show"}) && !flags["-j"] && !flags["-details"] {
		if !flags["-N"] {
			args = append([]string{"-N"}, args...)
		}
		return args, true
	}
	if len(body) != 4 && len(body) != 6 || len(body) < 4 || !slices.Equal(body[:3], []string{"route", "show", "table"}) {
		return nil, false
	}
	table, err := strconv.Atoi(body[3])
	spec, specErr := a.endpointSpec()
	if err != nil || specErr != nil || strconv.Itoa(table) != body[3] || table != spec.Table && table != spec.EndpointTable && table != 219 {
		return nil, false
	}
	if flags["-details"] && !flags["-j"] {
		return nil, false
	}
	if len(body) == 6 {
		prefix, err := netip.ParsePrefix(body[5])
		if body[4] != "exact" || !flags["-j"] || table != spec.EndpointTable || err != nil || prefix.String() != body[5] || prefix != prefix.Masked() || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().Is4In6() || prefix.Addr().Is6() != flags["-6"] {
			return nil, false
		}
	}
	if !flags["-N"] {
		args = append([]string{"-N"}, args...)
	}
	return args, true
}
