package startuptools

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Separate read-only ABI. No effect word, batch file, shell, namespace switch
// or external hostname can pass this projection of the original held tools.
func mihomoLiveReadArguments(index int, args []string) bool {
	if !boundedArguments(args) {
		return false
	}
	if index == 0 || index == 1 {
		return len(args) == 3 && args[0] == "-t" && slices.Contains([]string{"nat", "mangle", "filter", "raw"}, args[1]) && args[2] == "-S"
	}
	if index != 2 {
		return false
	}
	flags := map[string]bool{}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		flag := args[0]
		if !slices.Contains([]string{"-4", "-6", "-j", "-N", "-details", "-o"}, flag) || flags[flag] {
			return false
		}
		flags[flag] = true
		args = args[1:]
	}
	if flags["-4"] && flags["-6"] || len(args) < 2 {
		return false
	}
	device := func(raw string) bool {
		if raw == "" || len(raw) > 15 {
			return false
		}
		for _, c := range raw {
			if c < 'a' || c > 'z' {
				if c < 'A' || c > 'Z' {
					if c < '0' || c > '9' {
						if c != '_' && c != '.' && c != '-' {
							return false
						}
					}
				}
			}
		}
		return true
	}
	address := func(raw string) bool {
		a, err := netip.ParseAddr(raw)
		return err == nil && a.String() == raw && !a.Is4In6() && !a.IsUnspecified() && !a.IsMulticast()
	}
	prefix := func(raw string) bool {
		p, err := netip.ParsePrefix(raw)
		return err == nil && p.String() == raw && p == p.Masked() && !p.Addr().Is4In6()
	}
	switch args[0] {
	case "link", "addr", "address":
		return args[1] == "show" && (len(args) == 2 || len(args) == 4 && args[2] == "dev" && device(args[3]))
	case "rule":
		return len(args) == 2 && args[1] == "show"
	case "route":
		switch args[1] {
		case "get":
			if len(args) < 3 || !address(args[2]) {
				return false
			}
			args = args[3:]
			seen := map[string]bool{}
			for len(args) > 0 {
				if len(args) < 2 || seen[args[0]] {
					return false
				}
				seen[args[0]] = true
				switch args[0] {
				case "from":
					if !address(args[1]) {
						return false
					}
				case "iif", "oif":
					if !device(args[1]) {
						return false
					}
				case "mark":
					n, e := strconv.ParseUint(strings.TrimPrefix(args[1], "0x"), 16, 32)
					if e != nil || n == 0 {
						return false
					}
				default:
					return false
				}
				args = args[2:]
			}
			return true
		case "show":
			args = args[2:]
			// Original forwarding compilation observes only the main table's
			// defaults. This literal selector is read-only, not a free-form ABI.
			if slices.Equal(args, []string{"table", "main", "default"}) {
				return true
			}
			seen := map[string]bool{}
			for len(args) > 0 {
				if len(args) < 2 || seen[args[0]] {
					return false
				}
				seen[args[0]] = true
				switch args[0] {
				case "table":
					if !slices.Contains([]string{"all", "main", "local"}, args[1]) {
						n, e := strconv.Atoi(args[1])
						if e != nil || n < 1 || n > 32767 || strconv.Itoa(n) != args[1] {
							return false
						}
					}
				case "match", "exact":
					if !prefix(args[1]) {
						return false
					}
				case "dev":
					if !device(args[1]) {
						return false
					}
				default:
					return false
				}
				args = args[2:]
			}
			return true
		}
	}
	return false
}
func (r *policyRunner) RunMihomoLiveRead(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil {
		return nil, at("POLICY_UNISSUED", nil)
	}
	return r.lease.runMihomoLiveRead(ctx, name, args...)
}
