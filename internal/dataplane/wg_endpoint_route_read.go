package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var errWGEndpointRouteRead = errors.New("WireGuard endpoint route observation is unsupported or ambiguous")

// Only an exact iproute2 option diagnostic permits format negotiation. A
// malformed successful response, permission failure or lost owner never does.
func wgEndpointUnknownOption(data []byte, option string) bool {
	return len(data) < 256 && strings.TrimSpace(string(data)) == fmt.Sprintf("Option %q is unknown, try \"ip -help\".", option)
}

// Route queries retain the original adapter and command owner on every attempt.
func (a *WARPWireGuardAdapter) readWGEndpointRoutes(ctx context.Context, original ...string) ([]wgEndpointRoute, error) {
	family, get, valid := a.wgEndpointRouteReadShape(original)
	if !valid {
		return nil, errWGEndpointRouteRead
	}
	args := slices.Clone(original)
	confirmingAbsent := false
	for attempt := 0; attempt < 4; attempt++ {
		data, err := a.run(ctx, a.ip(), args...)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(data) > 64<<10 {
			return nil, errWGEndpointRouteRead
		}
		if err == nil {
			if slices.Contains(args, "-j") {
				return parseWGEndpointRoutes(data)
			}
			if !wgEndpointTextNamesUnaliased() {
				return nil, errWGEndpointRouteRead
			}
			return parseWGEndpointTextRoutes(data, family, get)
		}
		if slices.Contains(args, "-N") && wgEndpointUnknownOption(data, "-N") {
			args = slices.DeleteFunc(args, func(v string) bool { return v == "-N" })
			continue
		}
		if _, numeric := a.Runner.(numericPolicyReadRunner); numeric && slices.Contains(args, "-j") && wgEndpointUnknownOption(data, "-N") {
			// The existing numeric wrapper added -N. Its guarded plain text
			// retry supports this exact read after JSON is removed.
			args = slices.DeleteFunc(args, func(v string) bool { return v == "-j" })
			continue
		}
		if slices.Contains(args, "-j") && wgEndpointUnknownOption(data, "-j") {
			args = slices.DeleteFunc(args, func(v string) bool { return v == "-j" })
			continue
		}
		// A missing table is absence only after a separate exact text read
		// confirms emptiness. Never turn an arbitrary error into an empty FIB.
		absent := fmt.Sprintf("Error: ipv%d: FIB table does not exist.", family)
		message := strings.TrimSpace(string(data))
		if slices.Contains(args, "-j") {
			// iproute2 may write an empty JSON array before or after its
			// missing-table diagnostic. This permits only independent text
			// confirmation, never an absence grant from the JSON error alone.
			if first, rest, ok := strings.Cut(message, "\n"); ok && strings.TrimSpace(first) == "[]" {
				message = strings.TrimSpace(rest)
			} else if last := strings.LastIndex(message, "\n"); last >= 0 && strings.TrimSpace(message[last+1:]) == "[]" {
				message = strings.TrimSpace(message[:last])
			}
		}
		if !get && (message == absent || message == absent+"\nDump terminated") {
			if confirmingAbsent && !slices.Contains(args, "-j") {
				return []wgEndpointRoute{}, nil
			}
			confirmingAbsent = true
			args = slices.DeleteFunc(args, func(v string) bool { return v == "-j" })
			continue
		}
		return nil, err
	}
	return nil, errWGEndpointRouteRead
}

// No generic route, service-table or mutation vocabulary enters this fallback.
func (a *WARPWireGuardAdapter) wgEndpointRouteReadShape(args []string) (family int, get, valid bool) {
	family = 4
	flags := map[string]bool{}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		flag := args[0]
		if !slices.Contains([]string{"-N", "-j", "-4", "-6"}, flag) || flags[flag] {
			return family, false, false
		}
		flags[flag], args = true, args[1:]
	}
	if flags["-4"] && flags["-6"] {
		return family, false, false
	}
	if flags["-6"] {
		family = 6
	}
	if len(args) == 5 && slices.Equal(args[:2], []string{"route", "get"}) && args[3] == "mark" && args[4] == "0" {
		address, err := netip.ParseAddr(args[2])
		return family, true, err == nil && address.String() == args[2] && publicfetch.PublicAddress(address) && address.Zone() == "" && !address.Is4In6() && address.Is4() == (family == 4)
	}
	if len(args) != 4 && len(args) != 6 || len(args) < 4 || !slices.Equal(args[:3], []string{"route", "show", "table"}) {
		return family, false, false
	}
	table, parseErr := strconv.Atoi(args[3])
	known := false
	for _, spec := range PolicyOwnershipSpecs() {
		known = known || spec.EndpointMark != 0 && (table == spec.Table || table == spec.EndpointTable)
	}
	// Legacy retirement can inspect another WG adapter's recorded endpoint.
	// Coordinates bound the read ABI only; the caller's exact receipt still
	// establishes presence/deletion authority through wgEndpointRouteMatches.
	if parseErr != nil || strconv.Itoa(table) != args[3] || !known {
		return family, false, false
	}
	if len(args) == 6 {
		prefix, err := netip.ParsePrefix(args[5])
		if args[4] != "exact" || err != nil || prefix.String() != args[5] || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr().Is4() != (family == 4) {
			return family, false, false
		}
	}
	return family, false, true
}

// iproute2 4.4 elides unicast/global but prints static protocol and onlink.
// Support one route plus only its bare cache continuation from route-get.
// Unknown metrics, nexthops, source policies or extra records fail closed.
func parseWGEndpointTextRoutes(data []byte, family int, get bool) ([]wgEndpointRoute, error) {
	if len(data) > 64<<10 || family != 4 && family != 6 {
		return nil, errWGEndpointRouteRead
	}
	for _, c := range data {
		if c < 32 && c != '\n' && c != '\t' || c >= 127 {
			return nil, errWGEndpointRouteRead
		}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" && !get {
		return []wgEndpointRoute{}, nil
	}
	if len(lines) == 2 && get && strings.TrimSpace(lines[1]) == "cache" && len(lines[1]) > 0 && (lines[1][0] == ' ' || lines[1][0] == '\t') {
		lines = lines[:1]
	}
	if len(lines) != 1 {
		return nil, errWGEndpointRouteRead
	}
	fields := strings.Fields(lines[0])
	if len(fields) > 0 && fields[0] == "unicast" {
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return nil, errWGEndpointRouteRead
	}
	address, err := netip.ParseAddr(fields[0])
	if err != nil {
		prefix, parseErr := netip.ParsePrefix(fields[0])
		if parseErr != nil || prefix != prefix.Masked() {
			return nil, errWGEndpointRouteRead
		}
		address = prefix.Addr()
	}
	if address.Is4In6() || address.Zone() != "" || address.Is4() != (family == 4) {
		return nil, errWGEndpointRouteRead
	}
	r := wgEndpointRoute{Destination: fields[0], Type: "unicast"}
	seen := map[string]bool{}
	for i := 1; i < len(fields); i++ {
		key := fields[i]
		if seen[key] {
			return nil, errWGEndpointRouteRead
		}
		seen[key] = true
		if key == "onlink" {
			r.Flags = []string{"onlink"}
			continue
		}
		if i+1 >= len(fields) {
			return nil, errWGEndpointRouteRead
		}
		i++
		value := fields[i]
		switch key {
		case "via", "src":
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.Is4() != (family == 4) {
				return nil, errWGEndpointRouteRead
			}
			if key == "via" {
				r.Gateway = value
			} else {
				r.Source = value
			}
		case "from":
			if !wgEndpointUnrestrictedSource(value, r.Destination) {
				return nil, errWGEndpointRouteRead
			}
			r.From = value
		case "dev":
			if !proxyFirewallInterface.MatchString(value) || strings.ContainsAny(value, "+/\\") || len(value) > 15 {
				return nil, errWGEndpointRouteRead
			}
			r.Device = value
		case "proto", "scope":
			names := map[uint8]string{2: "kernel", 3: "boot", 4: "static", 9: "ra", 16: "dhcp"}
			if key == "scope" {
				names = map[uint8]string{0: "global", 200: "site", 253: "link", 254: "host"}
			}
			wire, _ := json.Marshal(value)
			normalized, err := wgEndpointRouteEnum(wire, names)
			known := slices.Contains([]string{"kernel", "boot", "static", "ra", "dhcp"}, normalized)
			if key == "scope" {
				known = slices.Contains([]string{"global", "universe", "site", "link", "host"}, normalized)
			}
			if err != nil || !known {
				return nil, errWGEndpointRouteRead
			}
			if key == "proto" {
				r.Protocol = normalized
			} else {
				r.Scope = normalized
			}
		case "metric":
			metric, err := strconv.ParseUint(value, 10, 31)
			if err != nil || strconv.FormatUint(metric, 10) != value {
				return nil, errWGEndpointRouteRead
			}
			r.Metric = int(metric)
		case "table":
			if value == "main" {
				r.Table = json.RawMessage("254")
			} else {
				table, err := strconv.ParseUint(value, 10, 32)
				if err != nil || table == 0 || strconv.FormatUint(table, 10) != value {
					return nil, errWGEndpointRouteRead
				}
				r.Table = json.RawMessage(value)
			}
		case "pref":
			if family != 6 || !slices.Contains([]string{"low", "medium", "high"}, value) {
				return nil, errWGEndpointRouteRead
			}
		default:
			return nil, errWGEndpointRouteRead
		}
	}
	if r.Device == "" || get && r.Source == "" {
		return nil, errWGEndpointRouteRead
	}
	return []wgEndpointRoute{r}, nil
}

// Without -N a local rt_protos/rt_scopes override can call a foreign value
// "static" or "link". Such names cannot become endpoint cleanup authority.
func wgEndpointTextNamesUnaliased() bool {
	if !reservedTableNamesUnaliased() {
		return false
	}
	for file, names := range map[string]map[string]uint64{
		"rt_protos": {"kernel": 2, "boot": 3, "static": 4, "ra": 9, "dhcp": 16},
		"rt_scopes": {"global": 0, "universe": 0, "site": 200, "link": 253, "host": 254},
	} {
		for _, root := range rtTablesSources {
			data, err := os.ReadFile(filepath.Join(root, file))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil || len(data) > 64<<10 {
				return false
			}
			for _, line := range strings.Split(string(data), "\n") {
				line, _, _ = strings.Cut(line, "#")
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				if len(fields) != 2 {
					return false
				}
				if want, known := names[fields[1]]; known {
					id, err := strconv.ParseUint(fields[0], 0, 8)
					if err != nil || id != want {
						return false
					}
				}
			}
		}
	}
	return true
}
