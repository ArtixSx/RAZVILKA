package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type proxyLANPrefix struct {
	prefix  netip.Prefix
	ingress string
}

func privateLANPrefix(prefix netip.Prefix) bool {
	for _, allowed := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		space := netip.MustParsePrefix(allowed)
		if prefix.Bits() >= space.Bits() && space.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func linuxBridgeMembers(ctx context.Context, iface string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !proxyFirewallInterface.MatchString(iface) {
		return nil, errors.New("invalid LAN bridge interface")
	}
	root := filepath.Join("/sys/class/net", iface)
	info, err := os.Stat(filepath.Join(root, "bridge"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() {
		return nil, errors.New("LAN bridge identity is unavailable")
	}
	entries, err := os.ReadDir(filepath.Join(root, "brif"))
	if err != nil || len(entries) > 64 {
		return nil, errors.New("LAN bridge members cannot be inspected")
	}
	members := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !proxyFirewallInterface.MatchString(entry.Name()) {
			return nil, errors.New("invalid LAN bridge member")
		}
		members = append(members, entry.Name())
	}
	return members, ctx.Err()
}

func (a *ProxyTunnelAdapter) connectedLANPrefixes(ctx context.Context, v6 bool) ([]proxyLANPrefix, error) {
	wan := map[string]bool{}
	// A bridge carrying either family's WAN default is never a LAN grant.
	for _, family := range []bool{false, true} {
		devices, err := a.forwardingWANInterfaces(ctx, family)
		if err != nil {
			return nil, err
		}
		for device := range devices {
			wan[device] = true
		}
	}
	for _, owned := range PolicyOwnershipSpecs() {
		wan[owned.Interface] = true
	}
	wan[a.Interface] = true
	wan["lo"] = true
	args := []string{"route", "show", "table", "main"}
	if v6 {
		args = append([]string{"-6"}, args...)
	}
	output, err := a.run(ctx, a.ip(), args...)
	if err != nil {
		return nil, errors.New("connected LAN routes cannot be inspected")
	}
	if len(output) > 1<<20 {
		return nil, errors.New("connected LAN route output exceeds its safe bound")
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 16384 {
		return nil, errors.New("connected LAN route count exceeds its safe bound")
	}
	probe := a.LANBridgeMembers
	if probe == nil {
		probe = linuxBridgeMembers
	}
	bridges := map[string]bool{}
	seenBridges := map[string]bool{}
	addresses := map[string]map[string]bool{}
	seen := map[string]bool{}
	var result []proxyLANPrefix
	for _, line := range lines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "unicast" {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(fields[0])
		if parseErr != nil || prefix.Addr().Is6() != v6 || !privateLANPrefix(prefix) || prefix.Addr().Is4In6() {
			continue
		}
		if policyHasToken(fields, "via") || policyHasToken(fields, "nexthop") {
			continue
		}
		if !v6 && !strings.Contains(" "+strings.Join(fields, " ")+" ", " scope link ") {
			continue
		}
		iface := policyRouteDevice([]byte(line))
		if !proxyFirewallInterface.MatchString(iface) || wan[iface] {
			continue
		}
		if !seenBridges[iface] {
			seenBridges[iface] = true
			members, err := probe(ctx, iface)
			if err != nil {
				return nil, err
			}
			bridges[iface] = len(members) > 0 && len(members) <= 64
			for _, member := range members {
				if !proxyFirewallInterface.MatchString(member) || wan[member] {
					bridges[iface] = false
				}
			}
		}
		if !bridges[iface] {
			continue
		}
		assigned, known := addresses[iface]
		if !known {
			assigned, err = a.lanInterfacePrefixes(ctx, iface, v6)
			if err != nil {
				return nil, err
			}
			addresses[iface] = assigned
		}
		// BusyBox omits `proto kernel`. Bind the connected route to an actual
		// address/prefix on the same UP bridge instead of guessing its origin.
		if !assigned[prefix.Masked().String()] {
			continue
		}
		key := prefix.Masked().String() + "\x00" + iface
		if !seen[key] {
			seen[key] = true
			result = append(result, proxyLANPrefix{prefix: prefix.Masked(), ingress: iface})
		}
		if len(result) > 64 {
			return nil, errors.New("connected LAN prefix count exceeds its safe bound")
		}
	}
	// Overlapping networks on distinct bridges are ambiguous even when a
	// reverse lookup happens to choose just one of them at this instant.
	for i, left := range result {
		for _, right := range result[i+1:] {
			if left.ingress != right.ingress && left.prefix.Overlaps(right.prefix) {
				return nil, errors.New("overlapping LAN bridges make source ingress ambiguous")
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].prefix.String() == result[j].prefix.String() {
			return result[i].ingress < result[j].ingress
		}
		return result[i].prefix.String() < result[j].prefix.String()
	})
	if len(result) == 0 {
		return nil, errors.New("no directly connected private LAN bridge prefix could be proven")
	}
	return result, nil
}

func (a *ProxyTunnelAdapter) lanInterfacePrefixes(ctx context.Context, iface string, v6 bool) (map[string]bool, error) {
	args := []string{"addr", "show", "dev", iface}
	if v6 {
		args = append([]string{"-6"}, args...)
	}
	output, err := a.run(ctx, a.ip(), args...)
	if err != nil {
		return nil, errors.New("LAN bridge addresses cannot be inspected")
	}
	if len(output) > 64<<10 {
		return nil, errors.New("LAN bridge address output exceeds its safe bound")
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 512 {
		return nil, errors.New("LAN bridge address count exceeds its safe bound")
	}
	result := map[string]bool{}
	current := ""
	up := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":")); err == nil && strings.HasSuffix(fields[0], ":") {
			current = strings.SplitN(strings.TrimSuffix(fields[1], ":"), "@", 2)[0]
			up = false
			for _, field := range fields[2:] {
				if strings.HasPrefix(field, "<") && strings.HasSuffix(field, ">") {
					up = strings.Contains(","+strings.Trim(field, "<>")+",", ",UP,")
					break
				}
			}
			continue
		}
		kind := "inet"
		if v6 {
			kind = "inet6"
		}
		if current != iface || !up || fields[0] != kind || policyHasToken(fields, "tentative") || policyHasToken(fields, "dadfailed") || policyHasToken(fields, "deprecated") {
			continue
		}
		prefix, err := netip.ParsePrefix(fields[1])
		if err != nil || prefix.Addr().Is6() != v6 || !privateLANPrefix(prefix) {
			continue
		}
		result[prefix.Masked().String()] = true
		if len(result) > 64 {
			return nil, errors.New("LAN bridge prefix count exceeds its safe bound")
		}
	}
	return result, nil
}

func (a *ProxyTunnelAdapter) prepareForwarding(ctx context.Context, state *PolicyState) error {
	ctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	rules := effectivePolicyRules(*state)
	expanded := map[string]PolicyRule{}
	lanByFamily := map[bool][]proxyLANPrefix{}
	for _, rule := range rules {
		if rule.Source != "" {
			expanded[rule.Source+"\x00"+rule.Destination] = rule
			continue
		}
		destination, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			return err
		}
		v6 := destination.Addr().Is6()
		lan, exists := lanByFamily[v6]
		if !exists {
			lan, err = a.connectedLANPrefixes(ctx, v6)
			if err != nil {
				return err
			}
			lanByFamily[v6] = lan
		}
		for _, network := range lan {
			source := network.prefix.String()
			expanded[source+"\x00"+rule.Destination] = PolicyRule{Source: source, Destination: rule.Destination}
		}
		if len(expanded) > maxProxyForwardingRules {
			return errors.New("LAN/service rule fanout exceeds the safe forwarding limit")
		}
	}
	state.Rules = make([]PolicyRule, 0, len(expanded))
	for _, rule := range expanded {
		state.Rules = append(state.Rules, rule)
	}
	sort.Slice(state.Rules, func(i, j int) bool {
		if state.Rules[i].Destination == state.Rules[j].Destination {
			return state.Rules[i].Source < state.Rules[j].Source
		}
		return state.Rules[i].Destination < state.Rules[j].Destination
	})
	var err error
	state.Forwarding, err = a.compileForwarding(ctx, *state)
	return err
}

func connectedLANIngress(networks []proxyLANPrefix, source netip.Prefix) (string, error) {
	ingress := ""
	for _, network := range networks {
		if network.prefix.Bits() <= source.Bits() && network.prefix.Contains(source.Addr()) {
			if ingress != "" && ingress != network.ingress {
				return "", errors.New("LAN source has ambiguous bridge ingress")
			}
			ingress = network.ingress
		}
	}
	if ingress == "" {
		return "", errors.New("source subnet is not contained in a directly connected LAN bridge")
	}
	return ingress, nil
}

func policySubnetProbeSource(ctx context.Context, runner NFQWS2Runner, ipCommand string, source netip.Prefix, tunnel, wantedIngress string) (netip.Addr, error) {
	address := source.Masked().Addr().Next()
	// Skip router-owned addresses: a local route lookup is not evidence for a
	// forwarded LAN packet. No probes/ARP/TCP are sent by these FIB lookups.
	for attempt := 0; attempt < 8 && source.Contains(address); attempt++ {
		ingress, err := policySourceIngress(ctx, runner, ipCommand, address, tunnel)
		if err == nil && ingress == wantedIngress {
			return address, nil
		}
		if ctx.Err() != nil {
			return netip.Addr{}, ctx.Err()
		}
		address = address.Next()
	}
	return netip.Addr{}, errors.New("no non-local LAN source could be used for a bounded forwarding route probe")
}
