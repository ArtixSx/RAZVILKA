package dataplane

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type kernelPolicyRule struct {
	family, priority, table      int
	source, destination, ingress string
	managed                      bool
}

// OwnsPolicyRule explains a complete kernel tuple from private recorded state.
// The adapter table or reserved slot alone never establishes ownership.
func (m *Manager) OwnsPolicyRule(adapterID string, family int, line string) bool {
	rule, ok := parseKernelPolicyRule(family, line)
	if !ok {
		return m.ownsWGEndpointRule(adapterID, family, line)
	}
	registered, exists := m.adapter(adapterID)
	if !exists {
		return false
	}
	var state PolicyState
	switch adapter := registered.(type) {
	case *ProxyTunnelAdapter:
		if adapter == nil || adapter.ID() != adapterID {
			return false
		}
		info, err := os.Lstat(adapter.policyPath())
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return false
		}
		file, err := os.Open(adapter.policyPath())
		if err != nil {
			return false
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return false
		}
		data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &state) != nil || state.Interface != adapter.Interface || state.Table != adapter.Table || state.PriorityBase != adapter.Priority {
			return false
		}
	case *WARPWireGuardAdapter:
		if adapter == nil || adapter.ID() != adapterID {
			return false
		}
		var err error
		state, exists, err = adapter.deactivationOwnership(context.Background())
		if err != nil || !exists {
			return false
		}
	default:
		return false
	}
	if len(state.Prefixes) == 0 || len(state.Prefixes) > maxPolicyPrefixes {
		return false
	}
	seen := map[string]bool{}
	for _, value := range state.Exclusions {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.String() != value || seen[value] {
			return false
		}
		seen[value] = true
	}
	rules, err := kernelRulesForPolicy(state)
	if err != nil {
		return false
	}
	for _, owned := range rules {
		if owned == rule {
			return true
		}
	}
	return false
}

func (m *Manager) ownedWGEndpoint(adapterID string) *WGEndpointState {
	registered, ok := m.adapter(adapterID)
	a, ok := registered.(*WARPWireGuardAdapter)
	if !ok || a == nil || a.ID() != adapterID {
		return nil
	}
	state, owned, err := a.deactivationOwnership(context.Background())
	if err != nil || !owned {
		return nil
	}
	return state.WireGuardEndpoint
}

func (m *Manager) ownsWGEndpointRule(adapterID string, family int, line string) bool {
	e := m.ownedWGEndpoint(adapterID)
	return e != nil && e.matchesRule(family, line)
}

// OwnsPolicyRoute explains only an exact persisted WG transport pin. A table,
// interface name or route prefix alone is never cleanup/Engine Lab authority.
func (m *Manager) OwnsPolicyRoute(adapterID string, family int, line string) bool {
	e := m.ownedWGEndpoint(adapterID)
	if e == nil || (family != 4 && family != 6) || (family == 4) != e.address().Is4() || len(line) > 2048 || strings.ContainsAny(line, "\x00\r\n") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	destination := fields[0]
	if ip, err := netip.ParseAddr(destination); err == nil {
		destination = netip.PrefixFrom(ip, ip.BitLen()).String()
	}
	if destination != e.prefix() {
		return false
	}
	values := map[string]string{}
	onlink := false
	for i := 1; i < len(fields); i++ {
		if fields[i] == "onlink" {
			if onlink {
				return false
			}
			onlink = true
			continue
		}
		key := fields[i]
		if i+1 >= len(fields) || values[key] != "" {
			return false
		}
		i++
		values[key] = fields[i]
		switch key {
		case "via", "dev", "src", "proto", "metric":
		case "scope":
			if fields[i] != "global" && fields[i] != "link" {
				return false
			}
		case "pref":
			if fields[i] != "medium" {
				return false
			}
		default:
			return false
		}
	}
	return values["via"] == e.Gateway && values["dev"] == e.Device && values["src"] == e.Source && values["proto"] == "static" && values["metric"] == strconv.Itoa(e.Metric) && onlink == (e.Gateway != "")
}

// OwnsProxyEndpointExclusion is a read-only Engine Lab ownership callback.
// Only a registered proxy's bounded private runtime policy can explain an
// exact main-table endpoint exclusion. No endpoint is returned in a public DTO.
func (m *Manager) OwnsProxyEndpointExclusion(adapterID string, family int, line string) bool {
	rule, ok := parseKernelPolicyRule(family, line)
	if !ok || rule.table != 254 || rule.source != "all" || rule.ingress != "" || rule.managed {
		return false
	}
	registered, ok := m.adapter(adapterID)
	a, ok := registered.(*ProxyTunnelAdapter)
	if !ok || a == nil {
		return false
	}
	var owner PolicyOwnershipSpec
	for _, spec := range PolicyOwnershipSpecs() {
		if spec.Adapter == adapterID {
			owner = spec
			break
		}
	}
	if owner.Adapter == "" || a.ID() != adapterID || a.Interface != owner.Interface || a.Table != owner.Table || a.Priority != owner.PriorityBase || rule.priority < owner.PriorityBase || rule.priority > owner.PriorityEnd {
		return false
	}
	info, err := os.Lstat(a.policyPath())
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return false
	}
	file, err := os.Open(a.policyPath())
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return false
	}
	var state PolicyState
	if json.Unmarshal(data, &state) != nil || state.RuleLayout != 0 || state.SharedPriorityBase != 0 || state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 || len(state.Prefixes) > maxPolicyPrefixes || len(effectivePolicyRules(state))+len(state.Exclusions) > maxPolicyPrefixes {
		return false
	}
	index := rule.priority - state.PriorityBase
	if index < 0 || index >= len(state.Exclusions) {
		return false
	}
	seen := make(map[string]bool, len(state.Exclusions))
	for _, value := range state.Exclusions {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() != prefix.Addr().BitLen() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.String() != value || seen[value] {
			return false
		}
		seen[value] = true
	}
	endpoint, err := netip.ParsePrefix(state.Exclusions[index])
	if err != nil || endpoint.Addr().Is4() != (family == 4) {
		return false
	}
	return rule.destination == endpoint.String()
}

// Parse only the grammar emitted for our simple ip rule commands. Optional
// selectors are never discarded while deciding ownership. Only our exact
// managed mark with explicit iif is supported in addition to legacy tuples;
// uidrange, other marks, not, goto and suppress_* cannot explain ownership.
func parseKernelPolicyRule(family int, line string) (kernelPolicyRule, bool) {
	var result kernelPolicyRule
	if (family != 4 && family != 6) || len(line) > 2048 || strings.ContainsAny(line, "\x00\r\n") {
		return result, false
	}
	fields := strings.Fields(line)
	if (len(fields) != 7 && len(fields) != 9 && len(fields) != 11) || !strings.HasSuffix(fields[0], ":") || fields[1] != "from" || fields[3] != "to" {
		return result, false
	}
	lookup := 5
	ingress := ""
	managed := false
	if len(fields) == 11 {
		if fields[5] != "fwmark" || fields[6] != LANPolicyGateMatch {
			return result, false
		}
		managed, lookup = true, 7
	}
	if len(fields) > 7 {
		if fields[lookup] != "iif" || !validPolicyIngress(fields[lookup+1]) {
			return result, false
		}
		ingress, lookup = fields[lookup+1], lookup+2
	}
	if fields[lookup] != "lookup" && fields[lookup] != "table" {
		return result, false
	}
	priorityText := strings.TrimSuffix(fields[0], ":")
	priority, err := strconv.Atoi(priorityText)
	if err != nil || priority < 0 || priority > 1<<31-1 || strconv.Itoa(priority) != priorityText {
		return result, false
	}
	normalize := func(value string, allowAll bool) (string, bool) {
		if allowAll && value == "all" {
			return "all", true
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addrErr := netip.ParseAddr(value)
			if addrErr != nil || address.Zone() != "" {
				return "", false
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4In6() || prefix.Addr().Is4() != (family == 4) || prefix != prefix.Masked() {
			return "", false
		}
		if allowAll && prefix.Bits() == 0 {
			return "all", true
		}
		return prefix.String(), true
	}
	source, ok := normalize(fields[2], true)
	if !ok {
		return result, false
	}
	destination, ok := normalize(fields[4], false)
	if !ok {
		return result, false
	}
	table := 254
	if fields[lookup+1] != "main" {
		table, err = strconv.Atoi(fields[lookup+1])
		if err != nil || table < 0 || table > 1<<31-1 || strconv.Itoa(table) != fields[lookup+1] {
			return result, false
		}
	}
	return kernelPolicyRule{family: family, priority: priority, table: table, source: source, destination: destination, ingress: ingress, managed: managed}, true
}
