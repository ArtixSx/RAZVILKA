package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Closed intent only. The original process/capture/mapping owner must publish
// and authenticate its COMMON receipt before this can become forwarding proof.
// Only this client's MAC/iif and reserved synthetic IP enter the capture hook.
func compileDomainTCPCaptureEffects(spec DomainPolicyTCPCaptureSpec, mapping dnscontrol.SyntheticDNSMappingObservation) (PolicyEffectPlan, error) {
	if !spec.valid() || !domainPolicyTCPMappingMatchesCapture(mapping, spec) {
		return PolicyEffectPlan{}, ErrDomainPolicyTCPConsumer
	}
	hash := sha256.Sum256([]byte(spec.Xray.Generation + "\x00" + mapping.PublicationID + "\x00" + spec.Client.Address.String() + "\x00" + spec.Client.MAC + "\x00" + spec.Client.Interface + "\x00" + mapping.Synthetic.String() + "\x00" + spec.Listen.String()))
	suffix := hex.EncodeToString(hash[:10])
	natChain, inputChain := "RZDC_"+suffix, "RZDI_"+suffix
	plan := PolicyEffectPlan{Generation: spec.Xray.Generation}
	plan.Effects = []PolicyEffect{
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-N", natChain}, Delete: []string{"-t", "nat", "-X", natChain}},
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-A", natChain, "-p", "tcp", "-j", "DNAT", "--to-destination", spec.Listen.String()}, Delete: []string{"-t", "nat", "-D", natChain, "-p", "tcp", "-j", "DNAT", "--to-destination", spec.Listen.String()}, Needs: []int{0}},
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "filter", "-N", inputChain}, Delete: []string{"-t", "filter", "-X", inputChain}},
		{Tool: PolicyEffectIPTables, Add: []string{"-t", "filter", "-A", inputChain, "-j", "ACCEPT"}, Delete: []string{"-t", "filter", "-D", inputChain, "-j", "ACCEPT"}, Needs: []int{2}},
	}
	input := []string{"INPUT", "-i", spec.Client.Interface, "-s", spec.Client.Address.String() + "/32", "-d", spec.Listen.Addr().String() + "/32", "-m", "mac", "--mac-source", spec.Client.MAC, "-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(int(spec.Listen.Port())), "-j", inputChain}
	plan.Effects = append(plan.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "filter", "-I", input[0], "1"}, input[1:]...), Delete: append([]string{"-t", "filter", "-D"}, input...), Needs: []int{2, 3}})
	for _, port := range []string{"80", "443"} {
		rule := []string{"PREROUTING", "-i", spec.Client.Interface, "-s", spec.Client.Address.String() + "/32", "-d", mapping.Synthetic.String() + "/32", "-m", "mac", "--mac-source", spec.Client.MAC, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", natChain}
		plan.Effects = append(plan.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "nat", "-I", rule[0], "1"}, rule[1:]...), Delete: append([]string{"-t", "nat", "-D"}, rule...), Needs: []int{0, 1, 4}})
	}
	if _, err := PolicyEffectPlanDigest(plan); err != nil {
		return PolicyEffectPlan{}, err
	}
	return plan, nil
}

func domainTCPCaptureEffectRow(effect PolicyEffect) (backendInventoryRow, error) {
	t := slices.Clone(effect.Add)
	if len(t) < 4 || t[0] != "-t" {
		return backendInventoryRow{}, ErrDomainPolicyTCPConsumer
	}
	row := backendInventoryRow{Family: 4, Table: t[1], Tokens: t[2:]}
	if row.Tokens[0] == "-I" {
		if len(row.Tokens) < 4 || row.Tokens[2] != "1" {
			return backendInventoryRow{}, ErrDomainPolicyTCPConsumer
		}
		row.Tokens = append([]string{"-A", row.Tokens[1]}, row.Tokens[3:]...)
	}
	return row, nil
}

func domainTCPCaptureChain(s string) bool {
	if len(s) != 25 || !strings.HasPrefix(s, "RZDC_") && !strings.HasPrefix(s, "RZDI_") {
		return false
	}
	return strings.Trim(s[5:], "0123456789abcdef") == ""
}

func domainTCPCaptureRuleKey(row backendInventoryRow) (string, error) {
	t := row.Tokens
	if row.Family != 4 || row.Table != "nat" && row.Table != "filter" || len(t) < 2 || len(t) > 40 {
		return "", ErrDomainPolicyTCPConsumer
	}
	if t[0] == "-N" && len(t) == 2 && domainTCPCaptureChain(t[1]) {
		return row.Table + "\x00-N\x00" + t[1], nil
	}
	if t[0] != "-A" || t[1] != "PREROUTING" && t[1] != "INPUT" && !domainTCPCaptureChain(t[1]) || len(t)%2 != 0 {
		return "", ErrDomainPolicyTCPConsumer
	}
	parts := []string{row.Table, t[0], t[1]}
	seen := map[string]bool{}
	modules := map[string]bool{}
	for n := 2; n < len(t); n += 2 {
		key, value := t[n], t[n+1]
		if key != "-m" && seen[key] {
			return "", ErrDomainPolicyTCPConsumer
		}
		seen[key] = true
		switch key {
		case "-s", "-d":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, e := netip.ParseAddr(value)
				if e != nil || !address.Is4() {
					return "", ErrDomainPolicyTCPConsumer
				}
				prefix = netip.PrefixFrom(address, 32)
			}
			if !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return "", ErrDomainPolicyTCPConsumer
			}
			value = prefix.String()
		case "--mac-source":
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
				return "", ErrDomainPolicyTCPConsumer
			}
			value = mac.String()
		case "-m":
			if value != "mac" && value != "tcp" || modules[value] {
				return "", ErrDomainPolicyTCPConsumer
			}
			modules[value] = true
		case "-p":
			if value != "tcp" {
				return "", ErrDomainPolicyTCPConsumer
			}
		case "-i":
			if !proxyFirewallInterface.MatchString(value) || value == "lo" {
				return "", ErrDomainPolicyTCPConsumer
			}
		case "--dport", "--to-ports":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
				return "", ErrDomainPolicyTCPConsumer
			}
		case "--to-destination":
			endpoint, err := netip.ParseAddrPort(value)
			if err != nil || !endpoint.Addr().Is4() || !endpoint.Addr().IsGlobalUnicast() || endpoint.Port() == 0 || endpoint.String() != value {
				return "", ErrDomainPolicyTCPConsumer
			}
		case "-j":
			if value != "ACCEPT" && value != "DNAT" && !domainTCPCaptureChain(value) {
				return "", ErrDomainPolicyTCPConsumer
			}
		default:
			return "", ErrDomainPolicyTCPConsumer
		}
		parts = append(parts, key+"="+value)
	}
	slices.Sort(parts[3:])
	data, _ := json.Marshal(parts)
	return string(data), nil
}

// Whole owned bodies/references, both tables and families, including duplicate
// rows. Missing effects may describe compensation; foreign bodies never do.
func domainTCPCapturePresence(rows []backendInventoryRow, plan PolicyEffectPlan, index int) (int, error) {
	if len(plan.Effects) != 7 || index < 0 || index >= len(plan.Effects) {
		return 0, ErrDomainPolicyTCPConsumer
	}
	chains := []string{plan.Effects[0].Add[3], plan.Effects[2].Add[3]}
	keys := make([]string, len(plan.Effects))
	counts := make([]int, len(keys))
	for i, effect := range plan.Effects {
		row, err := domainTCPCaptureEffectRow(effect)
		if err != nil {
			return 0, err
		}
		keys[i], err = domainTCPCaptureRuleKey(row)
		if err != nil {
			return 0, err
		}
	}
	for _, row := range rows {
		t := row.Tokens
		owned := len(t) > 1 && slices.Contains(chains, t[1])
		for n := 2; n+1 < len(t); n++ {
			if slices.Contains([]string{"-j", "-g", "--jump", "--goto"}, t[n]) && slices.Contains(chains, t[n+1]) {
				owned = true
			}
		}
		if !owned {
			continue
		}
		key, err := domainTCPCaptureRuleKey(row)
		if err != nil {
			return 0, err
		}
		match := slices.Index(keys, key)
		if match < 0 {
			return 0, ErrDomainPolicyTCPConsumer
		}
		counts[match]++
		if counts[match] > 1 {
			return 0, ErrDomainPolicyTCPConsumer
		}
	}
	return counts[index], nil
}

// Counterfactual baseline comparison removes only the compiler's exact owned
// capture rows after validating the whole owner. The caller separately holds
// the original typed capture resource; a DTO plan cannot select this view.
func domainTCPCaptureBaselineRows(rows []backendInventoryRow, plan PolicyEffectPlan) ([]backendInventoryRow, error) {
	if _, err := domainTCPCapturePresence(rows, plan, 0); err != nil {
		return nil, err
	}
	chains := []string{plan.Effects[0].Add[3], plan.Effects[2].Add[3]}
	filtered := make([]backendInventoryRow, 0, len(rows))
	for _, row := range rows {
		t := row.Tokens
		owned := len(t) > 1 && slices.Contains(chains, t[1])
		for n := 2; n+1 < len(t); n++ {
			if slices.Contains([]string{"-j", "-g", "--jump", "--goto"}, t[n]) && slices.Contains(chains, t[n+1]) {
				owned = true
			}
		}
		if !owned {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
}

// Complete readback additionally authenticates hook priority. Exact rules at
// the end of an unrelated chain are not capture readiness. Each -I 1 occurs
// in compiler order, so the 443 selector precedes the 80 selector in -S.
func domainTCPCapturePreparedInventory(rows []backendInventoryRow, plan PolicyEffectPlan) error {
	for i := range plan.Effects {
		count, err := domainTCPCapturePresence(rows, plan, i)
		if err != nil || count != 1 {
			return ErrDomainPolicyTCPConsumer
		}
	}
	for _, hook := range []struct {
		table, chain string
		indices      []int
	}{{"nat", "PREROUTING", []int{6, 5}}, {"filter", "INPUT", []int{4}}} {
		n := 0
		for _, row := range rows {
			if row.Family != 4 || row.Table != hook.table || len(row.Tokens) < 2 || row.Tokens[0] != "-A" || row.Tokens[1] != hook.chain {
				continue
			}
			if n == len(hook.indices) {
				break
			}
			actual, err := domainTCPCaptureRuleKey(row)
			expectedRow, e := domainTCPCaptureEffectRow(plan.Effects[hook.indices[n]])
			expected, e2 := domainTCPCaptureRuleKey(expectedRow)
			if err != nil || e != nil || e2 != nil || actual != expected {
				return ErrDomainPolicyTCPConsumer
			}
			n++
		}
		if n != len(hook.indices) {
			return ErrDomainPolicyTCPConsumer
		}
	}
	return nil
}
