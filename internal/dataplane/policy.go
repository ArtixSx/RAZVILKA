package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
)

const maxPolicyPrefixes = 1024

// PolicyOwnershipSpec publishes the kernel resources reserved by each
// transactional tunnel adapter. Engine Lab uses the same source of truth as
// activation, so preflight cannot silently drift from runtime defaults.
type PolicyOwnershipSpec struct {
	Adapter      string
	Interface    string
	Table        int
	PriorityBase int
	PriorityEnd  int
}

func PolicyOwnershipSpecs() []PolicyOwnershipSpec {
	return []PolicyOwnershipSpec{
		{Adapter: "warp-wg", Interface: "rz-warp", Table: 201, PriorityBase: 18100, PriorityEnd: 18100 + maxPolicyPrefixes - 1},
		{Adapter: "usque", Interface: "rz-usque", Table: 202, PriorityBase: 20000, PriorityEnd: 20000 + maxPolicyPrefixes - 1},
		{Adapter: "sing-box", Interface: "rz-sing", Table: 203, PriorityBase: 22000, PriorityEnd: 22000 + maxPolicyPrefixes - 1},
		{Adapter: "xray", Interface: "rz-xray", Table: 204, PriorityBase: 24000, PriorityEnd: 24000 + maxPolicyPrefixes - 1},
		{Adapter: "amneziawg", Interface: "rz-awg", Table: 205, PriorityBase: 26000, PriorityEnd: 26000 + maxPolicyPrefixes - 1},
	}
}

type PrefixResolver func(context.Context, string) ([]netip.Addr, error)

type PolicyState struct {
	Interface    string       `json:"interface"`
	Table        int          `json:"table"`
	PriorityBase int          `json:"priority_base"`
	Prefixes     []string     `json:"prefixes"`
	Rules        []PolicyRule `json:"rules,omitempty"`
	// WARP/AWG commit binds cleanup authority to the exact sanitized runtime.
	// Absent in older states and unrelated proxy policies; absence is not a
	// license to delete an interface merely because its name matches.
	RuntimeConfigSHA256 string `json:"runtime_config_sha256,omitempty"`
	// Exclusions are exact public endpoint prefixes routed through main before
	// the service rules. The private policy file is mode 0600 and is never a
	// public DTO.
	Exclusions []string `json:"exclusions,omitempty"`
	// Forwarding is the private, exact client/TUN firewall intent. Older state
	// remains removable, but cannot acquire new forwarding authority implicitly.
	Forwarding *ProxyForwardingState `json:"forwarding,omitempty"`
}

type PolicyRule struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
}

func resolvePolicyPrefixes(ctx context.Context, plan Plan, adapter string, resolver PrefixResolver) ([]string, error) {
	if resolver == nil {
		resolver = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
		}
	}
	prefixes := map[string]bool{}
	domains := map[string]bool{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != adapter {
			continue
		}
		for _, value := range route.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, fmt.Errorf("invalid policy prefix %q", value)
				}
				prefix = netip.PrefixFrom(address.Unmap(), address.BitLen())
			}
			prefixes[prefix.Masked().String()] = true
		}
		for _, domain := range route.Domains {
			domains[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))] = true
		}
	}
	type result struct {
		addresses []netip.Addr
		err       error
	}
	semaphore := make(chan struct{}, 8)
	results := make(chan result, len(domains))
	var wait sync.WaitGroup
	for domain := range domains {
		if domain == "" {
			continue
		}
		wait.Add(1)
		go func(domain string) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}
			addresses, err := resolver(ctx, domain)
			results <- result{addresses: addresses, err: err}
		}(domain)
	}
	wait.Wait()
	close(results)
	resolved := 0
	for result := range results {
		if result.err != nil {
			continue
		}
		for _, address := range result.addresses {
			address = address.Unmap()
			if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
				continue
			}
			prefixes[netip.PrefixFrom(address, address.BitLen()).String()] = true
			resolved++
		}
	}
	if len(domains) > 0 && resolved == 0 && len(prefixes) == 0 {
		return nil, errors.New("none of the service domains resolved to a public address")
	}
	if len(prefixes) > maxPolicyPrefixes {
		return nil, fmt.Errorf("resolved policy contains %d prefixes; maximum is %d", len(prefixes), maxPolicyPrefixes)
	}
	out := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := netip.ParsePrefix(out[i])
		right, _ := netip.ParsePrefix(out[j])
		if left.Addr().BitLen() != right.Addr().BitLen() {
			return left.Addr().BitLen() < right.Addr().BitLen()
		}
		return out[i] < out[j]
	})
	return out, nil
}

func resolvePolicyRules(ctx context.Context, plan Plan, adapter string, resolver PrefixResolver) ([]string, []PolicyRule, error) {
	prefixSet := map[string]bool{}
	ruleSet := map[string]PolicyRule{}
	global := map[string]bool{}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) != adapter {
			continue
		}
		prefixes, err := resolvePolicyPrefixes(ctx, Plan{Routes: []Route{route}}, adapter, resolver)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s policy for %s: %w", adapter, route.ServiceName, err)
		}
		sources := make([]netip.Prefix, 0, len(route.Sources))
		for _, value := range route.Sources {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, nil, fmt.Errorf("invalid device source %q", value)
				}
				address = address.Unmap()
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			sources = append(sources, prefix.Masked())
		}
		for _, destination := range prefixes {
			prefixSet[destination] = true
			destinationPrefix, _ := netip.ParsePrefix(destination)
			if len(sources) == 0 {
				global[destination] = true
				for key, rule := range ruleSet {
					if rule.Destination == destination {
						delete(ruleSet, key)
					}
				}
				ruleSet["\x00"+destination] = PolicyRule{Destination: destination}
				continue
			}
			if global[destination] {
				continue
			}
			for _, source := range sources {
				if source.Addr().Is4() != destinationPrefix.Addr().Is4() {
					continue
				}
				rule := PolicyRule{Source: source.String(), Destination: destination}
				ruleSet[rule.Source+"\x00"+rule.Destination] = rule
			}
		}
	}
	prefixes := make([]string, 0, len(prefixSet))
	for prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	rules := make([]PolicyRule, 0, len(ruleSet))
	for _, rule := range ruleSet {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Destination == rules[j].Destination {
			return rules[i].Source < rules[j].Source
		}
		return rules[i].Destination < rules[j].Destination
	})
	if len(rules) == 0 && len(prefixes) > 0 {
		return nil, nil, errors.New("device scopes do not match the destination address family")
	}
	if len(rules) > maxPolicyPrefixes {
		return nil, nil, fmt.Errorf("policy contains %d source/destination rules; maximum is %d", len(rules), maxPolicyPrefixes)
	}
	return prefixes, rules, nil
}

func applyPolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	rules := effectivePolicyRules(state)
	if state.Table < 1 || state.Table > 252 || state.PriorityBase < 1000 || state.Interface == "" || len(rules)+len(state.Exclusions) > maxPolicyPrefixes {
		return errors.New("invalid policy routing state")
	}
	if _, err := runner.Run(ctx, ipCommand, "route", "replace", "default", "dev", state.Interface, "table", fmt.Sprint(state.Table)); err != nil {
		return fmt.Errorf("create IPv4 policy table: %w", err)
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "replace", "default", "dev", state.Interface, "table", fmt.Sprint(state.Table))
	addedExclusions := []string{}
	for index, value := range state.Exclusions {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Exclusions: addedExclusions})
			return err
		}
		args := []string{"rule", "add", "priority", fmt.Sprint(state.PriorityBase + index), "to", prefix.String(), "lookup", "main"}
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Exclusions: addedExclusions})
			return fmt.Errorf("add direct endpoint exclusion: %w", err)
		}
		addedExclusions = append(addedExclusions, value)
	}
	added := []PolicyRule{}
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Exclusions: addedExclusions, Rules: added})
			return err
		}
		args := []string{"rule", "add", "priority", fmt.Sprint(state.PriorityBase + len(state.Exclusions) + index)}
		if rule.Source != "" {
			args = append(args, "from", rule.Source)
		}
		args = append(args, "to", prefix.String(), "lookup", fmt.Sprint(state.Table))
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil {
			_ = removePolicy(ctx, runner, ipCommand, PolicyState{Interface: state.Interface, Table: state.Table, PriorityBase: state.PriorityBase, Exclusions: addedExclusions, Rules: added})
			return fmt.Errorf("add policy rule for %s: %w", prefix, err)
		}
		added = append(added, rule)
	}
	return nil
}

func removePolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if runner == nil || ipCommand == "" {
		return errors.New("policy routing command runner is unavailable")
	}
	var firstErr error
	for index, value := range state.Exclusions {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		args := []string{"rule", "del", "priority", fmt.Sprint(state.PriorityBase + index), "to", prefix.String(), "lookup", "main"}
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	rules := effectivePolicyRules(state)
	for index, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			continue
		}
		args := []string{"rule", "del", "priority", fmt.Sprint(state.PriorityBase + len(state.Exclusions) + index)}
		if rule.Source != "" {
			args = append(args, "from", rule.Source)
		}
		args = append(args, "to", prefix.String(), "lookup", fmt.Sprint(state.Table))
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if _, err := runner.Run(ctx, ipCommand, args...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if _, err := runner.Run(ctx, ipCommand, "route", "flush", "table", fmt.Sprint(state.Table)); err != nil && firstErr == nil {
		firstErr = err
	}
	_, _ = runner.Run(ctx, ipCommand, "-6", "route", "flush", "table", fmt.Sprint(state.Table))
	verified := false
	for _, familyArgs := range [][]string{{"rule", "show"}, {"-6", "rule", "show"}} {
		output, err := runner.Run(ctx, ipCommand, familyArgs...)
		if err != nil {
			continue
		}
		verified = true
		text := string(output)
		for index := 0; index < len(state.Exclusions)+len(rules); index++ {
			priority := fmt.Sprint(state.PriorityBase + index)
			if strings.Contains(text, priority+":") || strings.Contains(text, "priority "+priority+" ") {
				return fmt.Errorf("policy rule priority %s remains after cleanup", priority)
			}
		}
	}
	if verified {
		return nil
	}
	return firstErr
}

func verifyPolicyEvidence(ctx context.Context, runner NFQWS2Runner, ipCommand string, state PolicyState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rules := effectivePolicyRules(state)
	if runner == nil || ipCommand == "" || state.Interface == "" || len(rules) == 0 {
		return errors.New("policy routing evidence is unavailable")
	}
	if state.Forwarding != nil && len(rules) > maxProxyForwardingRules {
		return errors.New("proxy forwarding route evidence exceeds its safe rule bound")
	}
	checked := 0
	ingresses := map[string]string{}
	probeSources := map[string]netip.Addr{}
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		prefix, err := netip.ParsePrefix(rule.Destination)
		if err != nil {
			return err
		}
		args := []string{"route", "get", prefix.Addr().String()}
		if rule.Source != "" {
			source, sourceErr := netip.ParsePrefix(rule.Source)
			if sourceErr != nil {
				return sourceErr
			}
			if source.Addr().Is4In6() || source.Addr().Is4() != prefix.Addr().Is4() {
				return errors.New("device source and destination families do not match")
			}
			sourceAddress := source.Addr()
			ingress, known := ingresses[source.String()]
			if !known {
				if state.Forwarding != nil && source.Bits() != source.Addr().BitLen() {
					for _, grant := range state.Forwarding.Rules {
						if grant.Source == source.String() && grant.Destination == rule.Destination {
							ingress = grant.Ingress
							break
						}
					}
					if ingress == "" {
						return errors.New("LAN route probe has no exact forwarding grant")
					}
					sourceAddress, sourceErr = policySubnetProbeSource(ctx, runner, ipCommand, source, state.Interface, ingress)
				} else {
					ingress, sourceErr = policySourceIngress(ctx, runner, ipCommand, source.Addr(), state.Interface)
				}
				if sourceErr != nil {
					return sourceErr
				}
				ingresses[source.String()] = ingress
				probeSources[source.String()] = sourceAddress
			} else {
				sourceAddress = probeSources[source.String()]
			}
			args = append(args, "from", sourceAddress.String())
			if ingress != "" {
				// Without iif Linux resolves a locally originated packet and
				// rejects the non-local address of an actual LAN client.
				args = append(args, "iif", ingress)
			}
		}
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		output, routeErr := runner.Run(ctx, ipCommand, args...)
		if routeErr != nil || policyNonUnicast(output) || policyRouteDevice(output) != state.Interface {
			return fmt.Errorf("kernel route evidence for %s does not use %s: %s", prefix, state.Interface, shortOutput(output, routeErr))
		}
		checked++
		// Proxy grants are already bounded: verify every granted pair so an
		// IPv6 or second-LAN rule cannot hide behind four IPv4 samples.
		if state.Forwarding == nil && checked >= 4 {
			break
		}
	}
	return nil
}

// A reverse lookup is only an ingress hint. For a forwarded source it must
// agree with one directly connected main-table interface: routed/asymmetric
// clients need an explicit ingress contract and cannot be inferred from a WAN
// default or another policy route. Forward lookup still must pick our tunnel.
func policySourceIngress(ctx context.Context, runner NFQWS2Runner, ipCommand string, source netip.Addr, tunnel string) (string, error) {
	if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() || source.Is4In6() || source.IsLinkLocalUnicast() {
		return "", errors.New("device source is not suitable for an ingress probe")
	}
	args := []string{"route", "get", source.String()}
	if source.Is6() {
		args = append([]string{"-6"}, args...)
	}
	output, err := runner.Run(ctx, ipCommand, args...)
	device := policyRouteDevice(output)
	if err != nil || device == "" || device == tunnel {
		return "", errors.New("device source ingress could not be established")
	}
	fields := strings.Fields(string(output))
	if len(fields) > 0 && fields[0] == "local" {
		return "", nil // A router-owned source uses the local output lookup.
	}
	if device == "lo" || policyNonUnicast(output) || policyHasToken(fields, "via") || policyHasToken(fields, "nexthop") {
		return "", errors.New("device source ingress is not a forwarding interface")
	}
	args = []string{"route", "show", "table", "main", "match", netip.PrefixFrom(source, source.BitLen()).String()}
	if source.Is6() {
		args = append([]string{"-6"}, args...)
	}
	connected, err := runner.Run(ctx, ipCommand, args...)
	if err != nil || !policyConnectedSource(connected, source, device) {
		return "", errors.New("device source ingress is not uniquely connected to the main table")
	}
	return device, nil
}

func policyConnectedSource(output []byte, source netip.Addr, device string) bool {
	if len(output) > 64<<10 {
		return false
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 512 {
		return false
	}
	found := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "default" {
			continue
		}
		if fields[0] == "unicast" {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			return false
		}
		prefix, err := netip.ParsePrefix(fields[0])
		if err != nil {
			address, addressErr := netip.ParseAddr(fields[0])
			if addressErr != nil {
				return false
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Bits() == 0 || !prefix.Contains(source) {
			continue
		}
		if policyHasToken(fields, "via") || policyHasToken(fields, "nexthop") || policyRouteDevice([]byte(line)) != device {
			return false
		}
		found = true
	}
	return found
}

func policyHasToken(fields []string, wanted string) bool {
	for _, field := range fields {
		if field == wanted {
			return true
		}
	}
	return false
}

func policyNonUnicast(output []byte) bool {
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return true
	}
	switch fields[0] {
	case "local", "broadcast", "multicast", "anycast", "blackhole", "unreachable", "prohibit", "throw", "nat":
		return true
	}
	return false
}

func policyRouteDevice(output []byte) string {
	fields := strings.Fields(string(output))
	device := ""
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			if device != "" {
				return ""
			}
			device = fields[i+1]
		}
	}
	return device
}

func effectivePolicyRules(state PolicyState) []PolicyRule {
	if len(state.Rules) > 0 {
		return state.Rules
	}
	rules := make([]PolicyRule, 0, len(state.Prefixes))
	for _, prefix := range state.Prefixes {
		rules = append(rules, PolicyRule{Destination: prefix})
	}
	return rules
}

func samePolicy(left, right PolicyState) bool {
	return left.Interface == right.Interface && left.Table == right.Table && left.PriorityBase == right.PriorityBase && reflect.DeepEqual(left.Prefixes, right.Prefixes) && reflect.DeepEqual(left.Exclusions, right.Exclusions) && reflect.DeepEqual(effectivePolicyRules(left), effectivePolicyRules(right)) && reflect.DeepEqual(left.Forwarding, right.Forwarding)
}

func replacePolicy(ctx context.Context, runner NFQWS2Runner, ipCommand string, oldState, newState PolicyState) error {
	if samePolicy(oldState, newState) {
		return nil
	}
	if err := removePolicy(ctx, runner, ipCommand, oldState); err != nil {
		return fmt.Errorf("remove old policy: %w", err)
	}
	if err := applyPolicy(ctx, runner, ipCommand, newState); err != nil {
		_ = removePolicy(ctx, runner, ipCommand, newState)
		if restoreErr := applyPolicy(ctx, runner, ipCommand, oldState); restoreErr != nil {
			return fmt.Errorf("apply refreshed policy: %w; restore old policy: %v", err, restoreErr)
		}
		return fmt.Errorf("apply refreshed policy: %w", err)
	}
	return nil
}
