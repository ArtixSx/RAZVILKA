package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var ErrLANPolicyTransitionRequired = errors.New("LAN policy requires a reviewed negative-boundary transition")

// LANPolicyCaptureClass is reconstructed by the existing capture owner from
// its frozen plan, never from receipt argv or a matching kernel tuple. Hooks
// are limited to consumers after mangle admission. A raw queue or an unknown
// earlier hook is NOT covered by this suspension compiler.
type LANPolicyCaptureClass struct {
	Owner                string   `json:"owner"`
	Generation           string   `json:"generation"`
	DescriptorDigest     string   `json:"descriptor_digest"`
	Family               int      `json:"family"`
	SegmentID            string   `json:"segment_id"`
	Interface            string   `json:"interface"`
	Hook                 string   `json:"hook"` // mangle-prerouting, nat-prerouting, routing
	Sources              []string `json:"sources"`
	Protocol             string   `json:"protocol"`         // tcp or udp
	DestinationMode      string   `json:"destination_mode"` // all or prefix; never implicit all
	Destinations         []string `json:"destinations,omitempty"`
	ExcludedDestinations []string `json:"excluded_destinations,omitempty"`
	DestinationPorts     []uint16 `json:"destination_ports"`
}

// A protected baseline flow requires the actual owner's original tuple and
// retained baseline lease. An address/name observation is not this proof.
type LANPolicyProtectedFlow struct {
	Generation  string         `json:"generation"`
	FlowID      string         `json:"flow_id"`
	GrantDigest string         `json:"grant_digest"`
	SegmentID   string         `json:"segment_id"`
	Interface   string         `json:"interface"`
	MAC         string         `json:"mac"`
	Source      netip.AddrPort `json:"source"`
	Destination netip.AddrPort `json:"destination"`
	Protocol    string         `json:"protocol"`
}

// Suspension blocks the exact retained owned class while preserving the old
// receipt and its negative boundaries. It does not withdraw or settle an
// unknown capture, clear admission bits, or turn blocked traffic into DIRECT.
// Changed ingress/membership/exclusions refuse before effects: safe union
// cutover must be implemented separately, never simulated by raw RETURN.
type LANPolicySuspensionPlan struct {
	Schema     int                      `json:"schema"`
	Generation string                   `json:"generation"`
	Digest     string                   `json:"digest"`
	PriorLAN   *LANPolicyRuntimePlan    `json:"prior_lan"`
	CurrentLAN *LANPolicyRuntimePlan    `json:"current_lan"`
	Captures   []LANPolicyCaptureClass  `json:"captures"`
	Baseline   []LANPolicyProtectedFlow `json:"baseline,omitempty"`
}

func CloneLANPolicySuspensionPlan(p *LANPolicySuspensionPlan) *LANPolicySuspensionPlan {
	if p == nil {
		return nil
	}
	c := *p
	c.PriorLAN, c.CurrentLAN = CloneLANPolicyRuntime(p.PriorLAN), CloneLANPolicyRuntime(p.CurrentLAN)
	c.Captures = slices.Clone(p.Captures)
	for i := range c.Captures {
		c.Captures[i].Sources = slices.Clone(p.Captures[i].Sources)
		c.Captures[i].Destinations = slices.Clone(p.Captures[i].Destinations)
		c.Captures[i].ExcludedDestinations = slices.Clone(p.Captures[i].ExcludedDestinations)
		c.Captures[i].DestinationPorts = slices.Clone(p.Captures[i].DestinationPorts)
	}
	c.Baseline = slices.Clone(p.Baseline)
	return &c
}

func lanPolicyCaptureDigest(c LANPolicyCaptureClass) string {
	c.DescriptorDigest = ""
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func lanPolicySuspensionDigest(p *LANPolicySuspensionPlan) string {
	c := *p
	c.Digest = ""
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func FreezeLANPolicySuspensionPlan(generation string, prior, current *LANPolicyRuntimePlan, captures []LANPolicyCaptureClass, baseline []LANPolicyProtectedFlow) (*LANPolicySuspensionPlan, error) {
	p := CloneLANPolicySuspensionPlan(&LANPolicySuspensionPlan{Schema: 1, Generation: generation, PriorLAN: prior, CurrentLAN: current, Captures: captures, Baseline: baseline})
	for i := range p.Captures {
		c := &p.Captures[i]
		sort.Strings(c.Sources)
		sort.Strings(c.Destinations)
		sort.Strings(c.ExcludedDestinations)
		slices.Sort(c.DestinationPorts)
		c.DescriptorDigest = lanPolicyCaptureDigest(*c)
	}
	sort.Slice(p.Captures, func(i, j int) bool { return p.Captures[i].DescriptorDigest < p.Captures[j].DescriptorDigest })
	sort.Slice(p.Baseline, func(i, j int) bool { return p.Baseline[i].FlowID < p.Baseline[j].FlowID })
	p.Digest = lanPolicySuspensionDigest(p)
	if err := ValidateLANPolicySuspensionPlan(p); err != nil {
		return nil, err
	}
	if _, err := p.Effects(); err != nil {
		return nil, err
	}
	return p, nil
}

func lanPolicySuspensionIngress(p *LANPolicyRuntimePlan, id, iface string) (LANPolicyIngress, bool) {
	for _, g := range p.Ingress {
		if g.SegmentID == id && g.Interface == iface {
			return g, true
		}
	}
	return LANPolicyIngress{}, false
}

func lanPolicySuspensionPrefix(value string, family int) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(value)
	return p, err == nil && p == p.Masked() && p.Bits() != 0 && !p.Addr().Is4In6() && p.Addr().Zone() == "" && p.Addr().Is4() == (family == 4) && !p.Addr().IsMulticast() && !p.Addr().IsUnspecified() && !p.Addr().IsLoopback()
}

func ValidateLANPolicySuspensionPlan(p *LANPolicySuspensionPlan) error {
	if p == nil || p.Schema != 1 || !lanPolicyHash(p.Generation) || ValidateLANPolicyRuntime(p.PriorLAN) != nil || ValidateLANPolicyRuntime(p.CurrentLAN) != nil || len(p.Captures) == 0 || len(p.Captures) > 32 || len(p.Baseline) > 128 || p.Digest != lanPolicySuspensionDigest(p) {
		return ErrLANPolicyRuntime
	}
	if !reflect.DeepEqual(p.PriorLAN.Ingress, p.CurrentLAN.Ingress) {
		return ErrLANPolicyTransitionRequired
	}
	seen := map[string]bool{}
	for _, c := range p.Captures {
		g, ok := lanPolicySuspensionIngress(p.PriorLAN, c.SegmentID, c.Interface)
		if !ok || c.Owner == "" || len(c.Owner) > 64 || !proxyFirewallInterface.MatchString(c.Owner) || strings.Contains(c.Owner, "+") || c.Generation != p.PriorLAN.Generation || c.DescriptorDigest != lanPolicyCaptureDigest(c) || seen[c.DescriptorDigest] || c.Family != 4 && c.Family != 6 || !slices.Contains([]string{"mangle-prerouting", "nat-prerouting", "routing"}, c.Hook) || !slices.Contains([]string{"tcp", "udp"}, c.Protocol) || len(c.Sources) == 0 || len(c.Sources) > 16 || len(c.Destinations) > 16 || len(c.ExcludedDestinations) > 16 || !slices.Contains([]string{"all", "prefix"}, c.DestinationMode) || c.DestinationMode == "all" && len(c.Destinations) != 0 || c.DestinationMode == "prefix" && len(c.Destinations) == 0 || len(c.DestinationPorts) == 0 || len(c.DestinationPorts) > 16 {
			return ErrLANPolicyRuntime
		}
		seen[c.DescriptorDigest] = true
		for listIndex, list := range [][]string{c.Sources, c.Destinations, c.ExcludedDestinations} {
			duplicates := map[string]bool{}
			for _, value := range list {
				prefix, valid := lanPolicySuspensionPrefix(value, c.Family)
				if !valid || duplicates[value] {
					return ErrLANPolicyRuntime
				}
				duplicates[value] = true
				if listIndex == 0 {
					inside := false
					for _, bound := range g.Sources {
						b := netip.MustParsePrefix(bound)
						inside = inside || b.Addr().Is4() == prefix.Addr().Is4() && b.Bits() <= prefix.Bits() && b.Contains(prefix.Addr())
					}
					if !inside {
						return ErrLANPolicyRuntime
					}
				}
			}
		}
		for i, port := range c.DestinationPorts {
			if port == 0 || i > 0 && port <= c.DestinationPorts[i-1] {
				return ErrLANPolicyRuntime
			}
		}
	}
	seen = map[string]bool{}
	for _, f := range p.Baseline {
		g, ok := lanPolicySuspensionIngress(p.PriorLAN, f.SegmentID, f.Interface)
		mac, err := net.ParseMAC(f.MAC)
		if !ok || f.Generation != p.PriorLAN.Generation || len(f.FlowID) == 0 || len(f.FlowID) > 256 || strings.ContainsAny(f.FlowID, "\r\n\x00") || seen[f.FlowID] || !lanPolicyHash(f.GrantDigest) || err != nil || len(mac) != 6 || mac[0]&1 != 0 || strings.ToUpper(mac.String()) != f.MAC || mac.String() == "00:00:00:00:00:00" || !f.Source.IsValid() || !f.Destination.IsValid() || f.Source.Port() == 0 || f.Destination.Port() == 0 || f.Source.Addr().Is4In6() || f.Destination.Addr().Is4In6() || f.Source.Addr().Zone() != "" || f.Destination.Addr().Zone() != "" || f.Source.Addr().Is4() != f.Destination.Addr().Is4() || !slices.Contains([]string{"tcp", "udp"}, f.Protocol) {
			return ErrLANPolicyRuntime
		}
		inside := false
		for _, value := range g.Sources {
			inside = inside || netip.MustParsePrefix(value).Contains(f.Source.Addr())
		}
		if !inside {
			return ErrLANPolicyRuntime
		}
		seen[f.FlowID] = true
	}
	return nil
}

func lanPolicySuspensionChains(p *LANPolicySuspensionPlan) []lanPolicyChain {
	var result []lanPolicyChain
	for i, capture := range p.Captures {
		g, _ := lanPolicySuspensionIngress(p.PriorLAN, capture.SegmentID, capture.Interface)
		c := lanPolicyChain{family: capture.Family, name: fmt.Sprintf("RZB_%s_%d_%d", p.Digest[:12], i, capture.Family)}
		c.jump = []string{"-i", g.Interface, "-j", c.name}
		for _, mac := range g.ExcludedMACs {
			c.rules = append(c.rules, []string{"-m", "mac", "--mac-source", mac, "-j", "RETURN"})
		}
		for _, source := range g.ExcludedSources {
			if netip.MustParsePrefix(source).Addr().Is4() == (c.family == 4) {
				c.rules = append(c.rules, []string{"-s", source, "-j", "RETURN"})
			}
		}
		for _, f := range p.Baseline {
			if f.Interface != g.Interface || f.Source.Addr().Is4() != (c.family == 4) {
				continue
			}
			c.rules = append(c.rules, []string{"-s", f.Source.Addr().String(), "-d", f.Destination.Addr().String(), "-p", f.Protocol, "-m", "mac", "--mac-source", f.MAC, "-m", f.Protocol, "--sport", strconv.Itoa(int(f.Source.Port())), "--dport", strconv.Itoa(int(f.Destination.Port())), "-j", "RETURN"})
		}
		for _, destination := range capture.ExcludedDestinations {
			c.rules = append(c.rules, []string{"-d", destination, "-j", "RETURN"})
		}
		macs, destinations := []string{""}, capture.Destinations
		if g.Membership == "mac" {
			macs = g.IncludedMACs
		}
		if capture.DestinationMode == "all" {
			destinations = []string{""}
		}
		for _, source := range capture.Sources {
			for _, destination := range destinations {
				for _, mac := range macs {
					for _, port := range capture.DestinationPorts {
						rule := []string{"-s", source}
						if destination != "" {
							rule = append(rule, "-d", destination)
						}
						rule = append(rule, "-p", capture.Protocol)
						if mac != "" {
							rule = append(rule, "-m", "mac", "--mac-source", mac)
						}
						rule = append(rule, "-m", capture.Protocol, "--dport", strconv.Itoa(int(port)), "-j", "DROP")
						c.rules = append(c.rules, rule)
					}
				}
			}
		}
		c.rules = append(c.rules, []string{"-j", "RETURN"})
		result = append(result, c)
	}
	return result
}

func (p *LANPolicySuspensionPlan) Effects() (PolicyEffectPlan, error) {
	if err := ValidateLANPolicySuspensionPlan(p); err != nil {
		return PolicyEffectPlan{}, err
	}
	// Bound the full expansion before allocating it or issuing any effects.
	count := 0
	for _, c := range p.Captures {
		g, _ := lanPolicySuspensionIngress(p.PriorLAN, c.SegmentID, c.Interface)
		count += 3 + len(g.ExcludedMACs) + len(g.ExcludedSources) + len(p.Baseline) + len(c.ExcludedDestinations) + len(c.Sources)*max(1, len(c.Destinations))*max(1, len(g.IncludedMACs))*len(c.DestinationPorts)
		if count > 4096 {
			return PolicyEffectPlan{}, ErrLANPolicyRuntime
		}
	}
	plan := PolicyEffectPlan{Generation: p.Generation}
	chains := lanPolicySuspensionChains(p)
	ready := make([]int, len(chains))
	for i, c := range chains {
		tool := PolicyEffectIPTables
		if c.family == 6 {
			tool = PolicyEffectIP6Tables
		}
		previous := len(plan.Effects)
		plan.Effects = append(plan.Effects, PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-N", c.name}, Delete: []string{"-t", "mangle", "-X", c.name}})
		for _, rule := range c.rules {
			index := len(plan.Effects)
			plan.Effects = append(plan.Effects, PolicyEffect{Tool: tool, Add: append([]string{"-t", "mangle", "-A", c.name}, rule...), Delete: append([]string{"-t", "mangle", "-D", c.name}, rule...), Needs: []int{previous}})
			previous = index
		}
		ready[i] = previous
	}
	// Every published jump depends on ALL bodies, including both families.
	for _, c := range chains {
		tool := PolicyEffectIPTables
		if c.family == 6 {
			tool = PolicyEffectIP6Tables
		}
		plan.Effects = append(plan.Effects, PolicyEffect{Tool: tool, Add: append([]string{"-t", "mangle", "-I", "PREROUTING", "1"}, c.jump...), Delete: append([]string{"-t", "mangle", "-D", "PREROUTING"}, c.jump...), Needs: slices.Clone(ready)})
	}
	if _, err := PolicyEffectPlanDigest(plan); err != nil {
		return PolicyEffectPlan{}, err
	}
	return plan, nil
}
