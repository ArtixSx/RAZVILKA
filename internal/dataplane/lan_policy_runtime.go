package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// These bits are proposed owned resources, not a claim that a firmware leaves
// them unused. Admission must inspect both families before reserving them.
const (
	LANPolicyManagedMark    uint32 = 0x20000000
	LANPolicyBypassMark     uint32 = 0x08000000
	LANPolicyGateMask       uint32 = LANPolicyManagedMark | LANPolicyBypassMark
	LANPolicySkipPriority          = 53
	LANPolicyAnchorPriority        = 73
)

var ErrLANPolicyRuntime = errors.New("LAN policy gate unavailable or mismatched")

// LANPolicyIngress is copied from the reviewed compiler's physical ingress
// binding. Empty Sources never means all. ExcludedMACs remain negative even
// for addresses that did not exist when the policy was reviewed.
type LANPolicyIngress struct {
	SegmentID       string   `json:"segment_id"`
	Interface       string   `json:"interface"`
	Sources         []string `json:"sources"`
	Membership      string   `json:"membership"` // all or mac; empty is normalized only by compiler
	IncludedMACs    []string `json:"included_macs,omitempty"`
	ExcludedSources []string `json:"excluded_sources,omitempty"`
	ExcludedMACs    []string `json:"excluded_macs,omitempty"`
}

// LANPolicyRuntimePlan is durable intent for the SAME Manager transaction.
// It contains no credentials, independent lifetime or capability booleans.
type LANPolicyRuntimePlan struct {
	Schema     int                `json:"schema"`
	Generation string             `json:"generation"`
	Digest     string             `json:"digest"`
	Ingress    []LANPolicyIngress `json:"ingress"`
}

func CompileLANPolicyRuntime(generation string, ingress []LANPolicyIngress) (*LANPolicyRuntimePlan, error) {
	p := &LANPolicyRuntimePlan{Schema: 1, Generation: generation, Ingress: cloneLANPolicyIngress(ingress)}
	for i := range p.Ingress {
		if p.Ingress[i].Membership == "" {
			p.Ingress[i].Membership = "all"
			if len(p.Ingress[i].IncludedMACs) > 0 {
				p.Ingress[i].Membership = "mac"
			}
		}
	}
	if err := validateLANPolicyRuntime(p, false); err != nil {
		return nil, err
	}
	for i := range p.Ingress {
		sort.Strings(p.Ingress[i].Sources)
		sort.Strings(p.Ingress[i].IncludedMACs)
		sort.Strings(p.Ingress[i].ExcludedSources)
		sort.Strings(p.Ingress[i].ExcludedMACs)
	}
	sort.Slice(p.Ingress, func(i, j int) bool { return p.Ingress[i].Interface < p.Ingress[j].Interface })
	p.Digest = lanPolicyDigest(p)
	if _, err := p.Effects(); err != nil {
		return nil, err
	}
	return p, nil
}

func CloneLANPolicyRuntime(p *LANPolicyRuntimePlan) *LANPolicyRuntimePlan {
	if p == nil {
		return nil
	}
	v := *p
	v.Ingress = cloneLANPolicyIngress(p.Ingress)
	return &v
}

func cloneLANPolicyIngress(v []LANPolicyIngress) []LANPolicyIngress {
	out := slices.Clone(v)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
		out[i].IncludedMACs = slices.Clone(out[i].IncludedMACs)
		out[i].ExcludedSources = slices.Clone(out[i].ExcludedSources)
		out[i].ExcludedMACs = slices.Clone(out[i].ExcludedMACs)
	}
	return out
}

func lanPolicyDigest(p *LANPolicyRuntimePlan) string {
	v := *p
	v.Digest = ""
	data, _ := json.Marshal(v)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func lanPolicyHash(v string) bool { return len(v) == 64 && strings.Trim(v, "0123456789abcdef") == "" }

func ValidateLANPolicyRuntime(p *LANPolicyRuntimePlan) error {
	return validateLANPolicyRuntime(p, true)
}

func validateLANPolicyRuntime(p *LANPolicyRuntimePlan, sealed bool) error {
	if p == nil || p.Schema != 1 || !lanPolicyHash(p.Generation) || len(p.Ingress) == 0 || len(p.Ingress) > 16 || sealed && p.Digest != lanPolicyDigest(p) {
		return ErrLANPolicyRuntime
	}
	interfaces, segments := map[string]bool{}, map[string]bool{}
	total := 0
	for _, g := range p.Ingress {
		if g.SegmentID == "" || len(g.SegmentID) > 128 || !proxyFirewallInterface.MatchString(g.Interface) || strings.Contains(g.Interface, "+") || g.Interface == "lo" || interfaces[g.Interface] || segments[g.SegmentID] || len(g.Sources) == 0 || len(g.Sources) > 1024 || len(g.ExcludedSources) > 128 || len(g.ExcludedMACs) > 128 || len(g.IncludedMACs) > 512 || !slices.Contains([]string{"all", "mac"}, g.Membership) || g.Membership == "mac" && len(g.IncludedMACs) == 0 || g.Membership == "all" && len(g.IncludedMACs) > 0 {
			return ErrLANPolicyRuntime
		}
		for _, owner := range PolicyOwnershipSpecs() {
			if g.Interface == owner.Interface {
				return ErrLANPolicyRuntime
			}
		}
		interfaces[g.Interface], segments[g.SegmentID] = true, true
		for _, list := range [][]string{g.Sources, g.ExcludedSources} {
			seen := map[string]bool{}
			for _, value := range list {
				prefix, err := netip.ParsePrefix(value)
				if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() || seen[value] {
					return ErrLANPolicyRuntime
				}
				seen[value] = true
			}
		}
		for _, list := range [][]string{g.ExcludedMACs, g.IncludedMACs} {
			seen := map[string]bool{}
			for _, mac := range list {
				hw, err := net.ParseMAC(mac)
				if err != nil || len(hw) != 6 || hw[0]&1 != 0 || hw.String() == "00:00:00:00:00:00" || strings.ToUpper(hw.String()) != mac || seen[mac] {
					return ErrLANPolicyRuntime
				}
				seen[mac] = true
			}
		}
		total += len(g.Sources) + len(g.ExcludedSources) + len(g.ExcludedMACs) + len(g.IncludedMACs)
	}
	if total > 2048 {
		return ErrLANPolicyRuntime
	}
	return nil
}

// LANPolicyMatch must constrain every owned DNS/proxy/NFQUEUE selector. The
// corresponding RPDB rules require the same positive mark AND exact iif.
func LANPolicyMatch() []string {
	return []string{"-m", "mark", "--mark", "0x20000000/0x28000000"}
}

// LANPolicyEffect is a neutral exact command pair for the shared durable
// addition receipt. Tool is a logical key, never an arbitrary executable path.
// No delete permission follows merely from seeing an identical kernel tuple.
type LANPolicyEffect struct {
	Tool   string   `json:"tool"`
	Add    []string `json:"add"`
	Delete []string `json:"delete"`
	Needs  []int    `json:"needs,omitempty"`
}

type lanPolicyChain struct {
	family int
	name   string
	jump   []string
	rules  [][]string
}

func lanPolicyChains(p *LANPolicyRuntimePlan) []lanPolicyChain {
	var result []lanPolicyChain
	for i, g := range p.Ingress {
		for _, family := range []int{4, 6} {
			c := lanPolicyChain{family: family, name: fmt.Sprintf("RZG_%s_%d_%d", p.Digest[:12], i, family)}
			c.jump = []string{"-i", g.Interface, "-j", c.name}
			// Clear ONLY our admission bits. A stale admitted packet cannot
			// inherit permission across an exclusion or scope replacement.
			c.rules = [][]string{{"-j", "MARK", "--set-xmark", "0x0/0x28000000"}}
			negative := func(match []string) {
				c.rules = append(c.rules, append(slices.Clone(match), "-j", "MARK", "--set-xmark", "0x08000000/0x28000000"))
			}
			for _, mac := range g.ExcludedMACs {
				negative([]string{"-m", "mac", "--mac-source", mac})
			}
			for _, value := range g.ExcludedSources {
				if strings.Contains(value, ":") == (family == 6) {
					negative([]string{"-s", value})
				}
			}
			c.rules = append(c.rules, []string{"-m", "mark", "--mark", "0x08000000/0x08000000", "-j", "RETURN"})
			for _, value := range g.Sources {
				if strings.Contains(value, ":") == (family == 6) {
					if g.Membership == "mac" {
						for _, mac := range g.IncludedMACs {
							c.rules = append(c.rules, []string{"-s", value, "-m", "mac", "--mac-source", mac, "-j", "MARK", "--set-xmark", "0x20000000/0x28000000"})
						}
					} else {
						c.rules = append(c.rules, []string{"-s", value, "-j", "MARK", "--set-xmark", "0x20000000/0x28000000"})
					}
				}
			}
			c.rules = append(c.rules, append(LANPolicyMatch(), "-j", "RETURN"))
			negative(nil) // source outside the selected prefix, on this ingress
			result = append(result, c)
		}
	}
	return result
}

func lanPolicyRules(p *LANPolicyRuntimePlan) []lanClassifierRule {
	var out []lanClassifierRule
	for _, family := range []int{4, 6} {
		out = append(out, lanClassifierRule{family: family, priority: LANPolicyAnchorPriority, source: "all", action: "nop"})
		for _, g := range p.Ingress {
			out = append(out, lanClassifierRule{family: family, priority: LANPolicySkipPriority, source: "all", action: "fwmark 0x8000000/0x8000000 iif " + g.Interface + " goto 73"})
		}
	}
	return out
}

func (p *LANPolicyRuntimePlan) Effects() ([]LANPolicyEffect, error) {
	if err := ValidateLANPolicyRuntime(p); err != nil {
		return nil, err
	}
	var effects []LANPolicyEffect
	count := 0
	for _, g := range p.Ingress {
		count += 2*(6+len(g.ExcludedMACs)) + len(g.ExcludedSources) + len(g.Sources)*max(1, len(g.IncludedMACs))
	}
	if count+2+2*len(p.Ingress) > 4096 {
		return nil, ErrLANPolicyRuntime
	}
	ready := []int{}
	anchors := map[int]int{}
	for _, rule := range lanPolicyRules(p) {
		idx := len(effects)
		needs := []int(nil)
		if rule.action == "nop" {
			anchors[rule.family] = idx
		} else {
			needs = []int{anchors[rule.family]}
		}
		effects = append(effects, LANPolicyEffect{Tool: "ip", Add: rule.args("add"), Delete: rule.args("del"), Needs: needs})
		ready = append(ready, idx)
	}
	for _, c := range lanPolicyChains(p) {
		tool := "iptables"
		if c.family == 6 {
			tool = "ip6tables"
		}
		previous := len(effects)
		effects = append(effects, LANPolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-N", c.name}, Delete: []string{"-t", "mangle", "-X", c.name}})
		for _, rule := range c.rules {
			effects = append(effects, LANPolicyEffect{Tool: tool, Add: append([]string{"-t", "mangle", "-A", c.name}, rule...), Delete: append([]string{"-t", "mangle", "-D", c.name}, rule...), Needs: []int{previous}})
			previous = len(effects) - 1
		}
		ready = append(ready, previous)
	}
	// Publish ingress only after both families and every anchor are prepared.
	for _, c := range lanPolicyChains(p) {
		tool := "iptables"
		if c.family == 6 {
			tool = "ip6tables"
		}
		effects = append(effects, LANPolicyEffect{Tool: tool, Add: append([]string{"-t", "mangle", "-I", "PREROUTING", "1"}, c.jump...), Delete: append([]string{"-t", "mangle", "-D", "PREROUTING"}, c.jump...), Needs: slices.Clone(ready)})
	}
	if len(effects) > 4096 {
		return nil, ErrLANPolicyRuntime
	}
	return effects, nil
}

// LANPolicyRuntime has no files, worker or standalone ownership. The common
// Manager participant supplies a durable Execute and physical ScopeCheck;
// both are required. Its private snapshot/receipt stores this exact plan.
type LANPolicyRuntime struct {
	Runner     NFQWS2Runner
	IP         string
	IPTables   string
	IP6Tables  string
	ScopeCheck func(context.Context, *LANPolicyRuntimePlan) error
	// TransportCheck proves the complete observed outer WG/AWG selector against
	// committed endpoint ownership, its receipt and fresh both-family inventory.
	// Only Verify consumes this proof; nil refuses and grants no service access.
	TransportCheck func(context.Context, *LANPolicyRuntimePlan, int, string) error
	// ConsumerCheck verifies exact other consumers' common receipts/generation.
	// It is needed when their positive mark selectors already exist at Verify.
	ConsumerCheck func(context.Context, *LANPolicyRuntimePlan) error
	Execute       func(context.Context, *LANPolicyRuntimePlan, []LANPolicyEffect) error
}

func (r *LANPolicyRuntime) command(tool string) string {
	switch tool {
	case "ip":
		return r.IP
	case "iptables":
		return r.IPTables
	case "ip6tables":
		return r.IP6Tables
	}
	return ""
}

func (r *LANPolicyRuntime) check(ctx context.Context, p *LANPolicyRuntimePlan) error {
	if err := r.checkTools(ctx, p); err != nil {
		return err
	}
	if r.ScopeCheck == nil {
		return ErrLANPolicyRuntime
	}
	if err := errors.Join(ctx.Err(), r.ScopeCheck(ctx, CloneLANPolicyRuntime(p))); err != nil {
		return err
	}
	return ctx.Err()
}

func (r *LANPolicyRuntime) checkTools(ctx context.Context, p *LANPolicyRuntimePlan) error {
	if err := ValidateLANPolicyRuntime(p); err != nil {
		return err
	}
	if r == nil || r.Runner == nil || r.IP == "" || r.IPTables == "" || r.IP6Tables == "" {
		return ErrLANPolicyRuntime
	}
	return ctx.Err()
}

// Activate never adds outside the shared addition receipt or retries an
// unknown effect. A receipt acknowledgement is followed by independent exact
// kernel readback before the owner may activate any other consumer.
func (r *LANPolicyRuntime) Activate(ctx context.Context, plan *LANPolicyRuntimePlan) error {
	p := CloneLANPolicyRuntime(plan)
	if err := r.check(ctx, p); err != nil {
		return err
	}
	if r.Execute == nil {
		return ErrLANPolicyRuntime
	}
	if err := r.Preflight(ctx, p); err != nil {
		return err
	}
	effects, err := p.Effects()
	if err != nil {
		return err
	}
	if err := r.Execute(ctx, CloneLANPolicyRuntime(p), effects); err != nil {
		return err // caller settles/rolls back through its existing receipt
	}
	return r.Verify(ctx, p)
}
