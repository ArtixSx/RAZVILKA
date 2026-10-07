package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

var ErrNFQWSScopedOwner = errors.New("scoped NFQWS owner unavailable or mismatched")

// Caller-facing capability diagnostic only. Missing inventory never grants an
// empty namespace, process launch, queue reservation or cleanup permission.
var ErrNFQWSScopedQueueInventory = errors.New("NFQUEUE kernel inventory unavailable; install or load nfnetlink_queue for this kernel and repeat preflight")

// NFQWSScopedCandidate is compiler input from the frozen managed-payload and
// candidate review. None of these strings is an executable or receipt path.
// ArgumentsSHA256 includes the real executable argv[0] and the reserved qnum.
type NFQWSScopedCandidate struct {
	ID, Incarnation, ArgumentsSHA256 string
	Traffic                          []NFQWSScopedTraffic
}

type NFQWSScopedTraffic struct {
	Protocol    string
	First, Last uint16
}

// This reservation must come from the existing Execution resource registrar.
// The compiler never searches for a free queue or adopts a current occupant.
type NFQWSScopedSpec struct {
	Queue                           uint16
	BootID, NetNamespace, SessionID string
	CommandSHA256                   string
	Candidate                       NFQWSScopedCandidate
}

type NFQWSScopedResources struct {
	Queue                                   uint16
	NetNamespace, Generation, LANDigest     string
	PlanID, PlanDigest, NetworkProfileID    string
	CandidateID, Incarnation, ArgumentsHash string
	Revision                                uint64
	Chains                                  []string
	BootID, SessionID, CommandSHA256        string
}

// Exact process evidence returned from the existing ownership.json session.
// This public metadata is never accepted as an admission or deletion grant.
type NFQWSScopedProcessProof struct {
	SessionID, CommandSHA256 string
	Receipt                  components.NFQWSSupervisionReceipt
	Child                    components.NFQWSRuntimeProcessIdentity
	Acknowledged             bool
}

type nfqwsScopedChain struct {
	tool  PolicyEffectTool
	name  string
	body  [][]string
	jumps [][]string
}

// NFQWSScopedPlan is opaque immutable compiler intent for the existing Manager
// transaction. It owns no journal, admission, process, scheduler or lifetime.
type NFQWSScopedPlan struct {
	resources NFQWSScopedResources
	spec      NFQWSScopedSpec
	lan       *LANPolicyRuntimePlan
	chains    []nfqwsScopedChain
	mixed     PolicyEffectPlan
	digest    string
}

// Spec returns detached compiler input for the SAME typed Execution record.
// Recovery reconstructs Effects from expected Plan + this spec; persisted
// command arrays never become execution or deletion authority.
func (p *NFQWSScopedPlan) Spec() NFQWSScopedSpec {
	if p == nil {
		return NFQWSScopedSpec{}
	}
	spec := p.spec
	spec.Candidate.Traffic = slices.Clone(spec.Candidate.Traffic)
	return spec
}

func (p *NFQWSScopedPlan) Resources() NFQWSScopedResources {
	if p == nil {
		return NFQWSScopedResources{}
	}
	r := p.resources
	r.Chains = slices.Clone(r.Chains)
	return r
}

func (p *NFQWSScopedPlan) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

func (p *NFQWSScopedPlan) Effects() (PolicyEffectPlan, error) {
	if p == nil || p.digest == "" {
		return PolicyEffectPlan{}, ErrNFQWSScopedOwner
	}
	copy, hash, err := copyPolicyEffectPlan(p.mixed)
	if err != nil || hash != p.digest {
		return PolicyEffectPlan{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return copy, nil
}

func nfqwsScopedNamespace(s string) bool {
	if !strings.HasPrefix(s, "net:[") || !strings.HasSuffix(s, "]") {
		return false
	}
	v := s[5 : len(s)-1]
	n, err := strconv.ParseUint(v, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}

func nfqwsScopedPrefix(value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil || p != p.Masked() || p.String() != value || p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return netip.Prefix{}, ErrNFQWSScopedOwner
	}
	return p, nil
}

func nfqwsScopedPublic(p netip.Prefix) bool {
	// A broad prefix that also contains protected destinations is refused.
	// The common policy compiler supplies its already carved public cells.
	for _, v := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8"} {
		if p.Overlaps(netip.MustParsePrefix(v)) {
			return false
		}
	}
	return true
}

// CompileNFQWSScopedPlan consumes trusted immutable Manager intent. Current
// review/WAN/Stop and the registrar lease are checked by the binding at every
// actual effect boundary. Passing typed input alone grants no authority.
func CompileNFQWSScopedPlan(expected Plan, spec NFQWSScopedSpec) (*NFQWSScopedPlan, error) {
	candidate := spec.Candidate
	if expected.SchemaVersion != SchemaVersion || expected.PlanID == "" || len(expected.PlanID) > 128 || !lanPolicyHash(expected.Digest) || expected.Revision == 0 || expected.NetworkProfileID == "" || len(expected.NetworkProfileID) > 128 || !expected.Ready || expected.SafeMode || expected.Noop || len(expected.Blockers) != 0 || len(expected.ResourceConflicts) != 0 || spec.Queue == 0 || !nfqwsScopedNamespace(spec.NetNamespace) || !nfqws2ManagedBoot(spec.BootID) || !nfqws2ManagedHex(spec.SessionID, 32) || !lanPolicyHash(spec.CommandSHA256) || ValidateLANPolicyRuntime(expected.LAN) != nil || candidate.ID == "" || len(candidate.ID) > 128 || strings.ContainsAny(candidate.ID, "\x00\r\n") || len(candidate.Incarnation) != 32 || strings.Trim(candidate.Incarnation, "0123456789abcdef") != "" || !lanPolicyHash(candidate.ArgumentsSHA256) || len(candidate.Traffic) == 0 || len(candidate.Traffic) > 16 || len(expected.Routes) == 0 || len(expected.Routes) > 1024 {
		return nil, ErrNFQWSScopedOwner
	}
	// Bound nested input before copying or marshaling any caller slices.
	total := 0
	for _, r := range expected.Routes {
		if len(r.Sources) > 1024 || len(r.CIDRs) > 2048 || len(r.Ingress) > 16 || len(r.Domains) > 1024 || len(r.SourceRefs) > 1024 || len(r.ServiceID) > 128 || len(r.ServiceName) > 512 || len(r.Selected) > 256 || len(r.Resolved) > 256 || len(r.NetworkPolicyGeneration) > 64 || len(r.NetworkPolicyRole) > 32 || len(r.ProbeURL) > 4096 || len(r.AppliedRoute) > 256 {
			return nil, ErrNFQWSScopedOwner
		}
		for _, values := range [][]string{r.Sources, r.CIDRs, r.Ingress, r.Domains, r.SourceRefs} {
			for _, v := range values {
				total += len(v) + 8
				if len(v) > 512 || total > 128<<10 {
					return nil, ErrNFQWSScopedOwner
				}
			}
		}
	}
	p := &NFQWSScopedPlan{lan: CloneLANPolicyRuntime(expected.LAN)}
	p.resources = NFQWSScopedResources{Queue: spec.Queue, NetNamespace: spec.NetNamespace, Generation: p.lan.Generation, LANDigest: p.lan.Digest, PlanID: expected.PlanID, PlanDigest: expected.Digest, NetworkProfileID: expected.NetworkProfileID, Revision: expected.Revision, CandidateID: candidate.ID, Incarnation: candidate.Incarnation, ArgumentsHash: candidate.ArgumentsSHA256, BootID: spec.BootID, SessionID: spec.SessionID, CommandSHA256: spec.CommandSHA256}
	traffic := slices.Clone(candidate.Traffic)
	sort.Slice(traffic, func(i, j int) bool {
		if traffic[i].Protocol != traffic[j].Protocol {
			return traffic[i].Protocol < traffic[j].Protocol
		}
		return traffic[i].First < traffic[j].First
	})
	for i, t := range traffic {
		if t.Protocol != "tcp" && t.Protocol != "udp" || t.First == 0 || t.Last < t.First || i > 0 && traffic[i-1].Protocol == t.Protocol && traffic[i-1].Last >= t.First {
			return nil, ErrNFQWSScopedOwner
		}
	}
	p.spec = spec
	p.spec.Candidate.Traffic = slices.Clone(traffic)
	// Hash the complete frozen input, including incarnation and WAN, for names.
	data, err := json.Marshal(struct {
		Resources NFQWSScopedResources
		Routes    []Route
		Traffic   []NFQWSScopedTraffic
	}{p.resources, cloneNetworkPolicyRoutes(expected.Routes), traffic})
	if err != nil || len(data) > 256<<10 || len(expected.Routes) > 1024 {
		return nil, ErrNFQWSScopedOwner
	}
	nameHash := routeidentity.Hash(append([]byte("nfqws-scoped-v1\x00"), data...))
	seen := map[string]bool{}
	for _, family := range []int{4, 6} {
		c := nfqwsScopedChain{tool: PolicyEffectIPTables, name: fmt.Sprintf("RZQ_%s_%d", nameHash[:18], family)}
		if family == 6 {
			c.tool = PolicyEffectIP6Tables
		}
		interfaces := map[string]bool{}
		for _, route := range expected.Routes {
			if AdapterID(route.Resolved) != "nfqws2" {
				continue
			}
			// DNS-observed IPs are not a domain dispatch authority. The common
			// domain-flow compiler must supply its own executable binding later.
			if route.NetworkPolicyGeneration != p.lan.Generation || len(route.Domains) != 0 || len(route.Ingress) == 0 || len(route.Sources) == 0 || len(route.CIDRs) == 0 {
				return nil, ErrNFQWSScopedOwner
			}
			for _, iface := range route.Ingress {
				var ingress *LANPolicyIngress
				for i := range p.lan.Ingress {
					if p.lan.Ingress[i].Interface == iface {
						ingress = &p.lan.Ingress[i]
					}
				}
				if ingress == nil {
					return nil, ErrNFQWSScopedOwner
				}
				for _, value := range route.Sources {
					source, err := nfqwsScopedPrefix(value)
					if err != nil {
						return nil, err
					}
					contained := false
					for _, allowed := range ingress.Sources {
						a := netip.MustParsePrefix(allowed)
						contained = contained || a.Contains(source.Addr()) && a.Bits() <= source.Bits() && a.Addr().BitLen() == source.Addr().BitLen()
					}
					if !contained {
						return nil, ErrNFQWSScopedOwner
					}
					for _, value := range route.CIDRs {
						destination, err := nfqwsScopedPrefix(value)
						if err != nil || !nfqwsScopedPublic(destination) {
							return nil, ErrNFQWSScopedOwner
						}
						if source.Addr().BitLen() != destination.Addr().BitLen() || destination.Addr().Is6() != (family == 6) {
							continue
						}
						for _, t := range traffic {
							port := strconv.Itoa(int(t.First))
							if t.Last != t.First {
								port += ":" + strconv.Itoa(int(t.Last))
							}
							rule := []string{"-i", iface, "-s", source.String(), "-d", destination.String()}
							rule = append(rule, LANPolicyMatch()...)
							rule = append(rule, "-p", t.Protocol, "-m", t.Protocol, "--dport", port, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(spec.Queue)))
							key := string(c.tool) + "\x00" + strings.Join(rule, "\x00")
							if !seen[key] {
								seen[key] = true
								c.body = append(c.body, rule)
								interfaces[iface] = true
								if len(seen) > 2048 {
									return nil, ErrNFQWSScopedOwner
								}
							}
						}
					}
				}
			}
		}
		if len(c.body) == 0 {
			continue
		}
		sort.Slice(c.body, func(i, j int) bool { return strings.Join(c.body[i], "\x00") < strings.Join(c.body[j], "\x00") })
		for _, iface := range sortedMapKeys(interfaces) {
			jump := append([]string{"-i", iface}, LANPolicyMatch()...)
			c.jumps = append(c.jumps, append(jump, "-j", c.name))
		}
		p.chains = append(p.chains, c)
		p.resources.Chains = append(p.resources.Chains, c.name)
	}
	if len(p.chains) == 0 {
		return nil, ErrNFQWSScopedOwner
	}
	p.mixed.Generation = p.lan.Generation
	ready := []int{}
	for _, c := range p.chains {
		last := len(p.mixed.Effects)
		p.mixed.Effects = append(p.mixed.Effects, PolicyEffect{Tool: c.tool, Add: []string{"-t", "mangle", "-N", c.name}, Delete: []string{"-t", "mangle", "-X", c.name}})
		for _, rule := range c.body {
			p.mixed.Effects = append(p.mixed.Effects, PolicyEffect{Tool: c.tool, Add: append([]string{"-t", "mangle", "-A", c.name}, rule...), Delete: append([]string{"-t", "mangle", "-D", c.name}, rule...), Needs: []int{last}})
			last = len(p.mixed.Effects) - 1
		}
		ready = append(ready, last)
	}
	for _, c := range p.chains {
		for _, jump := range c.jumps {
			p.mixed.Effects = append(p.mixed.Effects, PolicyEffect{Tool: c.tool, Add: append([]string{"-t", "mangle", "-A", "FORWARD"}, jump...), Delete: append([]string{"-t", "mangle", "-D", "FORWARD"}, jump...), Needs: slices.Clone(ready)})
		}
	}
	p.digest, err = PolicyEffectPlanDigest(p.mixed)
	if err != nil {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return p, nil
}

func sortedMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// NFQWSScopedBinding consumes an already retained common Execution. Guards
// must check the registrar's exact resources, generation, candidate, WAN and
// current admission. Runner MUST consume CORE authority at actual Cmd.Start.
// CleanupGuard is a separate receipt-owned grant and remains valid after Stop.
// Process callbacks must use the existing exact managed session (ECHILD/ACK),
// never init status, a PID file, process enumeration or /proc absence alone.
type NFQWSScopedBinding struct {
	Runner          NFQWS2Runner
	Tools           PolicyEffectTools
	ApplyGuard      func(context.Context, *NFQWSScopedPlan, PolicyEffect) error
	CleanupGuard    func(context.Context, *NFQWSScopedPlan, PolicyEffect) error
	VerifyLAN       func(context.Context, *LANPolicyRuntimePlan) error
	ProcessRunning  func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error)
	ProcessInactive func(context.Context, *NFQWSScopedPlan) (NFQWSScopedProcessProof, error)
	QueueCheck      func(context.Context, string, uint16, *components.NFQWSRuntimeProcessIdentity) error
	// Checks other kernel backends (including nftables) and the exact physical
	// namespace of Runner. Unknown or overlapping foreign capture must refuse.
	AdditionalReadback func(context.Context, *NFQWSScopedPlan) error
	// Only the private after-Start phase observes empty -> exact ready owned.
	// Strict pre-Start, Prepared, Apply and cleanup still use QueueCheck.
	queueReadiness func(context.Context, string, uint16, *components.NFQWSRuntimeProcessIdentity) (bool, error)
	options        policyAdditionOptions
}

func (b *NFQWSScopedBinding) prepare(p *NFQWSScopedPlan, cleanup bool) (PolicyEffectRuntime, PolicyEffectPlan, error) {
	if b == nil || b.Runner == nil || b.ApplyGuard == nil || b.CleanupGuard == nil || b.VerifyLAN == nil || b.ProcessRunning == nil || b.ProcessInactive == nil || b.QueueCheck == nil || b.AdditionalReadback == nil || b.Tools.IPTables == "" || b.Tools.IP6Tables == "" {
		return PolicyEffectRuntime{}, PolicyEffectPlan{}, ErrNFQWSScopedOwner
	}
	plan, err := p.Effects()
	if err != nil {
		return PolicyEffectRuntime{}, PolicyEffectPlan{}, err
	}
	guard := b.ApplyGuard
	if cleanup {
		guard = b.CleanupGuard
	}
	r := PolicyEffectRuntime{Runner: b.Runner, Tools: b.Tools}
	r.Guard = func(ctx context.Context, i int) error {
		if ctx == nil || i < 0 || i >= len(plan.Effects) {
			return ErrNFQWSScopedOwner
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard(ctx, p, cloneNFQWSScopedEffect(plan.Effects[i])); err != nil {
			return err
		}
		if cleanup {
			return b.readback(ctx, p, nfqwsScopedCleanup, -1)
		}
		return ctx.Err()
	}
	r.Preflight = func(ctx context.Context) error { return b.readback(ctx, p, nfqwsScopedNew, -1) }
	r.ExactPresence = func(ctx context.Context, i int) (int, error) { return b.inspect(ctx, p, i) }
	r.BeforeDelete = func(ctx context.Context, i int) error {
		if err := b.checkProcess(ctx, p, true); err != nil {
			return err
		}
		if _, err := b.inspect(ctx, p, i); err != nil {
			return err
		}
		return b.beforeDelete(ctx, p, i)
	}
	return r, plan, nil
}

func cloneNFQWSScopedEffect(e PolicyEffect) PolicyEffect {
	e.Add, e.Delete, e.Needs = slices.Clone(e.Add), slices.Clone(e.Delete), slices.Clone(e.Needs)
	return e
}

// Apply publishes attachments only after both families' complete bodies and a
// fresh exact running process/queue/LAN check. root is the common Execution's
// retained participant receipt root; this binding creates no second ledger.
func (b *NFQWSScopedBinding) Apply(ctx context.Context, p *NFQWSScopedPlan, root string) error {
	r, plan, err := b.prepare(p, false)
	if err != nil {
		return err
	}
	// Admission Guards stay fresh without repeating whole namespace scans.
	// Only this private Apply runner moves the full exact-prefix proof to the
	// actual mutation boundary; the base runner still owns Cmd.Start admission.
	r.Runner = nfqwsScopedApplyRunner{base: r.Runner, binding: b, scoped: p, plan: plan, tools: r.Tools, guard: r.Guard}
	if err := applyPolicyEffects(ctx, r, plan, root, b.options); err != nil {
		return err
	}
	// The final external admission callback precedes the final full proof.
	// Its nominal success must not hide a removed body or newly foreign rule.
	if err := r.Guard(ctx, len(plan.Effects)-1); err != nil {
		return err
	}
	return b.readback(ctx, p, nfqwsScopedComplete, -1)
}

func (b *NFQWSScopedBinding) Remove(ctx context.Context, p *NFQWSScopedPlan, root string) error {
	r, plan, err := b.prepare(p, true)
	if err != nil {
		return err
	}
	if err := b.checkProcess(ctx, p, true); err != nil {
		return err
	}
	if err := b.readback(ctx, p, nfqwsScopedCleanup, -1); err != nil {
		return err
	}
	if err := removePolicyEffects(ctx, r, plan, root, b.options); err != nil {
		return err
	}
	return b.VerifyInactive(ctx, p, root)
}

func (b *NFQWSScopedBinding) Inspect(ctx context.Context, p *NFQWSScopedPlan, root string) (PolicyAdditionStatus, error) {
	_, plan, err := b.prepare(p, true)
	if err != nil {
		return PolicyAdditionStatus{}, err
	}
	return nfqwsScopedInspectReceipt(ctx, plan, root, b.options)
}

// VerifyInactive is a fresh read-only whole-owner check. A removed receipt
// alone, a settled process alone, or absence of one IPv4 attachment cannot pass.
func (b *NFQWSScopedBinding) VerifyInactive(ctx context.Context, p *NFQWSScopedPlan, root string) error {
	r, plan, err := b.prepare(p, true)
	if err != nil {
		return err
	}
	if err := r.Guard(ctx, 0); err != nil {
		return err
	}
	status, err := nfqwsScopedInspectReceipt(ctx, plan, root, b.options)
	if err != nil || !status.Removed || status.Unknown || status.Promoted {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := b.readback(ctx, p, nfqwsScopedAbsent, -1); err != nil {
		return err
	}
	after, err := nfqwsScopedInspectReceipt(ctx, plan, root, b.options)
	if err != nil || status != after {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return r.Guard(ctx, 0)
}
