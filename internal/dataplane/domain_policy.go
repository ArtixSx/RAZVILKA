package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

var ErrDomainPolicy = errors.New("domain policy flow authority unavailable")

// Service definitions are supplied by the existing reviewed catalogue/route
// builder. Selected=false keeps a catalogue identity for explicit RU rules;
// it cannot acquire service override authority merely from a DNS answer.
type DomainPolicyService struct {
	ID             string
	Route          string
	Selected       bool
	Domains        []string
	DomainSuffixes []string // only these entries match subdomains
	CIDRs          []string
	Sources        []string
}

// NameSource may be application, tls-sni or quic-sni ONLY when the existing
// engine obtained it from this connection before selecting its outbound.
// Reverse DNS, the DNS observation ledger, ECH outer/public names and unknown
// fake-IP mappings are not accepted. Sniffing has connection granularity:
// coalesced encrypted requests cannot be independently routed by this API.
type DomainPolicyFlow struct {
	Client          autonomy.ClientPacket
	Destination     netip.Addr
	Protocol        string // tcp or udp
	Name            string
	NameSource      string
	NameState       DomainPolicyNameState
	Ambiguous       bool
	Coalesced       bool
	BeforeOutbound  bool
	DefaultCoverage string // same existing executor's coverage, never HTTP input
}

type DomainPolicyDecision struct {
	Generation string
	Kind       string // outside, baseline, default, service, refused, blocked, failed
	Route      string
	ServiceID  string
	Reason     string
	Decision   autonomy.NetworkDecision
}

type DomainPolicy struct {
	generation string
	policy     *config.NetworkPolicy
	scope      autonomy.ScopeObservation
	services   []DomainPolicyService
	guests     []string
}

func CompileDomainPolicy(generation string, policy *config.NetworkPolicy, scope autonomy.ScopeObservation, guestOptIn []string, services []DomainPolicyService, now time.Time) (*DomainPolicy, error) {
	if !lanPolicyHash(generation) || policy == nil || policy.Schema != 2 || config.ValidateAppliedNetworkPolicy(policy) != nil || len(services) > 128 || len(guestOptIn) > 16 || len(scope.Segments) > 16 || len(scope.Devices) > 512 || scope.BootID == "" || scope.NetworkID == "" || scope.Revision == 0 || now.IsZero() || now.Before(scope.ObservedAt) || !now.Before(scope.FreshUntil) || scope.FreshUntil.Sub(scope.ObservedAt) > 2*time.Minute {
		return nil, ErrDomainPolicy
	}
	p := &DomainPolicy{generation: generation, policy: config.CloneNetworkPolicy(policy), scope: cloneDomainPolicyScope(scope), services: slices.Clone(services), guests: slices.Clone(guestOptIn)}
	segments := map[string]autonomy.HomeSegment{}
	for i := range p.scope.Segments {
		s := &p.scope.Segments[i]
		if s.ID == "" || segments[s.ID].ID != "" {
			return nil, ErrDomainPolicy
		}
		if slices.Contains(p.policy.Clients.SegmentIDs, s.ID) && (!proxyFirewallInterface.MatchString(s.Interface) || s.Interface == "lo" || s.WAN || !s.Home && !slices.Contains(guestOptIn, s.ID)) {
			return nil, ErrDomainPolicy
		}
		if slices.Contains(guestOptIn, s.ID) && !s.WAN {
			s.Home = true // opt-in is bound to this immutable reviewed input
		}
		segments[s.ID] = *s
	}
	for _, id := range p.policy.Clients.SegmentIDs {
		s, ok := segments[id]
		if !ok || len(s.Prefixes) == 0 || len(s.Prefixes) > 16 {
			return nil, ErrDomainPolicy
		}
		for _, prefix := range s.Prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return nil, ErrDomainPolicy
			}
		}
	}
	seen := map[string]bool{}
	for i := range p.services {
		s := &p.services[i]
		if s.ID == "" || seen[s.ID] || len(s.Domains)+len(s.DomainSuffixes) > 256 || len(s.CIDRs) > 256 || len(s.Sources) > 128 || s.Selected && (adapterID(s.Route) == "" || adapterID(s.Route) == "auto") {
			return nil, ErrDomainPolicy
		}
		seen[s.ID] = true
		s.Domains, s.CIDRs, s.Sources = slices.Clone(s.Domains), slices.Clone(s.CIDRs), slices.Clone(s.Sources)
		s.DomainSuffixes = slices.Clone(s.DomainSuffixes)
		for _, name := range append(slices.Clone(s.Domains), s.DomainSuffixes...) {
			canonical, err := config.PolicyDomain(name)
			if err != nil || canonical != name {
				return nil, ErrDomainPolicy
			}
		}
		for _, list := range [][]string{s.CIDRs, s.Sources} {
			for _, value := range list {
				prefix, err := netip.ParsePrefix(value)
				if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
					return nil, ErrDomainPolicy
				}
			}
		}
	}
	return p, nil
}

func cloneDomainPolicyScope(scope autonomy.ScopeObservation) autonomy.ScopeObservation {
	scope.Segments = slices.Clone(scope.Segments)
	for i := range scope.Segments {
		scope.Segments[i].Prefixes = slices.Clone(scope.Segments[i].Prefixes)
	}
	scope.Devices = slices.Clone(scope.Devices)
	return scope
}

// The existing owner can renew its bounded physical observation without
// extending a stale review or introducing another refresh scheduler. Only
// freshness may change; changed boot/network/revision/device/segment identity
// requires a newly reviewed generation.
func (p *DomainPolicy) DecideWithScope(flow DomainPolicyFlow, current autonomy.ScopeObservation, now time.Time) DomainPolicyDecision {
	if p == nil {
		return DomainPolicyDecision{Kind: "refused", Reason: "SCOPE_UNAVAILABLE"}
	}
	current = cloneDomainPolicyScope(current)
	for i := range current.Segments {
		if slices.Contains(p.guests, current.Segments[i].ID) && !current.Segments[i].WAN {
			current.Segments[i].Home = true
		}
	}
	oldIdentity, newIdentity := cloneDomainPolicyScope(p.scope), cloneDomainPolicyScope(current)
	oldIdentity.ObservedAt, oldIdentity.FreshUntil = time.Time{}, time.Time{}
	newIdentity.ObservedAt, newIdentity.FreshUntil = time.Time{}, time.Time{}
	if !reflect.DeepEqual(oldIdentity, newIdentity) {
		return DomainPolicyDecision{Generation: p.generation, Kind: "refused", Reason: "SCOPE_IDENTITY_CHANGED"}
	}
	copy := *p
	copy.scope = current
	return copy.Decide(flow, now)
}

func domainPolicyName(flow DomainPolicyFlow) string {
	if flow.NameState != "" && flow.NameState != DomainPolicyNameVisible {
		return ""
	}
	if !flow.BeforeOutbound || flow.Ambiguous || flow.Coalesced || !slices.Contains([]string{"application", "tls-sni", "quic-sni"}, flow.NameSource) || flow.NameSource == "tls-sni" && flow.Protocol != "tcp" || flow.NameSource == "quic-sni" && flow.Protocol != "udp" {
		return ""
	}
	name, err := config.PolicyDomain(flow.Name)
	if err != nil {
		return ""
	}
	return name
}

func (p *DomainPolicy) Decide(flow DomainPolicyFlow, now time.Time) DomainPolicyDecision {
	d := DomainPolicyDecision{Kind: "refused", Reason: "FLOW_AUTHORITY_UNAVAILABLE"}
	if p == nil {
		return d
	}
	d.Generation = p.generation
	q := autonomy.TrafficQuestion{Client: flow.Client, Address: flow.Destination, DefaultCoverage: flow.DefaultCoverage}
	// Negative client/guest scope is evaluated before flow metadata. Even an
	// invalid or adversarial name cannot re-admit an excluded MAC/address.
	gate := autonomy.DecideNetworkPolicy(p.policy, p.scope, q, now)
	d.Decision = gate
	if slices.Contains([]string{"OUTSIDE_SCOPE", "DEVICE_EXCLUDED", "ADDRESS_EXCLUDED"}, gate.Reason) {
		d.Kind, d.Reason = "outside", gate.Reason
		return d
	}
	if gate.Reason == "SCOPE_UNAVAILABLE" || gate.Reason == "POLICY_INVALID" {
		d.Reason = gate.Reason
		return d
	}
	if !flow.Destination.IsValid() || flow.Destination.Is4In6() || flow.Destination.Zone() != "" || !slices.Contains([]string{"tcp", "udp"}, flow.Protocol) {
		return d
	}
	q.Domain = domainPolicyName(flow)
	var match *DomainPolicyService
	for i := range p.services {
		s := &p.services[i]
		matched := false
		for _, name := range s.Domains {
			matched = matched || q.Domain != "" && q.Domain == name
		}
		for _, name := range s.DomainSuffixes {
			matched = matched || q.Domain != "" && (q.Domain == name || strings.HasSuffix(q.Domain, "."+name))
		}
		for _, value := range s.CIDRs {
			matched = matched || netip.MustParsePrefix(value).Contains(flow.Destination)
		}
		if !matched {
			continue
		}
		if len(s.Sources) > 0 {
			inside := false
			for _, value := range s.Sources {
				inside = inside || netip.MustParsePrefix(value).Contains(flow.Client.Address)
			}
			if !inside {
				continue
			} // override miss continues default
		}
		if match != nil && (match.ID != s.ID || match.Route != s.Route) {
			d.Reason = "AMBIGUOUS_SERVICE_DEFINITION"
			return d
		}
		match = s
	}
	if match != nil {
		q.ServiceID, q.ServiceSelected, q.ServiceSources = match.ID, match.Selected, match.Sources
	}
	d.Decision = autonomy.DecideNetworkPolicy(p.policy, p.scope, q, now)
	d.Reason = d.Decision.Reason
	// The complete shared question must settle an IP/domain rule conflict
	// before an IP-direct exception can be honored. With no visible name,
	// an explicit IP/CIDR direct rule still supplies independent authority.
	// Other mandatory domain-direct exceptions cannot be promised for an
	// opaque flow by labelling a shared CDN address or silently taking default.
	if q.Domain == "" && !(d.Decision.Action == "base" && d.Decision.Reason == "MANUAL_DIRECT") && p.opaqueDirectApplies(gate.DeviceID, flow.Client.Address) {
		d.Reason = "EXPLICIT_DOMAIN_DIRECT_REQUIRES_FLOW_IDENTITY"
		return d
	}
	switch d.Decision.Action {
	case "base":
		d.Kind, d.Route = "baseline", "direct"
	case "blocked":
		d.Kind = "blocked"
	case "bypass":
		if d.Decision.Target == "service" && match != nil {
			d.Kind, d.Route, d.ServiceID = "service", match.Route, match.ID
		} else {
			d.Kind, d.Route = "default", p.policy.Traffic.DefaultRoute
		}
	default:
		d.Kind = "refused"
	}
	return d
}

func (p *DomainPolicy) opaqueDirectApplies(device string, source netip.Addr) bool {
	if p.policy.Russian.Enabled {
		return true
	}
	for _, rule := range p.policy.Rules {
		if rule.Action == "direct" && (rule.Kind == "exact" || rule.Kind == "suffix") && (len(rule.DeviceIDs) == 0 || slices.Contains(rule.DeviceIDs, device)) {
			return true
		}
	}
	for _, service := range p.services {
		if !service.Selected || service.Route != "direct" || len(service.Domains)+len(service.DomainSuffixes) == 0 {
			continue
		}
		if len(service.Sources) == 0 {
			return true
		}
		for _, value := range service.Sources {
			if netip.MustParsePrefix(value).Contains(source) {
				return true
			}
		}
	}
	return false
}

// Dispatch is called by the existing engine before forwarding the flow. The
// shared guard fences generation/control/gate readback; outbound failure is a
// typed failed decision and never converted to service miss/default/direct.
// It has no listener, scheduler, journal or independent network owner.
func (p *DomainPolicy) Dispatch(ctx context.Context, flow DomainPolicyFlow, now time.Time, guard func(context.Context, string) error, outbound func(context.Context, DomainPolicyDecision) error) (DomainPolicyDecision, error) {
	if p == nil || guard == nil || outbound == nil {
		return DomainPolicyDecision{Kind: "refused"}, ErrDomainPolicy
	}
	if err := errors.Join(ctx.Err(), guard(ctx, p.generation)); err != nil {
		return DomainPolicyDecision{Generation: p.generation, Kind: "refused"}, err
	}
	d := p.Decide(flow, now)
	if d.Kind == "refused" || d.Kind == "blocked" {
		return d, ErrDomainPolicy
	}
	if d.Kind == "outside" {
		return d, nil
	} // no owned action, including DNS/NFQUEUE
	if err := errors.Join(ctx.Err(), guard(ctx, p.generation)); err != nil {
		d.Kind = "refused"
		return d, err
	}
	if err := outbound(ctx, d); err != nil {
		d.Kind, d.Reason = "failed", "OUTBOUND_EXECUTION_FAILED"
		return d, err
	}
	return d, nil
}
