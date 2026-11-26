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
	return compileDomainPolicy(generation, policy, scope, guestOptIn, services, now, true)
}

// Retained intent may be inventoried during Stop/recovery; only the public
// compiler can produce a new executable list-mode definition.
func compileDomainPolicy(generation string, policy *config.NetworkPolicy, scope autonomy.ScopeObservation, guestOptIn []string, services []DomainPolicyService, now time.Time, listOnly bool) (*DomainPolicy, error) {
	if !lanPolicyHash(generation) || policy == nil || config.ValidateAppliedNetworkPolicy(policy) != nil || listOnly && policy.Traffic.Mode != "selected_services" || len(services) > 128 || len(guestOptIn) > 16 || len(scope.Segments) > 16 || len(scope.Devices) > 512 || scope.BootID == "" || scope.NetworkID == "" || scope.Revision == 0 || now.IsZero() || now.Before(scope.ObservedAt) || !now.Before(scope.FreshUntil) || scope.FreshUntil.Sub(scope.ObservedAt) > 2*time.Minute {
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
	if listOnly {
		set, err := config.EffectiveResourceExclusions(p.policy)
		if err != nil {
			return nil, ErrDomainPolicy
		}
		for _, list := range [][]config.ResourceMatch{set.Manual, set.Russian} {
			for _, match := range list {
				if match.Kind == "service" && !seen[match.Value] {
					return nil, ErrDomainPolicy // omitted catalogue identity cannot waive an exclusion
				}
			}
		}
		for _, rule := range set.LegacyRules {
			if rule.Kind == "service" && !seen[rule.Value] {
				return nil, ErrDomainPolicy
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
	negative := autonomy.DecideNetworkPolicy(p.policy, p.scope, q, now)
	if negative.Reason == "RESOURCE_IDENTITY_UNAVAILABLE" || negative.Reason == "RESOURCE_EXCLUSIONS_UNAVAILABLE" {
		d.Decision, d.Reason = negative, negative.Reason
		return d
	}
	if negative.Action == "base" && slices.Contains([]string{"MANUAL_DIRECT", "RU_CATALOG_DIRECT", "RESOURCE_EXCLUDED"}, negative.Reason) {
		d.Decision, d.Kind, d.Route, d.Reason = negative, "baseline", "direct", negative.Reason
		return d
	}
	// Catalogue exclusions are independent of positive selection and source
	// scope. Check every matching identity before resolving active overlaps.
	for i := range p.services {
		s := &p.services[i]
		if !domainPolicyServiceMatches(*s, q.Domain, flow.Destination) {
			continue
		}
		identity := q
		identity.ServiceID = s.ID
		negative = autonomy.DecideNetworkPolicy(p.policy, p.scope, identity, now)
		if negative.Reason == "RESOURCE_IDENTITY_UNAVAILABLE" || negative.Reason == "RESOURCE_EXCLUSIONS_UNAVAILABLE" {
			d.Decision, d.Reason = negative, negative.Reason
			return d
		}
		if negative.Action == "base" && slices.Contains([]string{"RU_CATALOG_DIRECT", "RESOURCE_EXCLUDED", "MANUAL_DIRECT"}, negative.Reason) {
			d.Decision, d.Kind, d.Route, d.Reason = negative, "baseline", "direct", negative.Reason
			return d
		}
	}
	var match *DomainPolicyService
	for i := range p.services {
		s := &p.services[i]
		if !s.Selected || !domainPolicyServiceMatches(*s, q.Domain, flow.Destination) {
			continue
		}
		if len(s.Sources) > 0 {
			inside := false
			for _, value := range s.Sources {
				inside = inside || netip.MustParsePrefix(value).Contains(flow.Client.Address)
			}
			if !inside {
				continue
			} // scan the other applicable active entries
		}
		if match != nil && match.Route != s.Route {
			d.Reason = "AMBIGUOUS_SERVICE_DEFINITION"
			return d
		}
		if match == nil || s.ID < match.ID {
			match = s
		}
	}
	if match != nil {
		q.ServiceID, q.ServiceSelected, q.ServiceSources = match.ID, match.Selected, match.Sources
	}
	d.Decision = autonomy.DecideNetworkPolicy(p.policy, p.scope, q, now)
	d.Reason = d.Decision.Reason
	// An unmatched opaque flow stays on baseline. An IP positive cannot
	// capture a shared address while domain negatives remain unobservable.
	if q.Domain == "" && d.Decision.Action == "bypass" && p.opaqueDirectApplies(gate.DeviceID, flow.Client.Address) {
		d.Reason = "EXPLICIT_DOMAIN_DIRECT_REQUIRES_FLOW_IDENTITY"
		return d
	}
	switch d.Decision.Action {
	case "base":
		d.Kind, d.Route = "baseline", "direct"
	case "blocked":
		d.Kind = "blocked"
	case "bypass":
		if d.Decision.Target == "service" && match != nil && match.Selected && match.Route != "" {
			d.Kind, d.Route, d.ServiceID = "service", match.Route, match.ID
		} else {
			d.Kind, d.Reason = "refused", "LIST_ROUTE_UNAVAILABLE"
		}
	default:
		d.Kind = "refused"
	}
	return d
}

func domainPolicyServiceMatches(s DomainPolicyService, domain string, address netip.Addr) bool {
	matched := domain != "" && slices.Contains(s.Domains, domain)
	for _, suffix := range s.DomainSuffixes {
		matched = matched || domain != "" && (domain == suffix || strings.HasSuffix(domain, "."+suffix))
	}
	for _, value := range s.CIDRs {
		matched = matched || netip.MustParsePrefix(value).Contains(address)
	}
	return matched
}

func (p *DomainPolicy) opaqueDirectApplies(device string, source netip.Addr) bool {
	set, err := config.EffectiveResourceExclusions(p.policy)
	if err != nil || len(set.BroadTLDs) != 0 {
		return true
	}
	for _, list := range [][]config.ResourceMatch{set.Manual, set.Russian} {
		for _, match := range list {
			if match.Kind == "exact" || match.Kind == "suffix" || match.Kind == "service" {
				return true
			}
		}
	}
	for _, rule := range p.policy.Rules {
		if rule.Action == "direct" && (rule.Kind == "exact" || rule.Kind == "suffix" || rule.Kind == "service") && (len(rule.DeviceIDs) == 0 || slices.Contains(rule.DeviceIDs, device)) {
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
