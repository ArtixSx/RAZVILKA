package app

import (
	"net"
	"net/netip"
	"slices"
)

type DefaultRouteDecisionKind string

const (
	DefaultRouteOutside  DefaultRouteDecisionKind = "OutsideOwnedScope"
	DefaultRouteExcluded DefaultRouteDecisionKind = "ExplicitBaselineExclusion"
	DefaultRouteBaseline DefaultRouteDecisionKind = "UnmatchedBaseline"
	DefaultRouteDefault  DefaultRouteDecisionKind = "Default"
	DefaultRouteOverride DefaultRouteDecisionKind = "ServiceOverride"
	DefaultRouteRefused  DefaultRouteDecisionKind = "CapabilityRefused"
	DefaultRouteFailed   DefaultRouteDecisionKind = "ExecutionFailed"
)

// FlowName is metadata of this connection, never a cached DNS name for its IP.
// The IP-only capability does not use either name as a routing discriminator.
// A future domain bridge must authenticate its own flow-metadata source.
type DefaultRouteFlow struct {
	Ingress                   string
	Source, Destination       netip.Addr
	MAC                       string
	FlowName, DNSObservedName string
	Protocol                  string
	DestinationPort           uint16
}

type DefaultRouteDecision struct {
	Kind                         DefaultRouteDecisionKind
	Route, ServiceID, Generation string
}

// Classify is a diagnostic/reference oracle for the compiled kernel policy.
// It never installs rules, promises packet success or grants execution rights.
func (c *DefaultRouteCompilation) Classify(flow DefaultRouteFlow) DefaultRouteDecision {
	d := DefaultRouteDecision{Kind: DefaultRouteRefused}
	if c == nil {
		return d
	}
	d.Kind, d.Generation = DefaultRouteOutside, c.digest
	if !flow.Source.IsValid() || !flow.Destination.IsValid() || flow.Source.Is4In6() || flow.Destination.Is4In6() || flow.Source.Zone() != "" || flow.Destination.Zone() != "" || flow.Source.Is4() != flow.Destination.Is4() {
		d.Kind = DefaultRouteRefused
		return d
	}
	if len(c.ingress) == 0 && len(c.rules) == 0 {
		d.Kind = DefaultRouteBaseline
		return d
	}
	var gate *DefaultRouteIngress
	for i := range c.ingress {
		if c.ingress[i].Interface == flow.Ingress {
			gate = &c.ingress[i]
			break
		}
	}
	if gate == nil {
		return d
	}
	if len(gate.ExcludedMACs) > 0 || len(gate.IncludedMACs) > 0 {
		mac, err := net.ParseMAC(flow.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			d.Kind = DefaultRouteRefused
			return d
		}
		if slices.Contains(gate.ExcludedMACs, mac.String()) {
			d.Kind = DefaultRouteExcluded
			return d
		}
		if len(gate.IncludedMACs) > 0 && !slices.Contains(gate.IncludedMACs, mac.String()) {
			return d
		}
	}
	if !defaultRouteContains(gate.Sources, flow.Source) {
		return d
	}
	if defaultRouteContains(gate.ExcludedSources, flow.Source) {
		d.Kind = DefaultRouteExcluded
		return d
	}
	public, err := defaultRoutePublic(c.policy)
	if err != nil {
		d.Kind = DefaultRouteRefused
		return d
	}
	if !defaultRouteContains(public, flow.Destination) {
		d.Kind = DefaultRouteExcluded
		return d
	}
	for _, rule := range c.rules {
		if rule.Ingress == flow.Ingress && rule.Source.Contains(flow.Source) && rule.Destination.Contains(flow.Destination) && (rule.Protocol == "" || rule.Protocol == flow.Protocol && flow.DestinationPort >= rule.FirstPort && flow.DestinationPort <= rule.LastPort) {
			d.Route, d.ServiceID = rule.Route, rule.ServiceID
			d.Kind = DefaultRouteDefault
			if rule.Origin == "override" {
				d.Kind = DefaultRouteOverride
			}
			return d
		}
	}
	d.Kind = DefaultRouteBaseline
	return d
}

// Failed keeps the matched route identity. An execution error is not a miss
// and must not create an unreviewed DIRECT/default fallback.
func (d DefaultRouteDecision) Failed() DefaultRouteDecision { d.Kind = DefaultRouteFailed; return d }
