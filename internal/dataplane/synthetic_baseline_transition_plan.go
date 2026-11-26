package dataplane

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

var ErrSyntheticBaselineTransition = errors.New("original synthetic baseline transition unavailable or not equivalent to firmware forwarding")

// SyntheticDNSTransportPlan is detached intent in the SAME Manager plan and
// ScopedDNSAdapter. It cannot extend the legacy DIRECT-only ScopedDNSPlan.
// All actual scope/control/DNS/capture/baseline owners are runtime bindings;
// serializing this definition never grants listener or publication readiness.
type SyntheticDNSTransportPlan struct {
	Listener           string                            `json:"listener"`
	CaptureEndpoint    string                            `json:"capture_endpoint"`
	DomainPolicyDigest string                            `json:"domain_policy_digest"`
	DNS                *dnscontrol.NetworkPolicyDNSPlan  `json:"dns"`
	Definition         dnscontrol.SyntheticDNSDefinition `json:"definition"`
}

func CloneSyntheticDNSTransportPlan(p *SyntheticDNSTransportPlan) *SyntheticDNSTransportPlan {
	if p == nil {
		return nil
	}
	copy := *p
	copy.DNS = dnscontrol.CloneNetworkPolicyDNSPlan(p.DNS)
	copy.Definition.ExactNames = slices.Clone(p.Definition.ExactNames)
	return &copy
}

// Definition validation is deliberately independent of current freshness, so
// retained intent remains inspectable during Stop/recovery. The original
// runtime must separately verify live physical, provider and effect owners.
func ValidateSyntheticDNSTransportPlan(p *SyntheticDNSTransportPlan, domain *DomainPolicyRuntimePlan) error {
	if p == nil || domain == nil || ValidateDomainPolicyRuntimePlan(domain) != nil || domain.Policy.Traffic.Mode != "selected_services" || p.DomainPolicyDigest != domain.Digest || dnscontrol.ValidateNetworkPolicyDNSPlan(p.DNS) != nil || p.DNS.Generation != domain.Generation || dnscontrol.ValidateSyntheticDNSDefinition(p.Definition) != nil {
		return ErrSyntheticBaselineTransition
	}
	listener, err := netip.ParseAddrPort(p.Listener)
	capture, captureErr := netip.ParseAddrPort(p.CaptureEndpoint)
	if err != nil || captureErr != nil || listener.String() != p.Listener || capture.String() != p.CaptureEndpoint || !listener.Addr().Is4() || !listener.Addr().IsPrivate() || listener.Addr() == p.Definition.Client || listener.Port() < 1024 || listener.Port() == 8787 || capture.Addr() != listener.Addr() || capture.Port() < 1024 || capture.Port() == 8787 || capture.Port() == listener.Port() {
		return ErrSyntheticBaselineTransition
	}
	set, err := config.EffectiveResourceExclusions(domain.Policy)
	if err != nil || p.DNS.Exclusions.PolicyRevision != domain.Policy.Revision || p.DNS.Exclusions.ExclusionRevision != set.Revision || p.DNS.Exclusions.Digest != set.Digest {
		return ErrSyntheticBaselineTransition
	}
	var segmentID string
	for _, device := range domain.Scope.Devices {
		if device.ID != p.Definition.DeviceID {
			continue
		}
		if segmentID != "" || !device.Confirmed || device.MAC != p.Definition.MAC || device.Interface != p.Definition.Ingress {
			return ErrSyntheticBaselineTransition
		}
		segmentID = device.SegmentID
	}
	if segmentID == "" || !slices.Contains(domain.Policy.Clients.SegmentIDs, segmentID) || slices.Contains(domain.Policy.Clients.ExcludedDeviceIDs, p.Definition.DeviceID) || domain.Policy.Clients.Mode == "selected_devices" && !slices.Contains(domain.Policy.Clients.DeviceIDs, p.Definition.DeviceID) {
		return ErrSyntheticBaselineTransition
	}
	inside, gatewayInside := false, false
	for _, segment := range domain.Scope.Segments {
		if segment.ID != segmentID {
			continue
		}
		if segment.Interface != p.Definition.Ingress || segment.WAN || !segment.Home {
			return ErrSyntheticBaselineTransition
		}
		for _, prefix := range segment.Prefixes {
			inside = inside || prefix.Contains(p.Definition.Client)
			gatewayInside = gatewayInside || prefix.Contains(listener.Addr())
		}
	}
	if !inside || !gatewayInside {
		return ErrSyntheticBaselineTransition
	}
	for _, value := range domain.Policy.Clients.ExcludedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Contains(p.Definition.Client) {
			return ErrSyntheticBaselineTransition
		}
	}
	// First executable slice has exact names and one resolved VLESS node.
	// Disabled identities remain in DomainPolicy for negative classification.
	names := map[string]bool{}
	node := ""
	for _, service := range domain.Services {
		if !service.Selected {
			continue
		}
		applicable := len(service.Sources) == 0
		for _, value := range service.Sources {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return ErrSyntheticBaselineTransition
			}
			applicable = applicable || prefix.Contains(p.Definition.Client)
		}
		if !applicable {
			continue
		}
		selected, ok := strings.CutPrefix(service.Route, "xray:")
		if !ok || selected == "" || len(selected) > 128 || strings.ContainsAny(selected, " \t/\\:\x00\r\n") || node != "" && node != selected || len(service.DomainSuffixes) != 0 || len(service.CIDRs) != 0 || len(service.Domains) == 0 {
			return ErrSyntheticBaselineTransition
		}
		node = selected
		for _, name := range service.Domains {
			names[name] = true
		}
	}
	if node == "" || len(names) != len(p.Definition.ExactNames) || len(p.DNS.Bindings) != len(names) {
		return ErrSyntheticBaselineTransition
	}
	for _, name := range p.Definition.ExactNames {
		if !names[name] {
			return ErrSyntheticBaselineTransition
		}
	}
	for _, binding := range p.DNS.Bindings {
		if binding.Client != p.Definition.Client || !names[binding.Domain] {
			return ErrSyntheticBaselineTransition
		}
	}
	return nil
}
