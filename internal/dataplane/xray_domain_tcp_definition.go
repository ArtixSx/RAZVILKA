package dataplane

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrXrayDomainTCPOriginal = errors.New("original domain Xray TCP owner is unavailable or changed")

// This definition is comparison data in the existing Manager journal. It
// cannot issue a DNS mapping, process, listener, admission or cleanup owner.
// In particular Capture.Xray.RealIP is not evidence of a DNS resolution.
type ExecutionXrayDomainTCPDefinition struct {
	Schema          int                                       `json:"schema"`
	PlanID          string                                    `json:"plan_id"`
	PlanDigest      string                                    `json:"plan_digest"`
	NetworkProfile  string                                    `json:"network_profile"`
	Domain          *DomainPolicyRuntimePlan                  `json:"domain"`
	Transport       *SyntheticDNSTransportPlan                `json:"transport"`
	Capture         DomainPolicyTCPCaptureSpec                `json:"capture"`
	Service         catalog.Service                           `json:"service"`
	Proof           NodeServiceProofReference                 `json:"proof"`
	Mapping         dnscontrol.SyntheticDNSMappingObservation `json:"mapping"`
	PrivateEndpoint netip.AddrPort                            `json:"private_endpoint"`
	ConfigSHA256    string                                    `json:"config_sha256"`
	NetworkIdentity netidentity.Identity                      `json:"network_identity"`
}

func (d ExecutionXrayDomainTCPDefinition) Clone() ExecutionXrayDomainTCPDefinition {
	d.Domain = CloneDomainPolicyRuntimePlan(d.Domain)
	d.Transport = CloneSyntheticDNSTransportPlan(d.Transport)
	d.Service = cloneXraySelectedTCPService(d.Service)
	d.Mapping.CNAMEChain = slices.Clone(d.Mapping.CNAMEChain)
	return d
}

func (d ExecutionXrayDomainTCPDefinition) validate() error {
	if d.Schema != 1 || !validPlanID(d.PlanID) || !validPlanDigest(d.PlanDigest) || d.NetworkIdentity.Validate() != nil || !validNetworkPolicyGeneration(d.ConfigSHA256) ||
		!d.PrivateEndpoint.IsValid() || d.PrivateEndpoint.Addr() != netip.MustParseAddr("127.0.0.1") || d.PrivateEndpoint.Port() < 1024 || d.PrivateEndpoint.Port() == 8787 {
		return ErrXrayDomainTCPOriginal
	}
	if err := validateXrayDomainTCPCaptureIntent(d.Domain, d.Transport, d.NetworkProfile, d.Capture); err != nil {
		return err
	}
	if !domainPolicyTCPMappingMatchesCapture(d.Mapping, d.Capture) || d.Mapping.Authority.ControlEpoch == 0 || d.Mapping.Authority.BindingRevision == 0 || d.Mapping.Authority.Exclusions != d.Transport.DNS.Exclusions {
		return ErrXrayDomainTCPOriginal
	}
	if validateXrayDomainTCPService(d.Service, d.Capture.Xray) != nil || d.Proof.Schema != 1 || d.Proof.EngineID != "xray" || d.Proof.NodeID != d.Capture.Xray.NodeID ||
		d.Proof.ServiceID != d.Service.ID || d.Proof.WANProfile != d.NetworkProfile || d.Proof.NodeGeneration == 0 ||
		!validNetworkPolicyGeneration(d.Proof.CompiledMaterialSHA256) || d.Proof.ServiceSHA256 != nodeServiceProofDigest(d.Service) || !validNetworkPolicyGeneration(d.Proof.ProofSHA256) ||
		d.Proof.CheckedAt.IsZero() || !d.Proof.ExpiresAt.After(d.Proof.CheckedAt) {
		return ErrXrayDomainTCPOriginal
	}
	return nil // Historical validity is independent of eligibility expiry.
}

func domainPolicyTCPMappingMatchesCapture(o dnscontrol.SyntheticDNSMappingObservation, spec DomainPolicyTCPCaptureSpec) bool {
	return o.Authority.Generation == spec.Xray.Generation && o.PublicationID != "" && o.Client == spec.Client.Address && o.DeviceID == spec.DeviceID && o.MAC == spec.Client.MAC && o.Ingress == spec.Client.Interface && o.QName == spec.Xray.Name &&
		o.RealIPv4 == spec.Xray.RealIP && domainPolicyTCPPublicIPv4(o.RealIPv4) && domainPolicyTCPSyntheticPool.Contains(o.Synthetic) && !o.ExpiresAt.IsZero()
}

func validateXrayDomainTCPCaptureIntent(domain *DomainPolicyRuntimePlan, transport *SyntheticDNSTransportPlan, wan string, spec DomainPolicyTCPCaptureSpec) error {
	if !spec.valid() || spec.Xray.NetworkProfile != wan || wan == "" || ValidateSyntheticDNSTransportPlan(transport, domain) != nil ||
		spec.Xray.Generation != domain.Generation || spec.Listen.String() != transport.CaptureEndpoint || spec.Client.Address != transport.Definition.Client ||
		spec.DeviceID != transport.Definition.DeviceID || spec.Client.MAC != transport.Definition.MAC || spec.Client.Interface != transport.Definition.Ingress || !slices.Contains(transport.Definition.ExactNames, spec.Xray.Name) {
		return ErrXrayDomainTCPOriginal
	}
	matched := 0
	for _, service := range domain.Services {
		if !service.Selected || service.ID != spec.Xray.ServiceID || service.Route != "xray:"+spec.Xray.NodeID || !slices.Contains(service.Domains, spec.Xray.Name) {
			continue
		}
		if len(service.CIDRs) != 0 || len(service.DomainSuffixes) != 0 {
			return ErrXrayDomainTCPOriginal
		}
		inside := len(service.Sources) == 0
		for _, source := range service.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return ErrXrayDomainTCPOriginal
			}
			inside = inside || prefix.Contains(spec.Client.Address)
		}
		if inside {
			matched++
		}
	}
	if matched != 1 {
		return ErrXrayDomainTCPOriginal
	}
	for _, device := range domain.Scope.Devices {
		if device.ID == spec.DeviceID && device.SegmentID == spec.Client.SegmentID {
			return nil
		}
	}
	return ErrXrayDomainTCPOriginal
}

func validateXrayDomainTCPService(service catalog.Service, spec DomainPolicyTCPXraySpec) error {
	if service.ID != spec.ServiceID || len(service.CIDRs) != 0 || !slices.Contains(service.Domains, spec.Name) || strings.Contains(spec.Name, "*") {
		return ErrXrayDomainTCPOriginal
	}
	_, err := FrozenProbeService(Route{LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL})
	return err
}
