package dataplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// ExecutionMihomoLiveDefinition is retained comparison data for the separate
// live reader contract. It cannot mint a child, grant cleanup, reconstruct a
// component source or promote finite probe evidence. No writer is registered
// until the original active-owner transfer and cold workflow are complete.
type ExecutionMihomoLiveDefinition struct {
	Schema            int                                   `json:"schema"`
	Plan              Plan                                  `json:"plan"`
	Source            components.MihomoLiveReference        `json:"source"`
	Node              NodeDefaultSourceReference            `json:"node"`
	Profile           components.MihomoLiveProfileReference `json:"profile"`
	Service           catalog.Service                       `json:"service"`
	NetworkProfile    string                                `json:"network_profile"`
	NetworkIdentity   netidentity.Identity                  `json:"network_identity"`
	EndpointHost      string                                `json:"endpoint_host"`
	Endpoint          netip.Addr                            `json:"endpoint"`
	EndpointAddresses []netip.Addr                          `json:"endpoint_addresses"`
	Sidecar           MihomoLiveSidecarReference            `json:"sidecar"`
	Policy            PolicyState                           `json:"policy"`
	Observation       *MihomoLiveRuntimeObservation         `json:"observation,omitempty"`
	NativeHome        *components.MihomoLiveHomeReference   `json:"native_home,omitempty"`
}

// MihomoLiveSidecarReference describes the original compiled sidecar's files,
// not a path or launch instruction. The original process owner is private.
type MihomoLiveSidecarReference struct {
	Kind         string `json:"kind"`
	BinarySHA256 string `json:"binary_sha256"`
	BinarySize   int64  `json:"binary_size"`
	ConfigSHA256 string `json:"config_sha256"`
}

// Only the original sidecar owner supplies this acknowledged comparison data
// after Start. It is excluded from immutable compiler identity.
type MihomoLiveRuntimeObservation struct {
	Schema                int    `json:"schema"`
	SidecarReceiptVersion int    `json:"sidecar_receipt_version"`
	SidecarReceiptSHA256  string `json:"sidecar_receipt_sha256"`
}

func (d ExecutionMihomoLiveDefinition) Clone() ExecutionMihomoLiveDefinition {
	d.Plan = cloneExecutionResourcePlan(d.Plan)
	if d.Plan.SiteExclusions != nil {
		exclusions := *d.Plan.SiteExclusions
		exclusions.Domains = slices.Clone(exclusions.Domains)
		exclusions.CIDRs = slices.Clone(exclusions.CIDRs)
		exclusions.Services = slices.Clone(exclusions.Services)
		exclusions.ServiceDomains = slices.Clone(exclusions.ServiceDomains)
		exclusions.ServiceCIDRs = slices.Clone(exclusions.ServiceCIDRs)
		d.Plan.SiteExclusions = &exclusions
	}
	d.Service = cloneXraySelectedTCPService(d.Service)
	d.EndpointAddresses = slices.Clone(d.EndpointAddresses)
	d.Policy = cloneWGPolicyState(d.Policy)
	if d.NativeHome != nil {
		home := *d.NativeHome
		d.NativeHome = &home
	}
	if d.Observation != nil {
		observed := *d.Observation
		d.Observation = &observed
	}
	return d
}

func (d ExecutionMihomoLiveDefinition) FrozenDigest() (string, error) {
	d.Observation = nil
	d.NativeHome = nil
	data, err := json.Marshal(d)
	if err != nil || len(data) > 1<<20 {
		return "", ErrExecutionJournal
	}
	return nodeDefaultSourceMaterialHash(data), nil
}

// validate checks retained intent only. Actual original source/process,
// resolver, control, LAN ingress and packet checks remain with the live owner.
func (d ExecutionMihomoLiveDefinition) validate() error {
	p, source, node, sidecar := d.Plan, d.Source, d.Node, d.Sidecar
	id, err := mihomoLiveIntentNode(p)
	if err != nil || d.Schema != 1 || p.SchemaVersion != SchemaVersion || !validPlanID(p.PlanID) || !validPlanDigest(p.Digest) || p.Revision == 0 || !p.Ready || p.Noop || p.RouteCount != 1 || len(p.Blockers) != 0 || len(p.ResourceConflicts) != 0 || !slices.Equal(p.Adapters, []string{"mihomo"}) || !slices.Equal(p.CanaryAdapters, []string{"mihomo"}) || len(p.RetiringAdapters) != 0 || !systemprobe.ValidWANProfileID(d.NetworkProfile) || p.NetworkProfileID != d.NetworkProfile || d.NetworkIdentity.Validate() != nil {
		return ErrExecutionJournal
	}
	if source.Schema != 1 || source.Version != components.ReviewedMihomoVersion || source.ParentOrigin.Validate() != nil || source.ParentOrigin.BootID != d.NetworkIdentity.BootID || node.Schema != 1 || node.EngineID != "mihomo" || node.NodeID != id || node.Resolved != "mihomo:"+id || node.NodeGeneration == 0 || !validPlanDigest(node.MaterialSHA256) || !validPlanDigest(d.Profile.ConfigSHA256) || d.Profile.SOCKSPort < 1024 || d.Profile.SOCKSPort > 65535 || d.Profile.SOCKSPort == 8787 {
		return ErrExecutionJournal
	}
	known := false
	for _, image := range components.ReviewedMihomoRuntimeImages() {
		known = known || source.BinarySHA256 == image.SHA256 && source.BinarySize == image.Size
	}
	if !known || !d.Endpoint.Is4() || !publicfetch.PublicAddress(d.Endpoint) || d.EndpointHost == "" || len(d.EndpointHost) > 253 || strings.ContainsAny(d.EndpointHost, "\x00\r\n /\\@:") || strings.ToLower(d.EndpointHost) != d.EndpointHost || len(d.EndpointAddresses) == 0 || len(d.EndpointAddresses) > 64 {
		return ErrExecutionJournal
	}
	if literal, err := netip.ParseAddr(d.EndpointHost); err == nil && literal != d.Endpoint {
		return ErrExecutionJournal
	}
	found := false
	for i, address := range d.EndpointAddresses {
		if !address.Is4() || !publicfetch.PublicAddress(address) || i > 0 && d.EndpointAddresses[i-1].Compare(address) >= 0 {
			return ErrExecutionJournal
		}
		found = found || address == d.Endpoint
	}
	service, err := FrozenProbeService(p.Routes[0])
	if !found || err != nil || nodeServiceProofDigest(service) != nodeServiceProofDigest(d.Service) || len(service.Domains) != 0 || !slices.Equal(sortedUnique(service.CIDRs), sortedUnique(p.Routes[0].CIDRs)) || sidecar.Kind != "sing-box" && sidecar.Kind != "hev" || !validPlanDigest(sidecar.BinarySHA256) || sidecar.BinarySize < 1 || sidecar.BinarySize > 256<<20 || !validPlanDigest(sidecar.ConfigSHA256) {
		return ErrExecutionJournal
	}
	policy := d.Policy
	if policy.Interface != "rz-mihomo" || policy.Table != 207 || policy.PriorityBase != 31200 || policy.RuleLayout != 2 || policy.SharedPriorityBase != 78 || policy.WireGuardEndpoint != nil || policy.NetworkDefault || policy.RuntimeConfigSHA256 != "" || !slices.Equal(sortedUnique(policy.Prefixes), sortedUnique(p.Routes[0].CIDRs)) {
		return ErrExecutionJournal
	}
	// Global ownership registration must be updated coherently before any live
	// definition becomes writable; current unregistered coordinates refuse.
	if validPolicyLayout(policy) != nil || validateSiteExclusions(p.SiteExclusions) != nil {
		return ErrExecutionJournal
	}
	// Recompile this literal-only intent. A decoded policy may not widen the
	// client/source predicates while keeping the same destination summary.
	prefixes, rules, err := resolvePolicyRules(context.Background(), p, "mihomo", func(context.Context, string) ([]netip.Addr, error) { return nil, ErrExecutionJournal })
	if err != nil || !slices.Equal(prefixes, policy.Prefixes) || !slices.Equal(rules, policy.Rules) || policy.NetworkPolicyGeneration != "" {
		return ErrExecutionJournal
	}
	exclusions := make([]string, len(d.EndpointAddresses))
	for i, address := range d.EndpointAddresses {
		exclusions[i] = netip.PrefixFrom(address, 32).String()
	}
	if !slices.Equal(sortedUnique(exclusions), policy.Exclusions) {
		return ErrExecutionJournal
	}
	if policy.Forwarding != nil {
		f := policy.Forwarding
		if len(f.Chain) != 16 || !strings.HasPrefix(f.Chain, "RZP_") || strings.Trim(strings.TrimPrefix(f.Chain, "RZP_"), "0123456789abcdef") != "" || len(f.Rules) != len(rules) || len(f.Rules) == 0 {
			return ErrExecutionJournal
		}
		for i, grant := range f.Rules {
			source, err := netip.ParsePrefix(grant.Source)
			if err != nil || !source.Addr().Is4() || !source.Addr().IsGlobalUnicast() || source != source.Masked() || source.String() != grant.Source || source.Bits() != 32 && !privateLANPrefix(source) || grant.Source != rules[i].Source || grant.Destination != rules[i].Destination || !validPolicyIngress(grant.Ingress) || grant.Ingress == "lo" || grant.Ingress == policy.Interface || rules[i].Ingress != "" && rules[i].Ingress != grant.Ingress {
				return ErrExecutionJournal
			}
		}
	}
	data, err := json.Marshal(d)
	if d.NativeHome != nil && d.NativeHome.Validate() != nil {
		return ErrExecutionJournal
	}
	if d.Observation != nil && (d.Observation.Schema != 1 || d.Observation.SidecarReceiptVersion != 1 || !validPlanDigest(d.Observation.SidecarReceiptSHA256)) {
		return ErrExecutionJournal
	}
	if err != nil || len(data) > 1<<20 {
		return ErrExecutionJournal
	}
	return nil
}

func (d ExecutionMihomoLiveDefinition) validateActive() error {
	if err := d.validate(); err != nil {
		return err
	}
	if d.NativeHome == nil || d.Observation == nil || d.Policy.Forwarding == nil || len(d.Policy.Forwarding.Rules) == 0 {
		return ErrExecutionJournal
	}
	return nil
}
