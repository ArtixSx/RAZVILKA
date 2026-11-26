package dataplane

import (
	"errors"
	"net/netip"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

var ErrMihomoProbe = errors.New("original scoped Mihomo probe is unavailable or changed")

// Retained intent only. No credential, argv, executable path or process owner
// is reconstructed from this document. Only the original source may launch.
type ExecutionMihomoProbeDefinition struct {
	Schema          int                             `json:"schema"`
	PlanID          string                          `json:"plan_id"`
	PlanDigest      string                          `json:"plan_digest"`
	NetworkProfile  string                          `json:"network_profile"`
	Revision        uint64                          `json:"revision"`
	NetworkIdentity netidentity.Identity            `json:"network_identity"`
	Source          components.MihomoProbeReference `json:"source"`
	Service         catalog.Service                 `json:"service"`
}

func (d ExecutionMihomoProbeDefinition) Clone() ExecutionMihomoProbeDefinition {
	d.Service = cloneXraySelectedTCPService(d.Service)
	return d
}

func (d ExecutionMihomoProbeDefinition) validate() error {
	r := d.Source
	if !r.ParentOrigin.IsZero() && (r.ParentOrigin.Validate() != nil || r.ParentOrigin.BootID != d.NetworkIdentity.BootID) {
		return ErrMihomoProbe
	}
	if d.Schema != 1 || !validPlanID(d.PlanID) || !validPlanDigest(d.PlanDigest) || d.NetworkProfile == "" || d.Revision == 0 || d.NetworkIdentity.Validate() != nil ||
		r.Version != components.ReviewedMihomoVersion || !validPlanDigest(r.BinarySHA256) || r.BinarySize < 1 || r.BinarySize > 256<<20 || !validPlanDigest(r.ReviewSHA256) || !validPlanDigest(r.ConfigSHA256) ||
		r.ServerHost == "" || !r.Endpoint.Is4() || !publicfetch.PublicAddress(r.Endpoint) || r.SOCKSPort < 1024 || r.SOCKSPort > 65535 || r.SOCKSPort == 8787 {
		return ErrMihomoProbe
	}
	if address, err := netip.ParseAddr(r.ServerHost); err == nil && address != r.Endpoint {
		return ErrMihomoProbe
	}
	if _, err := FrozenProbeService(Route{LogicalServiceID: d.Service.ID, ProbeService: &d.Service, ProbeURL: d.Service.ProbeURL}); err != nil {
		return err
	}
	return nil
}

func validateMihomoProbeExecutionResource(execution Execution, r ExecutionResource, terminal bool) error {
	d := r.MihomoProbe
	planID := execution.PlanID
	if execution.ResourcePlanID != "" {
		planID = execution.ResourcePlanID
	}
	if d == nil || r.Kind != "mihomo-probe" || d.validate() != nil || d.PlanID != planID || d.PlanDigest != execution.Digest ||
		r.Generation != d.Source.ConfigSHA256 || r.EffectsDigest != d.Source.ConfigSHA256 || r.NodeTransit != nil || r.NFQWS != nil || r.SyntheticBaseline != nil || r.XraySelectedTCP != nil || r.XrayDomainTCP != nil || r.DomainTCPCapture != nil || r.DomainTCPBaseline != nil {
		return ErrExecutionJournal
	}
	switch r.Phase {
	case "planned", "process-pending", "listener-ready", "closed":
		if terminal || r.State != "prepared" {
			return ErrExecutionJournal
		}
	case "removed":
		if r.State != "removed" {
			return ErrExecutionJournal
		}
	case "unused":
		if r.State != "unused" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	return nil
}
