package dataplane

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// These definitions are immutable journal comparisons. No executable path,
// argv, config bytes, prepared/ACTIVE boolean or serialized observation can
// construct an original runtime owner or supply command/cleanup permission.
type ExecutionXraySelectedTCPDefinition struct {
	Schema          int                                `json:"schema"`
	PlanID          string                             `json:"plan_id"`
	PlanDigest      string                             `json:"plan_digest"`
	NetworkProfile  string                             `json:"network_profile"`
	Match           XraySelectedTCPRedirectSpec        `json:"match"`
	Service         catalog.Service                    `json:"service"`
	Proof           NodeServiceProofReference          `json:"proof"`
	ConfigSHA256    string                             `json:"config_sha256"`
	EffectsSHA256   string                             `json:"effects_sha256"`
	Process         XraySelectedTCPProcessShape        `json:"process"`
	NetworkIdentity netidentity.Identity               `json:"network_identity"`
	Observation     *XraySelectedTCPRuntimeObservation `json:"observation,omitempty"`
}

type XraySelectedTCPProcessShape struct {
	EngineID     string `json:"engine_id"`
	Version      string `json:"version"`
	Verb         string `json:"verb"`
	ConfigFlag   string `json:"config_flag"`
	ConfigSource string `json:"config_source"`
	ConfigName   string `json:"config_name"`
	LogName      string `json:"log_name"`
	RouteProof   bool   `json:"route_proof"`
}

// Actual observation only compares to the original retained child/files and
// native listener. It does not contain a signal target or a cleanup recipe.
type XraySelectedTCPRuntimeObservation struct {
	Schema           int                  `json:"schema"`
	PID              int                  `json:"pid"`
	ParentPID        int                  `json:"parent_pid"`
	ProcessGroup     int                  `json:"process_group"`
	BootID           string               `json:"boot_id"`
	ProcessStart     string               `json:"process_start"`
	ExecutableSHA256 string               `json:"executable_sha256"`
	ArgumentsSHA256  string               `json:"arguments_sha256"`
	ConfigSHA256     string               `json:"config_sha256"`
	Listener         netip.AddrPort       `json:"listener"`
	SocketInode      uint64               `json:"socket_inode"`
	NetworkIdentity  netidentity.Identity `json:"network_identity"`
}

func xraySelectedTCPProcessShape() XraySelectedTCPProcessShape {
	return XraySelectedTCPProcessShape{EngineID: "xray", Version: "26.3.27", Verb: "run", ConfigFlag: "-config", ConfigSource: "original-owned-fd4", ConfigName: "xray-redirect.json", LogName: "xray.log", RouteProof: true}
}

func (d ExecutionXraySelectedTCPDefinition) Clone() ExecutionXraySelectedTCPDefinition {
	d.Match = d.Match.Clone()
	d.Service = cloneXraySelectedTCPService(d.Service)
	if d.Observation != nil {
		observed := *d.Observation
		d.Observation = &observed
	}
	return d
}

func cloneXraySelectedTCPService(service catalog.Service) catalog.Service {
	return copyProxyPredicateService(service)
}

func (d ExecutionXraySelectedTCPDefinition) validate() (PolicyEffectPlan, error) {
	if d.Schema != 1 || !validPlanID(d.PlanID) || !validPlanDigest(d.PlanDigest) || d.NetworkProfile == "" || len(d.NetworkProfile) > 256 || strings.ContainsAny(d.NetworkProfile, "\x00\r\n") || d.Process != xraySelectedTCPProcessShape() ||
		!validNetworkPolicyGeneration(d.ConfigSHA256) || !validNetworkPolicyGeneration(d.EffectsSHA256) || d.NetworkIdentity.Validate() != nil {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	canonical, err := canonicalXraySelectedTCPRedirect(d.Match)
	if err != nil || !reflect.DeepEqual(canonical, d.Match) || d.Match.LAN.Mode != LANPolicyXraySelectedTCPMode {
		return PolicyEffectPlan{}, errors.Join(ErrExecutionJournal, err)
	}
	service, err := FrozenProbeService(Route{LogicalServiceID: d.Match.ServiceID, ProbeService: &d.Service, ProbeURL: d.Service.ProbeURL})
	if err != nil || !reflect.DeepEqual(service, d.Service) || service.ID != d.Match.ServiceID || len(service.Domains) != 0 || !slices.Equal(sortedUnique(service.CIDRs), d.Match.Destinations) {
		return PolicyEffectPlan{}, errors.Join(ErrExecutionJournal, err)
	}
	proof := d.Proof
	if proof.Schema != 1 || proof.EngineID != "xray" || proof.NodeID != d.Match.NodeID || proof.ServiceID != d.Match.ServiceID || proof.WANProfile != d.NetworkProfile ||
		proof.NodeGeneration == 0 || !validNetworkPolicyGeneration(proof.CompiledMaterialSHA256) || !validNetworkPolicyGeneration(proof.ServiceSHA256) ||
		!validNetworkPolicyGeneration(proof.ProofSHA256) || proof.ServiceSHA256 != nodeServiceProofDigest(d.Service) || proof.CheckedAt.IsZero() || !proof.ExpiresAt.After(proof.CheckedAt) {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	compiled, err := CompileXraySelectedTCPRedirect(d.Match)
	digest, digestErr := PolicyEffectPlanDigest(compiled)
	if err != nil || digestErr != nil || digest != d.EffectsSHA256 {
		return PolicyEffectPlan{}, errors.Join(ErrExecutionJournal, err, digestErr)
	}
	if d.Observation != nil && d.validateObservation(*d.Observation) != nil {
		return PolicyEffectPlan{}, ErrExecutionJournal
	}
	return compiled, nil
}

func (d ExecutionXraySelectedTCPDefinition) validateObservation(o XraySelectedTCPRuntimeObservation) error {
	start, startErr := strconv.ParseUint(o.ProcessStart, 10, 64)
	if o.Schema != 1 || o.PID <= 1 || o.ParentPID <= 1 || o.ProcessGroup <= 0 || o.NetworkIdentity != d.NetworkIdentity || o.BootID != d.NetworkIdentity.BootID ||
		startErr != nil || start == 0 || strconv.FormatUint(start, 10) != o.ProcessStart ||
		!validNetworkPolicyGeneration(o.ExecutableSHA256) || !validNetworkPolicyGeneration(o.ArgumentsSHA256) || o.ConfigSHA256 != d.ConfigSHA256 ||
		o.Listener != d.Match.Listener || o.SocketInode == 0 {
		return ErrExecutionJournal
	}
	return nil
}

// Journal validity is deliberately independent of current wall time. Expired
// service eligibility must fence forward use while original exact cleanup
// continues to compare the retained historical intent under a fresh owner.
func (d ExecutionXraySelectedTCPDefinition) eligible(now time.Time) bool {
	return !now.Before(d.Proof.CheckedAt) && now.Before(d.Proof.ExpiresAt)
}
