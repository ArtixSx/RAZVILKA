package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

const ServicePolicySchema = 1
const MaxServicePolicies = 128

var ErrServicePolicy = errors.New("invalid service automation policy")
var policyIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// Policy is permission, never runtime evidence. Saving it cannot apply a route.
// DeviceSources is the exact committed scope; an empty list explicitly means LAN.
type ServicePolicy struct {
	Schema                    int             `json:"schema"`
	ServiceID                 string          `json:"service_id"`
	Revision                  uint64          `json:"revision"`
	Enabled                   bool            `json:"enabled"`
	Mode                      string          `json:"mode"`
	DeviceSources             []string        `json:"device_sources"`
	GroupID                   string          `json:"group_id,omitempty"`
	AllowedNodeIDs            []string        `json:"allowed_node_ids"`
	AllowedEngines            []string        `json:"allowed_engines"`
	AllowedSourceIDs          []string        `json:"allowed_source_ids"`
	TrustClasses              []string        `json:"trust_classes"`
	PinnedNodeID              string          `json:"pinned_node_id,omitempty"`
	PinFallback               bool            `json:"pin_fallback"`
	Scenario                  ServiceScenario `json:"scenario"`
	TerminalAction            string          `json:"terminal_action"`
	CheckIntervalSeconds      int             `json:"check_interval_seconds"`
	HoldDownSeconds           int             `json:"hold_down_seconds"`
	MaxSwitchesPerHour        int             `json:"max_switches_per_hour"`
	AllowCredentialGeneration bool            `json:"allow_credential_generation"`
	LegacyOptIn               bool            `json:"legacy_opt_in"`
}

type ServiceScenario struct {
	Kind          string `json:"kind"`
	RequireUDP    bool   `json:"require_udp"`
	RequireIPv6   bool   `json:"require_ipv6"`
	EgressCountry string `json:"egress_country,omitempty"`
}

func DefaultServicePolicy(id string, applied ServiceState) ServicePolicy {
	return ServicePolicy{Schema: ServicePolicySchema, ServiceID: id, Mode: "manual", DeviceSources: append([]string(nil), applied.Sources...),
		AllowedNodeIDs: []string{}, AllowedEngines: []string{"sing-box"}, AllowedSourceIDs: []string{}, TrustClasses: []string{},
		Scenario: ServiceScenario{Kind: "web"}, TerminalAction: "retain", CheckIntervalSeconds: 300, HoldDownSeconds: 600, MaxSwitchesPerHour: 3}
}

func NormalizeServicePolicy(p ServicePolicy) (ServicePolicy, error) {
	if p.Schema != ServicePolicySchema || !policyIdentifier.MatchString(p.ServiceID) || !slices.Contains([]string{"auto", "manual", "paused"}, p.Mode) ||
		!slices.Contains([]string{"retain", "direct", "block"}, p.TerminalAction) || !slices.Contains([]string{"web", "api", "video", "media", "voice"}, p.Scenario.Kind) ||
		p.CheckIntervalSeconds < 60 || p.CheckIntervalSeconds > 86400 || p.HoldDownSeconds < 60 || p.HoldDownSeconds > 86400 || p.MaxSwitchesPerHour < 1 || p.MaxSwitchesPerHour > 60 {
		return p, ErrServicePolicy
	}
	if p.GroupID != "" && (!strings.HasPrefix(p.GroupID, "group-") || !policyIdentifier.MatchString(p.GroupID)) ||
		p.PinnedNodeID != "" && !validPolicyNode(p.PinnedNodeID) || len(p.Scenario.EgressCountry) != 0 && (len(p.Scenario.EgressCountry) != 2 || strings.Trim(p.Scenario.EgressCountry, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "") {
		return p, ErrServicePolicy
	}
	var err error
	if len(p.DeviceSources) > 128 {
		return p, ErrServicePolicy
	}
	p.DeviceSources, err = NormalizeSources(p.DeviceSources)
	if err != nil {
		return p, ErrServicePolicy
	}
	for index, values := range []*[]string{&p.AllowedNodeIDs, &p.AllowedEngines, &p.AllowedSourceIDs, &p.TrustClasses} {
		limit := 128
		if index == 1 || index == 3 {
			limit = 16
		}
		if len(*values) > limit {
			return p, ErrServicePolicy
		}
		copy := append([]string{}, (*values)...)
		for _, value := range copy {
			valid := policyIdentifier.MatchString(value)
			switch index {
			case 0:
				valid = validPolicyNode(value)
			case 1:
				valid = slices.Contains([]string{"sing-box", "nfqws2", "warp-wg", "usque", "amneziawg", "xray", "dns", "relay"}, value)
			case 3:
				valid = slices.Contains([]string{"manual", "file", "subscription", "community", "legacy"}, value)
			}
			if !valid {
				return p, ErrServicePolicy
			}
		}
		slices.Sort(copy)
		*values = slices.Compact(copy)
	}
	if p.PinnedNodeID != "" && !slices.Contains(p.AllowedNodeIDs, p.PinnedNodeID) {
		return p, ErrServicePolicy
	}
	return p, nil
}

func validPolicyNode(id string) bool {
	return len(id) == 69 && strings.HasPrefix(id, "node-") && strings.Trim(id[5:], "0123456789abcdef") == ""
}

func validateServicePolicies(policies map[string]ServicePolicy) error {
	if len(policies) > MaxServicePolicies {
		return ErrServicePolicy
	}
	for id, p := range policies {
		if id != p.ServiceID || p.Revision == 0 {
			return ErrServicePolicy
		}
		if _, err := NormalizeServicePolicy(p); err != nil {
			return err
		}
	}
	return nil
}

func cloneServicePolicies(in map[string]ServicePolicy) map[string]ServicePolicy {
	if in == nil {
		return nil
	}
	out := make(map[string]ServicePolicy, len(in))
	for id, p := range in {
		p.DeviceSources = slices.Clone(p.DeviceSources)
		p.AllowedNodeIDs = slices.Clone(p.AllowedNodeIDs)
		p.AllowedEngines = slices.Clone(p.AllowedEngines)
		p.AllowedSourceIDs = slices.Clone(p.AllowedSourceIDs)
		p.TrustClasses = slices.Clone(p.TrustClasses)
		out[id] = p
	}
	return out
}

// UpdateServicePolicy is a CAS on both user configuration and policy revision.
// A request cannot change the applied scope through this settings endpoint.
func (s *Store) UpdateServicePolicy(p ServicePolicy, revision, policyRevision uint64) (ServicePolicy, error) {
	var err error
	p, err = NormalizeServicePolicy(p)
	if err != nil {
		return p, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.cfg.ServicePolicies[p.ServiceID]
	if s.cfg.Revision != revision || revision == ^uint64(0) || current.Revision != policyRevision || policyRevision == ^uint64(0) {
		return p, ErrRevisionChanged
	}
	if !reflect.DeepEqual(p.DeviceSources, s.cfg.AppliedServices[p.ServiceID].Sources) {
		return p, ErrServicePolicy
	}
	previous := cloneConfig(s.cfg)
	if s.cfg.ServicePolicies == nil {
		s.cfg.ServicePolicies = map[string]ServicePolicy{}
	}
	if _, ok := s.cfg.ServicePolicies[p.ServiceID]; !ok && len(s.cfg.ServicePolicies) >= MaxServicePolicies {
		return p, ErrServicePolicy
	}
	p.Revision = policyRevision + 1
	p.LegacyOptIn = false
	s.cfg.ServicePolicies[p.ServiceID] = p
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return p, err
	}
	return p, nil
}

// PreserveLegacyServicePolicies snapshots only explicitly applied fallback
// groups discovered by the caller. Config migration alone cannot infer members
// or trust from a route string, and never invents permission for public feeds.
func (s *Store) PreserveLegacyServicePolicies(policies []ServicePolicy, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != revision {
		return ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	changed := false
	for _, p := range policies {
		if _, exists := s.cfg.ServicePolicies[p.ServiceID]; exists {
			continue
		}
		p, err := NormalizeServicePolicy(p)
		if err != nil {
			s.cfg = previous
			return err
		}
		applied := s.cfg.AppliedServices[p.ServiceID]
		if !applied.Enabled || normalizeState(applied).Route != "sing-box:"+p.GroupID || !reflect.DeepEqual(applied.Sources, p.DeviceSources) {
			s.cfg = previous
			return ErrServicePolicy
		}
		if s.cfg.ServicePolicies == nil {
			s.cfg.ServicePolicies = map[string]ServicePolicy{}
		}
		p.Revision = 1
		p.LegacyOptIn = true
		s.cfg.ServicePolicies[p.ServiceID] = p
		changed = true
	}
	if !changed {
		return nil
	}
	if err := validateServicePolicies(s.cfg.ServicePolicies); err != nil {
		s.cfg = previous
		return err
	}
	// This records existing authority, not a new routing/config generation.
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return err
	}
	return nil
}

// Manual routing intent revokes the previous automatic commit permission.
// Its caller owns the single configuration revision increment and rollback.
func fenceServicePolicy(cfg *Config, id, route string, sources []string) {
	p, ok := cfg.ServicePolicies[id]
	if !ok {
		return
	}
	p.Enabled = false
	p.Mode = "manual"
	p.LegacyOptIn = false
	p.DeviceSources = append([]string(nil), sources...)
	if p.Revision < ^uint64(0) {
		p.Revision++
	}
	p.PinnedNodeID = ""
	if strings.HasPrefix(route, "sing-box:node-") {
		node := strings.TrimPrefix(route, "sing-box:")
		if slices.Contains(p.AllowedNodeIDs, node) {
			p.PinnedNodeID = node
		}
	}
	cfg.ServicePolicies[id] = p
}

func (s *Store) AutomationStatePath() string {
	return filepath.Join(filepath.Dir(s.path), filepath.Base(s.path)+".automation.json")
}
