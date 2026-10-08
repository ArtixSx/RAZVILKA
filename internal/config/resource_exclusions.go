package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

var ErrResourceExclusions = errors.New("invalid resource exclusions")

// ResourceMatch is an explicit negative selector, never an executable route.
// suffix includes the named domain and its subdomains at label boundaries.
type ResourceMatch struct {
	Kind  string `json:"kind"` // service, exact, suffix, ip, cidr
	Value string `json:"value"`
}

type AcceptedRussianSnapshot struct {
	CatalogID string          `json:"catalog_id"`
	Revision  uint64          `json:"revision"`
	Digest    string          `json:"digest"`
	Entries   []ResourceMatch `json:"entries"`
}

// ResourceExclusions keeps manual edits independent of the last accepted feed.
// Disabling Russian exclusions does not delete its retained snapshot.
type ResourceExclusions struct {
	Schema          int                      `json:"schema"`
	Revision        uint64                   `json:"revision"`
	Manual          []ResourceMatch          `json:"manual"`
	RussianSnapshot *AcceptedRussianSnapshot `json:"russian_snapshot,omitempty"`
}

// ResourceExclusionStateEqual protects retained negatives from an ordinary
// positive policy/path approval. Changes belong to the explicit exclusion API.
func ResourceExclusionStateEqual(a, b *NetworkPolicy) bool {
	negative := func(p *NetworkPolicy) any {
		v := struct {
			Exclusions *ResourceExclusions
			Russian    RussianExclusions
			Rules      []NetworkRule
		}{Rules: []NetworkRule{}}
		if p != nil {
			p = CloneNetworkPolicy(p)
			v.Exclusions, v.Russian = p.Exclusions, p.Russian
			for _, r := range p.Rules {
				if r.Action == "direct" {
					v.Rules = append(v.Rules, r)
				}
			}
		}
		return v
	}
	return reflect.DeepEqual(negative(a), negative(b))
}

func CloneResourceExclusions(in *ResourceExclusions) *ResourceExclusions {
	if in == nil {
		return nil
	}
	out := *in
	out.Manual = slices.Clone(in.Manual)
	if in.RussianSnapshot != nil {
		v := *in.RussianSnapshot
		v.Entries = slices.Clone(v.Entries)
		out.RussianSnapshot = &v
	}
	return &out
}

func normalizeResourceMatch(m ResourceMatch) (ResourceMatch, error) {
	switch m.Kind {
	case "service":
		if !policyIdentifier.MatchString(m.Value) {
			return m, ErrResourceExclusions
		}
	case "exact", "suffix":
		name, err := PolicyDomain(m.Value)
		if err != nil {
			return m, ErrResourceExclusions
		}
		m.Value = name
	case "ip":
		ip, err := netip.ParseAddr(m.Value)
		if err != nil || ip.String() != m.Value || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return m, ErrResourceExclusions
		}
	case "cidr":
		if _, ok := policyPrefix(m.Value); !ok {
			return m, ErrResourceExclusions
		}
	default:
		return m, ErrResourceExclusions
	}
	return m, nil
}

// NormalizeResourceMatches validates every entry before producing a detached,
// sorted set. It does not mask an invalid CIDR or infer a suffix from an exact
// domain. Duplicates, including IDN aliases, are refused.
func NormalizeResourceMatches(in []ResourceMatch) ([]ResourceMatch, error) {
	if len(in) > 4096 {
		return nil, ErrResourceExclusions
	}
	out := make([]ResourceMatch, 0, len(in))
	seen := map[ResourceMatch]bool{}
	for _, m := range in {
		m, err := normalizeResourceMatch(m)
		if err != nil || seen[m] {
			return nil, ErrResourceExclusions
		}
		seen[m] = true
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b ResourceMatch) int {
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		return strings.Compare(a.Value, b.Value)
	})
	return out, nil
}

func exclusionDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func RussianSnapshotDigest(in *AcceptedRussianSnapshot) string {
	if in == nil {
		return ""
	}
	v := *in
	entries, err := NormalizeResourceMatches(in.Entries)
	if err != nil {
		return ""
	}
	v.Entries, v.Digest = entries, ""
	return exclusionDigest(v)
}

func validateRussianSnapshot(in *AcceptedRussianSnapshot) error {
	if in == nil {
		return nil
	}
	if !policyIdentifier.MatchString(in.CatalogID) || in.Revision == 0 || in.Revision == ^uint64(0) || len(in.Entries) == 0 || !consentHex(in.Digest, 64) || in.Digest != RussianSnapshotDigest(in) {
		return ErrResourceExclusions
	}
	return validateCanonicalResourceMatches(in.Entries)
}

func validateCanonicalResourceMatches(in []ResourceMatch) error {
	if _, err := NormalizeResourceMatches(in); err != nil {
		return err
	}
	for _, m := range in {
		canonical, _ := normalizeResourceMatch(m)
		if canonical != m {
			return ErrResourceExclusions
		}
	}
	return nil
}

func ValidateResourceExclusions(in *ResourceExclusions) error {
	if in == nil {
		return nil
	}
	if in.Schema != 1 || in.Revision == 0 || in.Revision == ^uint64(0) || len(in.Manual) > 512 || validateCanonicalResourceMatches(in.Manual) != nil {
		return ErrResourceExclusions
	}
	return validateRussianSnapshot(in.RussianSnapshot)
}

// ValidateResourceExclusionStorage permits one stored negative document. Before
// a real network scope exists it remains inactive, without fabricated clients.
func ValidateResourceExclusionStorage(cfg Config) error {
	if cfg.InactiveResourceExclusions != nil && cfg.NetworkPolicy != nil {
		return ErrResourceExclusions
	}
	return ValidateResourceExclusions(cfg.InactiveResourceExclusions)
}

// NetworkPolicyWithRetainedExclusions losslessly carries an inactive document
// into the first explicit real policy. It issues no scope or path permission;
// the caller still validates real clients, selected services and source owners.
func NetworkPolicyWithRetainedExclusions(expected Config, policy *NetworkPolicy) (*NetworkPolicy, error) {
	if policy == nil || ValidateResourceExclusionStorage(expected) != nil {
		return nil, ErrResourceExclusions
	}
	out := CloneNetworkPolicy(policy)
	before := expected.NetworkPolicy
	if expected.InactiveResourceExclusions != nil {
		if out.Exclusions == nil {
			out.Exclusions = CloneResourceExclusions(expected.InactiveResourceExclusions)
		}
		before = &NetworkPolicy{Exclusions: expected.InactiveResourceExclusions}
	}
	if !ResourceExclusionStateEqual(before, out) {
		return nil, ErrResourceExclusions
	}
	return out, nil
}

// EffectiveExclusionSet is a detached comparison/decision image. The actual
// Store, complete config revision, control epoch and positive route proof remain
// mandatory at each runtime admission. This DTO cannot grant any operation.
type EffectiveExclusionSet struct {
	PolicyRevision  uint64                   `json:"policy_revision"`
	Revision        uint64                   `json:"revision"`
	Clients         ClientScope              `json:"clients"`
	RussianEnabled  bool                     `json:"russian_enabled"`
	RussianSnapshot *AcceptedRussianSnapshot `json:"russian_snapshot,omitempty"`
	LegacyRussian   RussianExclusions        `json:"legacy_russian"`
	Manual          []ResourceMatch          `json:"manual"`
	Russian         []ResourceMatch          `json:"russian"`
	LegacyRules     []NetworkRule            `json:"legacy_rules"`
	BroadTLDs       []string                 `json:"broad_tlds"`
	Digest          string                   `json:"digest"`
}

func EffectiveResourceExclusions(p *NetworkPolicy) (EffectiveExclusionSet, error) {
	v := EffectiveExclusionSet{Manual: []ResourceMatch{}, Russian: []ResourceMatch{}, LegacyRules: []NetworkRule{}, BroadTLDs: []string{}}
	if err := ValidateNetworkPolicy(p); err != nil {
		return v, err
	}
	if p != nil {
		p = CloneNetworkPolicy(p)
		v.PolicyRevision, v.Clients, v.RussianEnabled = p.Revision, p.Clients, p.Russian.Enabled
		if p.Exclusions != nil {
			v.Revision = p.Exclusions.Revision
			v.Manual, _ = NormalizeResourceMatches(p.Exclusions.Manual)
			if p.Russian.Enabled && p.Exclusions.RussianSnapshot != nil {
				v.Russian = slices.Clone(p.Exclusions.RussianSnapshot.Entries)
			}
		}
		if p.Russian.Enabled {
			v.LegacyRussian = p.Russian
			slices.Sort(v.LegacyRussian.ServiceIDs)
			slices.Sort(v.LegacyRussian.BroadTLDs)
			if p.Exclusions != nil && p.Exclusions.RussianSnapshot != nil {
				v.RussianSnapshot = CloneResourceExclusions(p.Exclusions).RussianSnapshot
				v.RussianSnapshot.Entries, _ = NormalizeResourceMatches(v.RussianSnapshot.Entries)
			}
			for _, id := range p.Russian.ServiceIDs {
				m := ResourceMatch{Kind: "service", Value: id}
				if !slices.Contains(v.Russian, m) {
					v.Russian = append(v.Russian, m)
				}
			}
			v.BroadTLDs = append(v.BroadTLDs, p.Russian.BroadTLDs...)
		}
		v.Russian, _ = NormalizeResourceMatches(v.Russian)
		for _, rule := range p.Rules {
			if rule.Action == "direct" {
				slices.Sort(rule.DeviceIDs)
				v.LegacyRules = append(v.LegacyRules, rule)
			}
		}
		slices.SortFunc(v.LegacyRules, func(a, b NetworkRule) int { return strings.Compare(a.ID, b.ID) })
		slices.Sort(v.BroadTLDs)
		slices.Sort(v.Clients.SegmentIDs)
		slices.Sort(v.Clients.DeviceIDs)
		slices.Sort(v.Clients.ExcludedDeviceIDs)
		slices.Sort(v.Clients.ExcludedCIDRs)
	}
	v.Digest = exclusionDigest(v)
	return v, nil
}

// EffectiveConfigResourceExclusions also sees the saved inactive document. Its
// presence cannot create positive membership or make a nil policy executable.
func EffectiveConfigResourceExclusions(cfg Config) (EffectiveExclusionSet, error) {
	if err := ValidateResourceExclusionStorage(cfg); err != nil {
		return EffectiveExclusionSet{}, err
	}
	v, err := EffectiveResourceExclusions(cfg.NetworkPolicy)
	if err != nil {
		return v, err
	}
	if cfg.InactiveResourceExclusions != nil {
		v.Revision = cfg.InactiveResourceExclusions.Revision
		v.Manual, _ = NormalizeResourceMatches(cfg.InactiveResourceExclusions.Manual)
		v.Digest = ""
		v.Digest = exclusionDigest(v)
	}
	return v, nil
}

// ResourceTarget may contain only one known identity. DNS owners check the
// original service/domain before a request and each CNAME/A/AAAA afterwards.
// Client membership is an independent decision made by the physical owner.
type ResourceTarget struct {
	ServiceID string
	Domain    string
	DeviceID  string
	Address   netip.Addr
}

func normalizeResourceTarget(t ResourceTarget) (ResourceTarget, error) {
	if t.ServiceID == "" && t.Domain == "" && !t.Address.IsValid() || t.ServiceID != "" && !policyIdentifier.MatchString(t.ServiceID) || t.DeviceID != "" && !policyIdentifier.MatchString(t.DeviceID) {
		return t, ErrResourceExclusions
	}
	if t.Domain != "" {
		name, err := PolicyDomain(t.Domain)
		if err != nil {
			return t, ErrResourceExclusions
		}
		t.Domain = name
	}
	if t.Address.IsValid() && (t.Address.Is4In6() || t.Address.Zone() != "" || t.Address.IsUnspecified() || t.Address.IsMulticast() || t.Address.IsLoopback() || t.Address.IsLinkLocalUnicast()) {
		return t, ErrResourceExclusions
	}
	return t, nil
}

func resourceMatches(m ResourceMatch, t ResourceTarget) bool {
	switch m.Kind {
	case "service":
		return t.ServiceID != "" && t.ServiceID == m.Value
	case "exact":
		return t.Domain != "" && t.Domain == m.Value
	case "suffix":
		return t.Domain != "" && (t.Domain == m.Value || strings.HasSuffix(t.Domain, "."+m.Value))
	case "ip":
		ip, _ := netip.ParseAddr(m.Value)
		return t.Address.IsValid() && ip == t.Address
	case "cidr":
		p, _ := netip.ParsePrefix(m.Value)
		return t.Address.IsValid() && p.Contains(t.Address)
	}
	return false
}

func (v EffectiveExclusionSet) Matches(target ResourceTarget) (bool, error) {
	if validateCanonicalResourceMatches(v.Manual) != nil || validateCanonicalResourceMatches(v.Russian) != nil {
		return false, ErrResourceExclusions
	}
	for _, r := range v.LegacyRules {
		if validateCanonicalResourceMatches([]ResourceMatch{{Kind: r.Kind, Value: r.Value}}) != nil || r.Action != "direct" || !policyIDs(r.DeviceIDs, 128) {
			return false, ErrResourceExclusions
		}
	}
	for _, tld := range v.BroadTLDs {
		if !slices.Contains([]string{"ru", "xn--p1ai", "su"}, tld) {
			return false, ErrResourceExclusions
		}
	}
	t, err := normalizeResourceTarget(target)
	if err != nil {
		return false, err
	}
	for _, set := range [][]ResourceMatch{v.Manual, v.Russian} {
		for _, m := range set {
			if resourceMatches(m, t) {
				return true, nil
			}
		}
	}
	for _, rule := range v.LegacyRules {
		if !resourceMatches(ResourceMatch{Kind: rule.Kind, Value: rule.Value}, t) {
			continue
		}
		if len(rule.DeviceIDs) != 0 {
			if t.DeviceID == "" {
				return false, ErrResourceExclusions
			}
			if !slices.Contains(rule.DeviceIDs, t.DeviceID) {
				continue
			}
		}
		return true, nil
	}
	for _, tld := range v.BroadTLDs {
		if t.Domain != "" && strings.HasSuffix(t.Domain, "."+tld) {
			return true, nil
		}
	}
	return false, nil
}

func ResourceExcluded(p *NetworkPolicy, target ResourceTarget) (bool, error) {
	v, err := EffectiveResourceExclusions(p)
	if err != nil {
		return false, err
	}
	return v.Matches(target)
}

func ConfigResourceExcluded(cfg Config, target ResourceTarget) (bool, error) {
	v, err := EffectiveConfigResourceExclusions(cfg)
	if err != nil {
		return false, err
	}
	return v.Matches(target)
}

// WithResourceExclusionObservation closes an independent bounded observation
// against SAME actual Store, the entire frozen config and its observed disk
// image. It supplies detached negatives, not positive/client/operation authority.
// Like WithRevisionObservation, use MUST NOT call this Store or acquire the
// application gate. Obtain original gate admission first; a long-lived consumer
// must re-enter with its real owner and a fresh bounded context on each use.
func (s *Store) WithResourceExclusionObservation(ctx context.Context, expected Config, use func(EffectiveExclusionSet) error) error {
	if ctx == nil || use == nil {
		return ErrRevisionChanged
	}
	return s.WithRevisionObservation(ctx, expected.Revision, func() error {
		if !reflect.DeepEqual(s.cfg, expected) || ValidateListNetworkPolicy(s.cfg.NetworkPolicy) != nil {
			return ErrRevisionChanged
		}
		set, err := EffectiveConfigResourceExclusions(s.cfg)
		if err != nil {
			return err
		}
		if err := use(set); err != nil {
			return err
		}
		if !reflect.DeepEqual(s.cfg, expected) {
			return ErrRevisionChanged
		}
		return nil
	})
}

// ValidateListNetworkPolicy is the current product contract. Historical full
// tunnel intent remains decodable for diagnosis/recovery, never authorized.
func ValidateListNetworkPolicy(p *NetworkPolicy) error {
	if err := ValidateNetworkPolicy(p); err != nil {
		return err
	}
	if p != nil && p.Traffic.Mode != "selected_services" {
		return ErrNetworkPolicy
	}
	return nil
}

// UpdateResourceExclusions edits only explicit negatives. A nil manual patch
// preserves it; a present empty slice clears only manual entries. A missing,
// empty or malformed feed can never replace the last accepted snapshot.
func (s *Store) UpdateResourceExclusions(ctx context.Context, expected Config, manual *[]ResourceMatch, accepted *AcceptedRussianSnapshot) (Config, error) {
	return s.UpdateResourceExclusionsPatch(ctx, expected, ResourceExclusionsPatch{Manual: manual, Accepted: accepted})
}

type ResourceExclusionsPatch struct {
	Manual                   *[]ResourceMatch
	Accepted                 *AcceptedRussianSnapshot
	RussianEnabled           *bool
	RussianAutoUpdateAllowed *bool
}

func (s *Store) UpdateResourceExclusionsPatch(ctx context.Context, expected Config, patch ResourceExclusionsPatch) (Config, error) {
	manual, accepted := patch.Manual, patch.Accepted
	if ctx == nil || ValidateResourceExclusionStorage(expected) != nil || ValidateListNetworkPolicy(expected.NetworkPolicy) != nil || manual == nil && accepted == nil && patch.RussianEnabled == nil && patch.RussianAutoUpdateAllowed == nil || expected.Revision == ^uint64(0) || expected.NetworkPolicy != nil && expected.NetworkPolicy.Revision >= ^uint64(0)-1 {
		return Config{}, ErrResourceExclusions
	}
	next := cloneConfig(expected)
	p := next.NetworkPolicy
	if p == nil {
		if manual == nil || accepted != nil || patch.RussianEnabled != nil || patch.RussianAutoUpdateAllowed != nil {
			return Config{}, ErrResourceExclusions
		}
		if next.InactiveResourceExclusions == nil {
			next.InactiveResourceExclusions = &ResourceExclusions{Schema: 1, Manual: []ResourceMatch{}}
		}
		entries, err := NormalizeResourceMatches(*manual)
		if err != nil || len(entries) > 512 || next.InactiveResourceExclusions.Revision >= ^uint64(0)-1 {
			return Config{}, ErrResourceExclusions
		}
		next.InactiveResourceExclusions.Manual = entries
		next.InactiveResourceExclusions.Revision++
		return s.commitResourceExclusions(ctx, expected, next)
	}
	if patch.RussianAutoUpdateAllowed != nil {
		p.Russian.AutoUpdateAllowed = *patch.RussianAutoUpdateAllowed
	}
	if patch.RussianEnabled != nil {
		p.Russian.Enabled = *patch.RussianEnabled
		if !p.Russian.Enabled {
			p.Russian.AutoUpdateAllowed = false
		}
	}
	if p.Exclusions == nil {
		p.Exclusions = &ResourceExclusions{Schema: 1, Manual: []ResourceMatch{}}
	}
	if p.Exclusions.Revision >= ^uint64(0)-1 {
		return Config{}, ErrResourceExclusions
	}
	if manual != nil {
		entries, err := NormalizeResourceMatches(*manual)
		if err != nil || len(entries) > 512 {
			return Config{}, ErrResourceExclusions
		}
		p.Exclusions.Manual = entries
	}
	if accepted != nil {
		if !p.Russian.Enabled || validateRussianSnapshot(accepted) != nil {
			return Config{}, ErrResourceExclusions
		}
		prior := p.Exclusions.RussianSnapshot
		if prior != nil && (prior.CatalogID != accepted.CatalogID || accepted.Revision <= prior.Revision) {
			return Config{}, ErrRevisionChanged
		}
		v := *accepted
		v.Entries, _ = NormalizeResourceMatches(accepted.Entries)
		p.Exclusions.RussianSnapshot = &v
	}
	p.Exclusions.Revision++
	p.Revision++
	if ValidateNetworkPolicy(p) != nil {
		return Config{}, ErrResourceExclusions
	}
	return s.commitResourceExclusions(ctx, expected, next)
}

func (s *Store) commitResourceExclusions(ctx context.Context, expected, next Config) (Config, error) {
	next.Revision++
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	if !reflect.DeepEqual(s.cfg, expected) {
		return Config{}, ErrRevisionChanged
	}
	previous := s.cfg
	s.cfg = next
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return Config{}, err
	}
	return cloneConfig(s.cfg), nil
}
