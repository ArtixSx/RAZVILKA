package dnscontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

// NetworkPolicyDNSPlan is a detached DNS definition inside the existing
// Manager's reviewed plan. It owns no lifecycle, root, journal or capability.
// The NET participant binds its listener/physical leases to the same generation.
type NetworkPolicyDNSPlan struct {
	Schema               int                               `json:"schema"`
	Generation           string                            `json:"generation"`
	Digest               string                            `json:"digest"`
	DefaultProfileID     string                            `json:"default_profile_id"`
	DefaultProfileDigest string                            `json:"default_profile_digest"`
	Bindings             []NetworkPolicyDNSReviewedBinding `json:"bindings,omitempty"`
	Exclusions           NetworkPolicyDNSExclusionStamp    `json:"exclusions"`
}

type NetworkPolicyDNSReviewedBinding struct {
	ClientDNSBinding
	ProfileDigest string `json:"profile_digest"`
}

func CloneNetworkPolicyDNSPlan(p *NetworkPolicyDNSPlan) *NetworkPolicyDNSPlan {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Bindings = slices.Clone(p.Bindings)
	return &copy
}

func networkPolicyDNSHash(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func networkPolicyDNSPlanDigest(p *NetworkPolicyDNSPlan) string {
	copy := *p
	copy.Digest = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ValidateNetworkPolicyDNSPlan(p *NetworkPolicyDNSPlan) error {
	if p == nil || p.Schema != 2 || !networkPolicyDNSHash(p.Generation) || !networkPolicyDNSHash(p.Digest) || !networkPolicyDNSHash(p.DefaultProfileDigest) || !networkPolicyDNSHash(p.Exclusions.Digest) || len(p.Bindings) > 128 {
		return ErrNetworkPolicyDNS
	}
	if _, ok := profileByID(p.DefaultProfileID); !ok {
		return ErrNetworkPolicyDNS
	}
	seen := make(map[scopedDNSKey]bool)
	for _, b := range p.Bindings {
		host, err := normalizeCandidateHostname(b.Domain)
		_, literal := netip.ParseAddr(host)
		_, profileOK := profileByID(b.ProfileID)
		key := scopedDNSKey{b.Client, host}
		if !b.Client.IsValid() || b.Client.Is4In6() || b.Client.Zone() != "" || !b.Client.IsGlobalUnicast() && !b.Client.IsLoopback() || err != nil || host != b.Domain || host == "home.arpa" || literal == nil || !profileOK || !networkPolicyDNSHash(b.ProfileDigest) || seen[key] {
			return ErrNetworkPolicyDNS
		}
		seen[key] = true
	}
	if p.Digest != networkPolicyDNSPlanDigest(p) {
		return ErrNetworkPolicyDNS
	}
	return nil
}

// FreezeNetworkPolicyDNSPlan captures every production provider identity under
// the same existing Manager read lock. Diagnostic reachability is not authority.
func (m *Manager) FreezeNetworkPolicyDNSPlan(ctx context.Context, generation, defaultProfile string, bindings []ClientDNSBinding, exclusions *NetworkPolicyDNSExclusions) (*NetworkPolicyDNSPlan, error) {
	if err := exclusions.current(ctx); err != nil {
		return nil, err
	}
	p, err := m.freezeNetworkPolicyDNSPlan(generation, defaultProfile, bindings, exclusions.Stamp())
	if err != nil {
		return nil, err
	}
	if err := exclusions.current(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (m *Manager) freezeNetworkPolicyDNSPlan(generation, defaultProfile string, bindings []ClientDNSBinding, stamp NetworkPolicyDNSExclusionStamp) (*NetworkPolicyDNSPlan, error) {
	if m == nil || !networkPolicyDNSHash(generation) || len(bindings) > 128 {
		return nil, ErrNetworkPolicyDNS
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	identity, err := scopedProfileIdentity(m.doc, defaultProfile)
	if err != nil {
		return nil, err
	}
	p := &NetworkPolicyDNSPlan{Schema: 2, Generation: generation, DefaultProfileID: defaultProfile, DefaultProfileDigest: identity, Exclusions: stamp}
	for _, binding := range bindings {
		identity, err := scopedProfileIdentity(m.doc, binding.ProfileID)
		if err != nil {
			return nil, err
		}
		p.Bindings = append(p.Bindings, NetworkPolicyDNSReviewedBinding{binding, identity})
	}
	slices.SortFunc(p.Bindings, func(a, b NetworkPolicyDNSReviewedBinding) int {
		if cmp := a.Client.Compare(b.Client); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Domain, b.Domain)
	})
	p.Digest = networkPolicyDNSPlanDigest(p)
	if err := ValidateNetworkPolicyDNSPlan(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Requires m.mu.RLock. The caller retains the frozen digests; checking current
// production trust without matching those digests would silently change review.
func (m *Manager) checkNetworkPolicyDNSDefinition(p *NetworkPolicyDNSPlan) error {
	identity, err := scopedProfileIdentity(m.doc, p.DefaultProfileID)
	if err != nil || identity != p.DefaultProfileDigest {
		return ErrServiceDNSChanged
	}
	for _, b := range p.Bindings {
		identity, err := scopedProfileIdentity(m.doc, b.ProfileID)
		if err != nil || identity != b.ProfileDigest {
			return ErrServiceDNSChanged
		}
	}
	return nil
}

// CheckNetworkPolicyDNSPlan is the read-only Stage/Validate/Health boundary
// for the existing NET participant. It neither constructs sockets nor changes
// DNS settings or ownership records.
func (m *Manager) CheckNetworkPolicyDNSPlan(ctx context.Context, plan *NetworkPolicyDNSPlan, exclusions *NetworkPolicyDNSExclusions) error {
	if m == nil || plan == nil || len(plan.Bindings) > 128 {
		return ErrNetworkPolicyDNS
	}
	p := CloneNetworkPolicyDNSPlan(plan)
	if err := ValidateNetworkPolicyDNSPlan(p); err != nil {
		return err
	}
	if exclusions == nil || p.Exclusions != exclusions.Stamp() {
		return ErrNetworkPolicyDNS
	}
	if err := exclusions.current(ctx); err != nil {
		return err
	}
	m.mu.RLock()
	err := m.checkNetworkPolicyDNSDefinition(p)
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	return exclusions.current(ctx)
}

// NewNetworkPolicyDNSResolverForPlan consumes the reviewed definition, never
// a fresh set of profiles obtained after review. Existing per-query/send checks
// continue fencing the provider identities selected here.
func (m *Manager) NewNetworkPolicyDNSResolverForPlan(ctx context.Context, plan *NetworkPolicyDNSPlan, authority NetworkPolicyDNSAuthority, guard func(context.Context) error, admit func(context.Context, netip.Addr, string) (NetworkPolicyDNSAdmission, error), exclusions *NetworkPolicyDNSExclusions) (*NetworkPolicyDNSResolver, error) {
	if m == nil || plan == nil || len(plan.Bindings) > 128 {
		return nil, ErrNetworkPolicyDNS
	}
	p := CloneNetworkPolicyDNSPlan(plan)
	if ValidateNetworkPolicyDNSPlan(p) != nil || authority.Generation != p.Generation || authority.Exclusions != p.Exclusions {
		return nil, ErrNetworkPolicyDNS
	}
	m.mu.RLock()
	err := m.checkNetworkPolicyDNSDefinition(p)
	m.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	bindings := make([]ClientDNSBinding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		bindings = append(bindings, b.ClientDNSBinding)
	}
	r, err := m.NewNetworkPolicyDNSResolver(ctx, p.DefaultProfileID, bindings, authority, guard, admit, exclusions)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	if err := m.checkNetworkPolicyDNSDefinition(p); err != nil {
		m.mu.RUnlock()
		return nil, err
	}
	// A provider changed and reverted during construction must not leave a
	// resolver bound to the intervening unreviewed provider identity.
	choices := []scopedDNSChoice{r.choice}
	if r.service != nil {
		for _, choice := range r.service.choices {
			choices = append(choices, choice)
		}
	}
	for _, choice := range choices {
		current, ok := providerByIDFor(choice.provider.ID, m.doc)
		if !ok || !reflect.DeepEqual(current, choice.provider) {
			m.mu.RUnlock()
			return nil, ErrServiceDNSChanged
		}
	}
	m.mu.RUnlock()
	if err := exclusions.current(ctx); err != nil {
		return nil, err
	}
	r.frozenPlan = CloneNetworkPolicyDNSPlan(p)
	return r, nil
}
