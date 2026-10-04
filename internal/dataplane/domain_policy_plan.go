package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
)

// DomainPolicyRuntimePlan is only the serialized definition component of the
// existing Manager plan. It has no producer, listener, journal or capability.
// Names and current scope still come from the actual pre-outbound flow owner.
type DomainPolicyRuntimePlan struct {
	Schema     int                       `json:"schema"`
	Generation string                    `json:"generation"`
	Digest     string                    `json:"digest"`
	Policy     *config.NetworkPolicy     `json:"policy"`
	Scope      autonomy.ScopeObservation `json:"scope"`
	GuestOptIn []string                  `json:"guest_opt_in,omitempty"`
	Services   []DomainPolicyService     `json:"services,omitempty"`
}

func CloneDomainPolicyRuntimePlan(p *DomainPolicyRuntimePlan) *DomainPolicyRuntimePlan {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Policy = config.CloneNetworkPolicy(p.Policy)
	copy.Scope = cloneDomainPolicyScope(p.Scope)
	copy.GuestOptIn = slices.Clone(p.GuestOptIn)
	copy.Services = slices.Clone(p.Services)
	for i := range copy.Services {
		copy.Services[i].Domains = slices.Clone(p.Services[i].Domains)
		copy.Services[i].DomainSuffixes = slices.Clone(p.Services[i].DomainSuffixes)
		copy.Services[i].CIDRs = slices.Clone(p.Services[i].CIDRs)
		copy.Services[i].Sources = slices.Clone(p.Services[i].Sources)
	}
	return &copy
}

func domainPolicyRuntimeDigest(p *DomainPolicyRuntimePlan) string {
	copy := *p
	copy.Digest = ""
	data, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func FreezeDomainPolicyRuntimePlan(generation string, policy *config.NetworkPolicy, scope autonomy.ScopeObservation, guestOptIn []string, services []DomainPolicyService, now time.Time) (*DomainPolicyRuntimePlan, error) {
	compiled, err := CompileDomainPolicy(generation, policy, scope, guestOptIn, services, now)
	if err != nil {
		return nil, err
	}
	p := &DomainPolicyRuntimePlan{Schema: 1, Generation: generation, Policy: compiled.policy, Scope: compiled.scope, GuestOptIn: compiled.guests, Services: compiled.services}
	p.Digest = domainPolicyRuntimeDigest(p)
	if p.Digest == "" {
		return nil, ErrDomainPolicy
	}
	return p, nil
}

// Validation of retained intent is independent of current freshness, so a
// Stop/recovery can inventory the old definition. It grants no new outbound.
// CompileDomainPolicyForPlan still checks real time before a new use.
func ValidateDomainPolicyRuntimePlan(p *DomainPolicyRuntimePlan) error {
	if p == nil || p.Schema != 1 || !lanPolicyHash(p.Generation) || !lanPolicyHash(p.Digest) || len(p.Services) > 128 || len(p.GuestOptIn) > 16 || len(p.Scope.Segments) > 16 || len(p.Scope.Devices) > 512 || p.Scope.ObservedAt.IsZero() {
		return ErrDomainPolicy
	}
	if _, err := CompileDomainPolicy(p.Generation, p.Policy, p.Scope, p.GuestOptIn, p.Services, p.Scope.ObservedAt); err != nil {
		return err
	}
	if p.Digest != domainPolicyRuntimeDigest(p) {
		return ErrDomainPolicy
	}
	return nil
}

func CompileDomainPolicyForPlan(plan *DomainPolicyRuntimePlan, now time.Time) (*DomainPolicy, error) {
	if err := ValidateDomainPolicyRuntimePlan(plan); err != nil {
		return nil, err
	}
	p := CloneDomainPolicyRuntimePlan(plan)
	if err := ValidateDomainPolicyRuntimePlan(p); err != nil {
		return nil, err
	}
	return CompileDomainPolicy(p.Generation, p.Policy, p.Scope, p.GuestOptIn, p.Services, now)
}
