package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
)

var ErrDefaultRouteConsent = errors.New("explicit default route consent is missing or changed")

// DefaultRouteGrant is explicit approved intent for one exact resolved path.
// Source IDs/kinds and protocols are selected permissions, never node health or
// executable proof. Unknown nodes are not covered by a provider class alone.
type DefaultRouteGrant struct {
	Resolved      string   `json:"resolved"`
	ProviderClass string   `json:"provider_class"`
	ProviderID    string   `json:"provider_id"`
	SourceIDs     []string `json:"source_ids"`
	SourceKinds   []string `json:"source_kinds"`
	Protocols     []string `json:"protocols"`
}

// DefaultRouteConsent belongs to the existing revisioned config. Its digest is
// a comparison only. Actual consent readers must retain the real Store/control
// owner and original operation capability; this record cannot issue a handle.
type DefaultRouteConsent struct {
	Schema           int                 `json:"schema"`
	InstallationID   string              `json:"installation_id"`
	Sequence         uint64              `json:"sequence"`
	ApprovalRevision uint64              `json:"approval_revision"`
	ConfigRevision   uint64              `json:"config_revision"`
	Policy           *NetworkPolicy      `json:"policy"`
	Grants           []DefaultRouteGrant `json:"grants"`
	Digest           string              `json:"digest"`
}

func CloneDefaultRouteConsent(in *DefaultRouteConsent) *DefaultRouteConsent {
	if in == nil {
		return nil
	}
	out := *in
	out.Policy = CloneNetworkPolicy(in.Policy)
	out.Grants = slices.Clone(in.Grants)
	for i := range out.Grants {
		out.Grants[i].SourceIDs = slices.Clone(in.Grants[i].SourceIDs)
		out.Grants[i].SourceKinds = slices.Clone(in.Grants[i].SourceKinds)
		out.Grants[i].Protocols = slices.Clone(in.Grants[i].Protocols)
	}
	return &out
}

func DefaultRouteConsentDigest(in *DefaultRouteConsent) string {
	if in == nil {
		return ""
	}
	copy := CloneDefaultRouteConsent(in)
	copy.ConfigRevision, copy.Digest = 0, ""
	raw, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func consentHex(value string, length int) bool {
	return len(value) == length && strings.Trim(value, "0123456789abcdef") == ""
}

func ValidateDefaultRouteGrant(g DefaultRouteGrant) error {
	engine, id, exactNode := strings.Cut(g.Resolved, ":")
	if exactNode && (engine == "xray" || engine == "sing-box") && strings.HasPrefix(id, "node-") && policyIdentifier.MatchString(id) {
		if g.ProviderClass != "node" || g.ProviderID != id || len(g.SourceIDs) == 0 || len(g.SourceKinds) != len(g.SourceIDs) || !policyIDs(g.SourceIDs, 32) || len(g.Protocols) == 0 || !policyIDs(g.Protocols, 16) {
			return ErrDefaultRouteConsent
		}
		for _, kind := range g.SourceKinds {
			if !slices.Contains([]string{"manual", "file", "subscription", "community", "legacy"}, kind) {
				return ErrDefaultRouteConsent
			}
		}
		for _, protocol := range g.Protocols {
			if !slices.Contains([]string{"vless", "vmess", "trojan", "shadowsocks", "socks", "hysteria2", "tuic"}, protocol) {
				return ErrDefaultRouteConsent
			}
		}
		return nil
	}
	if len(g.SourceIDs) != 0 || len(g.SourceKinds) != 0 || len(g.Protocols) != 0 {
		return ErrDefaultRouteConsent
	}
	if exactNode && (engine == "wireguard" || engine == "amneziawg") && policyIdentifier.MatchString(id) && g.ProviderClass == "private_profile" && g.ProviderID == id {
		return nil
	}
	switch g.Resolved {
	case "usque", "warp-wg":
		if g.ProviderClass == "cloudflare" && g.ProviderID == g.Resolved {
			return nil
		}
	case "wireguard", "amneziawg":
		if g.ProviderClass == "private_profile" && policyIdentifier.MatchString(g.ProviderID) {
			return nil
		}
	}
	return ErrDefaultRouteConsent
}

func ValidateDefaultRouteConsent(c *DefaultRouteConsent) error {
	if c == nil {
		return nil
	}
	if c.Schema != 1 || !consentHex(c.InstallationID, 32) || c.Sequence == 0 || c.ApprovalRevision == 0 || c.ConfigRevision < c.ApprovalRevision || ValidateNetworkPolicy(c.Policy) != nil || c.Policy == nil || c.Policy.Schema != 2 || c.Policy.Traffic.Mode != "all_except" || !c.Policy.Traffic.AllExceptAllowed || len(c.Grants) == 0 || len(c.Grants) > 64 || !consentHex(c.Digest, 64) || c.Digest != DefaultRouteConsentDigest(c) {
		return ErrDefaultRouteConsent
	}
	seen := map[string]bool{}
	for _, g := range c.Grants {
		if ValidateDefaultRouteGrant(g) != nil || seen[g.Resolved] {
			return ErrDefaultRouteConsent
		}
		seen[g.Resolved] = true
	}
	return nil
}

// CurrentDefaultRouteConsent checks saved intent only. Actual control epoch,
// current source/material and original configured owners remain mandatory.
func CurrentDefaultRouteConsent(cfg Config) bool {
	c := cfg.DefaultRouteConsent
	return c != nil && ValidateDefaultRouteConsent(c) == nil && c.ConfigRevision == cfg.Revision && reflect.DeepEqual(c.Policy, cfg.NetworkPolicy)
}

// ApproveDefaultRouteConsent is the exact config-file CAS used solely by the
// authenticated explicit review writer. It saves intent, never applied routes.
// Caller first verifies every selected source/node/provider against real owners
// under original operation/control admission. Legacy AllExceptAllowed is not
// promoted automatically. Subsequent unrelated config revisions revoke consent.
func (s *Store) ApproveDefaultRouteConsent(ctx context.Context, expected Config, policy *NetworkPolicy, grants []DefaultRouteGrant, installationID string, sequence uint64) (DefaultRouteConsent, error) {
	if ctx == nil || policy == nil || expected.Revision == ^uint64(0) {
		return DefaultRouteConsent{}, ErrDefaultRouteConsent
	}
	previousPolicyRevision := uint64(0)
	if expected.NetworkPolicy != nil {
		previousPolicyRevision = expected.NetworkPolicy.Revision
	}
	if previousPolicyRevision >= ^uint64(0)-1 || policy.Revision != previousPolicyRevision+1 {
		return DefaultRouteConsent{}, ErrRevisionChanged
	}
	c := &DefaultRouteConsent{Schema: 1, InstallationID: installationID, Sequence: sequence, ApprovalRevision: expected.Revision + 1, ConfigRevision: expected.Revision + 1, Policy: CloneNetworkPolicy(policy), Grants: grants}
	c = CloneDefaultRouteConsent(c)
	c.Digest = DefaultRouteConsentDigest(c)
	if ValidateDefaultRouteConsent(c) != nil {
		return DefaultRouteConsent{}, ErrDefaultRouteConsent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return DefaultRouteConsent{}, err
	}
	if !reflect.DeepEqual(s.cfg, expected) {
		return DefaultRouteConsent{}, ErrRevisionChanged
	}
	previous := cloneConfig(s.cfg)
	s.cfg.NetworkPolicy = CloneNetworkPolicy(policy)
	s.cfg.DefaultRouteConsent = c
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = previous
		return DefaultRouteConsent{}, err
	}
	return *CloneDefaultRouteConsent(c), nil
}
