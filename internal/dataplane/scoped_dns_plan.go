package dataplane

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

const scopedDNSAdapterID = "dns-scoped"

// ScopedDNSPlan is part of the SAME route digest and transaction. The first
// executor handles exact domains and IPv4 clients using router DNS on port 53.
// Application DoH, external DNS, IPv6 client transport and suffix bindings
// require separate executors; none is silently covered by these bindings.
type ScopedDNSPlan struct {
	Listener string             `json:"listener"`
	Ingress  string             `json:"ingress"`
	Bindings []ScopedDNSBinding `json:"bindings"`
	Probe    catalog.Probe      `json:"probe"`
}

type ScopedDNSBinding struct {
	ServiceID     string `json:"service_id"`
	Client        string `json:"client"`
	Domain        string `json:"domain"`
	ProfileID     string `json:"profile_id"`
	ProfileDigest string `json:"profile_digest"`
}

func validateScopedDNSPlan(p *ScopedDNSPlan, routes []Route) error {
	if p == nil {
		return nil
	}
	fail := errors.New("scoped DNS requires exact private IPv4 clients/domains on DIRECT routes and a bound high-port LAN listener")
	listen, err := netip.ParseAddrPort(p.Listener)
	if err != nil || !listen.Addr().Is4() || !listen.Addr().IsPrivate() || listen.Port() < 1024 || listen.Port() == 8787 || !proxyFirewallInterface.MatchString(p.Ingress) || p.Ingress == "lo" || len(p.Bindings) == 0 || len(p.Bindings) > 32 {
		return fail
	}
	services := map[string]Route{}
	for _, r := range routes {
		if _, exists := services[r.ServiceID]; exists {
			return fail
		}
		services[r.ServiceID] = r
	}
	seen := map[string]bool{}
	service := services[p.Bindings[0].ServiceID]
	origin, originErr := url.Parse(p.Probe.URL)
	if originErr != nil || origin.Scheme != "https" || origin.User != nil || !p.Probe.Required || p.Probe.URL != service.ProbeURL || catalog.Validate(catalog.Catalog{Services: []catalog.Service{{ID: service.ServiceID, Name: service.ServiceName, Category: "dns", Strategy: []string{"direct"}, Domains: service.Domains, ProbeURL: service.ProbeURL, Probes: []catalog.Probe{p.Probe}}}}) != nil {
		return errors.New("scoped DNS requires a catalog-owned HTTPS scenario")
	}
	probeBound := false
	for _, b := range p.Bindings {
		if b.Client != p.Bindings[0].Client || b.ServiceID != p.Bindings[0].ServiceID || b.ProfileID != p.Bindings[0].ProfileID {
			return errors.New("first scoped DNS executor supports one service, profile and client per policy")
		}
		ip, err := netip.ParseAddr(b.Client)
		domain, domainErr := config.PolicyDomain(b.Domain)
		digest, digestErr := hex.DecodeString(b.ProfileDigest)
		r, exists := services[b.ServiceID]
		key := b.Client + "\x00" + b.Domain
		if err != nil || !ip.Is4() || !ip.IsPrivate() || ip == listen.Addr() || ip.String() != b.Client || domainErr != nil || domain != b.Domain || digestErr != nil || len(digest) != 32 || strings.ToLower(b.ProfileDigest) != b.ProfileDigest || b.ProfileID == "" || seen[key] || !exists || r.Resolved != "direct" || !slices.Contains(r.Domains, b.Domain) || !slices.Contains(r.Sources, b.Client+"/32") {
			return fail
		}
		seen[key] = true
		probeBound = probeBound || b.Domain == strings.ToLower(origin.Hostname())
	}
	if !probeBound {
		return errors.New("scoped DNS probe hostname is not bound to the chosen resolver")
	}
	return nil
}

// A route-only caller must not accidentally orphan an already committed DNS
// policy. It must carry the binding forward or explicitly retire the adapter
// inside the same rollback-capable transaction.
func (m *Manager) checkScopedDNSContinuation(p Plan) error {
	if err := validateScopedDNSPlan(p.DNS, p.Routes); err != nil {
		return err
	}
	has := slices.Contains(p.Adapters, scopedDNSAdapterID)
	if has != (p.DNS != nil) || has && p.Noop {
		return errors.New("scoped DNS plan lacks its transaction owner")
	}
	old, exists, err := m.committedLocked()
	if err != nil {
		return executionJournalError(err)
	}
	if exists && old.DNS != nil && p.DNS == nil && !slices.Contains(p.RetiringAdapters, scopedDNSAdapterID) {
		return errors.New("existing scoped DNS must be retained or explicitly retired")
	}
	return nil
}
