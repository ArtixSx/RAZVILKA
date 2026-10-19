package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
)

// SiteExclusions are the owner's "sites without bypass" in the whole-network
// mode. NFQWS2 enforces them itself for every connection, before its own
// selection (stock --hostlist-exclude and --ipset-exclude lists). A route that
// selects traffic by address cannot see names; an excluded address that falls
// inside such a route is refused as a conflict instead of being bypassed.
//
// Domains, CIDRs and Services are the owner's saved list. An excluded service
// keeps its route, so applied state and the project switch stay consistent;
// its catalog names and networks, frozen when the plan is built, are excluded
// in NFQWS2 instead, and a VPN or proxy route of it is refused.
type SiteExclusions struct {
	Domains        []string `json:"domains,omitempty"`
	CIDRs          []string `json:"cidrs,omitempty"`
	Services       []string `json:"services,omitempty"`
	ServiceDomains []string `json:"service_domains,omitempty"`
	ServiceCIDRs   []string `json:"service_cidrs,omitempty"`
}

const maxSiteExclusions = 4096

// ExcludedDomains and ExcludedCIDRs are everything NFQWS2 must not process.
func (s *SiteExclusions) ExcludedDomains() []string {
	if s == nil {
		return nil
	}
	return sortedUnique(append(slices.Clone(s.Domains), s.ServiceDomains...))
}

func (s *SiteExclusions) ExcludedCIDRs() []string {
	if s == nil {
		return nil
	}
	return sortedUnique(append(slices.Clone(s.CIDRs), s.ServiceCIDRs...))
}

func (s *SiteExclusions) excludesService(id string) bool {
	return s != nil && slices.Contains(s.Services, id)
}

func validateSiteExclusions(s *SiteExclusions) error {
	if s == nil {
		return nil
	}
	if len(s.Domains)+len(s.ServiceDomains) > maxSiteExclusions || len(s.CIDRs)+len(s.ServiceCIDRs) > maxSiteExclusions || len(s.Services) > maxSiteExclusions {
		return errors.New("too many sites without bypass")
	}
	for _, domain := range s.ExcludedDomains() {
		if !validManagedDomain(domain) {
			return fmt.Errorf("invalid excluded domain %q", domain)
		}
	}
	for _, value := range s.ExcludedCIDRs() {
		if _, err := siteExclusionPrefix(value); err != nil {
			return fmt.Errorf("invalid excluded address %q", value)
		}
	}
	for _, id := range s.Services {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, " \t\r\n\x00") {
			return fmt.Errorf("invalid excluded service %q", id)
		}
	}
	return nil
}

func canonicalSiteExclusions(s *SiteExclusions) *SiteExclusions {
	if s == nil || len(s.Domains)+len(s.CIDRs)+len(s.Services)+len(s.ServiceDomains)+len(s.ServiceCIDRs) == 0 {
		return nil
	}
	return &SiteExclusions{Domains: sortedUnique(slices.Clone(s.Domains)), CIDRs: sortedUnique(slices.Clone(s.CIDRs)), Services: sortedUnique(slices.Clone(s.Services)),
		ServiceDomains: sortedUnique(slices.Clone(s.ServiceDomains)), ServiceCIDRs: sortedUnique(slices.Clone(s.ServiceCIDRs))}
}

// LegacySiteExclusions reads the owner's saved "sites without bypass" for the
// whole-network mode. Only the manual list counts; the retained Russian
// snapshot has no switch outside the home-network mode and stays inactive.
// An exact name is excluded together with its subdomains, as nfqws2 matches.
// The caller adds the excluded services' catalog names and networks.
func LegacySiteExclusions(cfg config.Config) (*SiteExclusions, error) {
	if cfg.NetworkPolicy != nil || cfg.InactiveResourceExclusions == nil {
		return nil, nil
	}
	entries, err := config.NormalizeResourceMatches(cfg.InactiveResourceExclusions.Manual)
	if err != nil {
		return nil, err
	}
	out := &SiteExclusions{}
	for _, entry := range entries {
		switch entry.Kind {
		case "service":
			out.Services = append(out.Services, entry.Value)
		case "exact", "suffix":
			out.Domains = append(out.Domains, entry.Value)
		case "ip", "cidr":
			out.CIDRs = append(out.CIDRs, entry.Value)
		default:
			return nil, config.ErrResourceExclusions
		}
	}
	if err := validateSiteExclusions(out); err != nil {
		return nil, err
	}
	return canonicalSiteExclusions(out), nil
}

// SameSiteExclusions compares the owner's saved part of two exclusion sets.
// The catalog expansion of excluded services is frozen per plan and follows
// the catalog, not the owner's list.
func SameSiteExclusions(a, b *SiteExclusions) bool {
	a, b = canonicalSiteExclusions(a), canonicalSiteExclusions(b)
	if a == nil || b == nil {
		owner := func(s *SiteExclusions) bool { return s == nil || len(s.Domains)+len(s.CIDRs)+len(s.Services) == 0 }
		return owner(a) && owner(b)
	}
	return slices.Equal(a.Domains, b.Domains) && slices.Equal(a.CIDRs, b.CIDRs) && slices.Equal(a.Services, b.Services)
}

// PlanHonoursLegacyExclusions reports whether a committed whole-network plan
// already carries the saved site exclusions. A recovery that copies old
// routes must never revive them beneath exclusions saved after that plan.
func PlanHonoursLegacyExclusions(cfg config.Config, plan Plan) bool {
	sites, err := LegacySiteExclusions(cfg)
	return err == nil && SameSiteExclusions(sites, plan.SiteExclusions)
}

func siteExclusionPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()), nil
}

// A route is always named, so an unnamed one cannot slip through as empty.
func siteExclusionRouteName(route Route) string {
	if name := strings.TrimSpace(route.ServiceName); name != "" {
		return name
	}
	if id := strings.TrimSpace(route.ServiceID); id != "" {
		return id
	}
	return route.Resolved
}

func siteExclusionAddressRoute(route Route) bool {
	id := adapterID(route.Resolved)
	return id != "nfqws2" && id != "direct"
}

// siteExclusionConflicts names routes outside NFQWS2 whose addresses overlap
// an excluded address: such a route would carry the excluded site. Routes of
// excluded services are reported by siteExclusionRoutedServices instead.
func siteExclusionConflicts(s *SiteExclusions, routes []Route) []string {
	if s == nil {
		return nil
	}
	excluded := []netip.Prefix{}
	for _, value := range s.ExcludedCIDRs() {
		if prefix, err := siteExclusionPrefix(value); err == nil {
			excluded = append(excluded, prefix)
		}
	}
	conflicts := []string{}
	for _, route := range routes {
		if !siteExclusionAddressRoute(route) || s.excludesService(route.ServiceID) {
			continue
		}
		for _, value := range route.CIDRs {
			prefix, err := siteExclusionPrefix(value)
			if err != nil {
				continue
			}
			if slices.ContainsFunc(excluded, prefix.Overlaps) {
				conflicts = append(conflicts, siteExclusionRouteName(route))
				break
			}
		}
	}
	return sortedUnique(conflicts)
}

// siteExclusionRoutedServices names excluded services assigned to a VPN or
// proxy: only NFQWS2 can leave an enabled service's traffic unprocessed.
func siteExclusionRoutedServices(s *SiteExclusions, routes []Route) []string {
	names := []string{}
	for _, route := range routes {
		if s.excludesService(route.ServiceID) && siteExclusionAddressRoute(route) {
			names = append(names, siteExclusionRouteName(route))
		}
	}
	return sortedUnique(names)
}

// SiteExclusionsAffectRoutes reports whether an exclusion set changes what
// these routes do: NFQWS2 carries a route, or a VPN/proxy route conflicts
// with it. Otherwise the list waits, harmlessly, for the next Apply.
func SiteExclusionsAffectRoutes(s *SiteExclusions, routes []Route) bool {
	for _, route := range routes {
		if adapterID(route.Resolved) == "nfqws2" {
			return true
		}
	}
	return len(siteExclusionConflicts(s, routes))+len(siteExclusionRoutedServices(s, routes)) != 0
}
