package dataplane

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/ArtixSx/razvilka/internal/config"
)

// SiteExclusions are the owner's "sites without bypass" in the whole-network
// mode. NFQWS2 enforces them itself for every connection, before its own
// selection (stock --hostlist-exclude and --ipset-exclude lists). A route that
// selects traffic by address cannot see names; an excluded address that falls
// inside such a route is refused as a conflict instead of being bypassed.
type SiteExclusions struct {
	Domains []string `json:"domains,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
}

const maxSiteExclusions = 4096

func validateSiteExclusions(s *SiteExclusions) error {
	if s == nil {
		return nil
	}
	if len(s.Domains) > maxSiteExclusions || len(s.CIDRs) > maxSiteExclusions {
		return errors.New("too many sites without bypass")
	}
	for _, domain := range s.Domains {
		if !validManagedDomain(domain) {
			return fmt.Errorf("invalid excluded domain %q", domain)
		}
	}
	for _, value := range s.CIDRs {
		if _, err := siteExclusionPrefix(value); err != nil {
			return fmt.Errorf("invalid excluded address %q", value)
		}
	}
	return nil
}

func canonicalSiteExclusions(s *SiteExclusions) *SiteExclusions {
	if s == nil || len(s.Domains)+len(s.CIDRs) == 0 {
		return nil
	}
	return &SiteExclusions{Domains: sortedUnique(slices.Clone(s.Domains)), CIDRs: sortedUnique(slices.Clone(s.CIDRs))}
}

// LegacySiteExclusions reads the owner's saved "sites without bypass" for the
// whole-network mode: names and addresses for NFQWS2, and services that are
// not bypassed at all. Only the manual list counts; the retained Russian
// snapshot has no switch outside the home-network mode and stays inactive.
// An exact name is excluded together with its subdomains, as nfqws2 matches.
func LegacySiteExclusions(cfg config.Config) (*SiteExclusions, map[string]bool, error) {
	services := map[string]bool{}
	if cfg.NetworkPolicy != nil || cfg.InactiveResourceExclusions == nil {
		return nil, services, nil
	}
	entries, err := config.NormalizeResourceMatches(cfg.InactiveResourceExclusions.Manual)
	if err != nil {
		return nil, nil, err
	}
	out := &SiteExclusions{}
	for _, entry := range entries {
		switch entry.Kind {
		case "service":
			services[entry.Value] = true
		case "exact", "suffix":
			out.Domains = append(out.Domains, entry.Value)
		case "ip", "cidr":
			out.CIDRs = append(out.CIDRs, entry.Value)
		default:
			return nil, nil, config.ErrResourceExclusions
		}
	}
	if err := validateSiteExclusions(out); err != nil {
		return nil, nil, err
	}
	return canonicalSiteExclusions(out), services, nil
}

// SameSiteExclusions compares two plans' exclusions after canonical ordering.
func SameSiteExclusions(a, b *SiteExclusions) bool {
	a, b = canonicalSiteExclusions(a), canonicalSiteExclusions(b)
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return slices.Equal(a.Domains, b.Domains) && slices.Equal(a.CIDRs, b.CIDRs)
}

// PlanHonoursLegacyExclusions reports whether a committed whole-network plan
// already carries the saved site exclusions and no route of an excluded
// service. A recovery that copies old routes must never revive them beneath
// exclusions saved after that plan was applied.
func PlanHonoursLegacyExclusions(cfg config.Config, plan Plan) bool {
	sites, services, err := LegacySiteExclusions(cfg)
	if err != nil || !SameSiteExclusions(sites, plan.SiteExclusions) {
		return false
	}
	for _, route := range plan.Routes {
		if services[route.ServiceID] {
			return false
		}
	}
	return true
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

// siteExclusionConflicts names routes outside NFQWS2 whose addresses overlap
// an excluded address: such a route would carry the excluded site.
func siteExclusionConflicts(s *SiteExclusions, routes []Route) []string {
	if s == nil {
		return nil
	}
	excluded := []netip.Prefix{}
	for _, value := range s.CIDRs {
		if prefix, err := siteExclusionPrefix(value); err == nil {
			excluded = append(excluded, prefix)
		}
	}
	conflicts := []string{}
	for _, route := range routes {
		if id := adapterID(route.Resolved); id == "nfqws2" || id == "direct" {
			continue
		}
		for _, value := range route.CIDRs {
			prefix, err := siteExclusionPrefix(value)
			if err != nil {
				continue
			}
			for _, other := range excluded {
				if prefix.Overlaps(other) {
					conflicts = append(conflicts, route.ServiceName)
					break
				}
			}
		}
	}
	return sortedUnique(conflicts)
}
