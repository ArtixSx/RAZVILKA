package app

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// nodeResourceAdmission is a negative observation, never the positive provider,
// path or physical client proof. Existing owners must still supply those.
// It closes SAME Store, complete config and disk image in a short leaf call;
// no protocol, App gate or recursive Store call runs under its read lock.
func (a *App) nodeResourceAdmission(ctx context.Context, expected config.Config, service catalog.Service, host string, address netip.Addr) error {
	if a.Store == nil || !expected.Services[service.ID].Enabled {
		return dataplane.ErrNodeResourceDenied
	}
	definitions := a.catalogSnapshot()
	found := false
	for _, actual := range definitions.Services {
		if actual.ID == service.ID {
			found = reflect.DeepEqual(actual, service)
			break
		}
	}
	if !found {
		return errors.Join(dataplane.ErrNodeResourceDenied, dataplane.ErrReviewChanged)
	}
	err := a.Store.WithResourceExclusionObservation(ctx, expected, func(set config.EffectiveExclusionSet) error {
		admit := func(target config.ResourceTarget) error {
			excluded, err := set.Matches(target)
			if err != nil || excluded {
				return dataplane.ErrNodeResourceDenied
			}
			return nil
		}
		if err := admit(config.ResourceTarget{ServiceID: service.ID}); err != nil {
			return err
		}
		checkHost := func(name string, ip netip.Addr) error {
			target := config.ResourceTarget{Address: ip}
			if literal, err := netip.ParseAddr(name); err == nil {
				if ip.IsValid() && literal != ip {
					return dataplane.ErrNodeResourceDenied
				}
				target.Address = literal
			} else {
				target.Domain = name
			}
			if err := admit(target); err != nil {
				return err
			}
			// Auxiliary endpoints need not be positive entries, but a known
			// catalog service exclusion must also win over their hostnames.
			for _, known := range definitions.Services {
				for _, domain := range known.Domains {
					if strings.EqualFold(name, domain) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(domain)) {
						if err := admit(config.ResourceTarget{ServiceID: known.ID}); err != nil {
							return err
						}
						break
					}
				}
			}
			return nil
		}
		// A required scenario cannot be omitted and replaced with a partial
		// service PASS just because the checker selects another first probe.
		urls := []string{}
		if service.ProbeURL != "" {
			urls = append(urls, service.ProbeURL)
		}
		for _, probe := range service.Probes {
			if probe.Required && probe.URL != "" {
				urls = append(urls, probe.URL)
			}
		}
		for _, raw := range urls {
			u, err := url.Parse(raw)
			if err != nil || u.Hostname() == "" {
				return dataplane.ErrNodeResourceDenied
			}
			if err := checkHost(u.Hostname(), netip.Addr{}); err != nil {
				return err
			}
		}
		if host != "" || address.IsValid() {
			return checkHost(host, address)
		}
		return nil
	})
	if err != nil {
		return errors.Join(dataplane.ErrNodeResourceDenied, err)
	}
	return nil
}

func (a *App) nodeServiceResourceAdmission(ctx context.Context, cfg config.Config, id string) error {
	for _, service := range a.catalogSnapshot().Services {
		if service.ID == id {
			return a.nodeResourceAdmission(ctx, cfg, service, "", netip.Addr{})
		}
	}
	return dataplane.ErrNodeResourceDenied
}
