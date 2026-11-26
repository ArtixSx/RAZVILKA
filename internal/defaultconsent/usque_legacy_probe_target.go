package defaultconsent

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
)

// LegacyUSQUEProbeTargetReview is a finite negative observer for one saved
// CIDR service. It owns neither a default grant nor any client or route effect.
type LegacyUSQUEProbeTargetReview struct {
	self     *LegacyUSQUEProbeTargetReview
	owner    *Owner
	original context.Context
	cfg      config.Config
	service  string
	probeURL string
	known    map[string]legacyProbeTargets
}

type legacyProbeTargets struct {
	domains []string
	pins    []netip.Prefix
}

func (o *Owner) ReviewLegacyUSQUEProbeTargets(ctx context.Context, expected config.Config, frozen catalog.Catalog, id string) (*LegacyUSQUEProbeTargetReview, error) {
	r := &LegacyUSQUEProbeTargetReview{owner: o, original: ctx, service: id}
	r.self = r
	err := o.withOwner(ctx, func() error {
		r.cfg = o.store.Get()
		if !reflect.DeepEqual(r.cfg, expected) || r.cfg.NetworkPolicy != nil || r.cfg.AppliedNetworkPolicy != nil ||
			r.cfg.SafeMode || r.cfg.ServiceControl.Stopped || r.cfg.ServiceControl.EffectiveMode() == "manual" || !r.cfg.Services[id].Enabled {
			return ErrProbeTargetUnknown
		}
		if err := o.control.Current(ctx); err != nil {
			return err
		}
		if catalog.Validate(frozen) != nil {
			return ErrProbeTargetUnknown
		}
		r.known = make(map[string]legacyProbeTargets, len(frozen.Services))
		for _, s := range frozen.Services {
			if err := ctx.Err(); err != nil {
				return err
			}
			targets, err := compileLegacyProbeTargets(s)
			if err != nil {
				return err
			}
			r.known[s.ID] = targets
			if s.ID == id {
				if !legacyUSQUELiteralService(s) {
					return ErrProbeTargetUnknown
				}
				r.probeURL = s.ProbeURL
			}
		}
		if r.probeURL == "" {
			return ErrProbeTargetUnknown
		}
		return o.store.WithResourceExclusionObservation(ctx, r.cfg, func(set config.EffectiveExclusionSet) error {
			return matchProbeTarget(set, config.ResourceTarget{ServiceID: id})
		})
	})
	if err != nil {
		return nil, errors.Join(ErrChanged, err)
	}
	return r, nil
}

func legacyUSQUELiteralService(service catalog.Service) bool {
	u, err := url.Parse(service.ProbeURL)
	if err != nil || publicfetch.ValidateURL(service.ProbeURL) != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		len(service.Domains) != 0 || len(service.SourceRefs) != 0 || !slices.Contains(service.Strategy, "usque") {
		return false
	}
	pin, err := netip.ParseAddr(u.Hostname())
	if err != nil || !pin.Is4() || !publicfetch.PublicAddress(pin) || pin.String() != u.Hostname() {
		return false
	}
	return slices.ContainsFunc(service.CIDRs, func(raw string) bool {
		prefix, err := netip.ParsePrefix(raw)
		return err == nil && prefix.Contains(pin)
	})
}

func compileLegacyProbeTargets(s catalog.Service) (legacyProbeTargets, error) {
	var out legacyProbeTargets
	for _, raw := range s.CIDRs {
		pin, err := netip.ParsePrefix(raw)
		if err != nil {
			return out, ErrProbeTargetUnknown
		}
		out.pins = append(out.pins, pin)
	}
	names := slices.Clone(s.Domains)
	urls := []string{s.ProbeURL}
	for _, probe := range s.Probes {
		urls = append(urls, probe.URL)
	}
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return out, ErrProbeTargetUnknown
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
			out.pins = append(out.pins, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		names = append(names, u.Hostname())
	}
	for _, raw := range names {
		domain, err := config.ResourceHostname(raw)
		if err != nil {
			return out, ErrProbeTargetUnknown
		}
		out.domains = append(out.domains, domain)
	}
	return out, nil
}

func (r *LegacyUSQUEProbeTargetReview) MatchesService(id, rawURL string) bool {
	return r != nil && r.self == r && r.service == id && r.probeURL == rawURL
}

func (r *LegacyUSQUEProbeTargetReview) CheckProbeTarget(ctx context.Context, hostname string, pins []netip.Addr) error {
	if r == nil || r.self != r || ctx == nil || len(pins) > 64 || hostname == "" && len(pins) == 0 {
		return ErrProbeTargetUnknown
	}
	name := ""
	if hostname != "" {
		var err error
		name, err = config.ResourceHostname(hostname)
		if err != nil {
			return ErrProbeTargetUnknown
		}
	}
	pins = slices.Clone(pins)
	o := r.owner
	// The Gate admits at most one original exclusive operation. Holding the
	// original live operation across the supplied context rules out later or
	// foreign leases, and the Store leaf never reenters either owner.
	return o.gate.WithExclusiveContext(r.original, func() error {
		return o.withOwner(ctx, func() error {
			if err := o.control.Current(ctx); err != nil {
				return err
			}
			err := o.store.WithResourceExclusionObservation(ctx, r.cfg, func(set config.EffectiveExclusionSet) error {
				if err := matchProbeTarget(set, config.ResourceTarget{ServiceID: r.service}); err != nil {
					return err
				}
				if name != "" {
					if err := matchProbeTarget(set, config.ResourceTarget{Domain: name}); err != nil {
						return err
					}
				}
				for _, pin := range pins {
					if !pin.IsValid() {
						return ErrProbeTargetUnknown
					}
					if err := matchProbeTarget(set, config.ResourceTarget{Domain: name, Address: pin}); err != nil {
						return err
					}
				}
				return r.checkKnownServiceExclusions(ctx, set, name, pins)
			})
			return errors.Join(err, o.control.Current(ctx))
		})
	})
}

func (r *LegacyUSQUEProbeTargetReview) checkKnownServiceExclusions(ctx context.Context, set config.EffectiveExclusionSet, name string, pins []netip.Addr) error {
	for _, matches := range [][]config.ResourceMatch{set.Manual, set.Russian} {
		for _, entry := range matches {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Kind != "service" {
				continue
			}
			targets, ok := r.known[entry.Value]
			if !ok {
				return ErrProbeTargetUnknown
			}
			if slices.ContainsFunc(targets.domains, func(domain string) bool { return name == domain || strings.HasSuffix(name, "."+domain) }) ||
				slices.ContainsFunc(pins, func(pin netip.Addr) bool {
					return slices.ContainsFunc(targets.pins, func(p netip.Prefix) bool { return p.Contains(pin) })
				}) {
				return ErrProbeTargetExcluded
			}
		}
	}
	return nil
}
