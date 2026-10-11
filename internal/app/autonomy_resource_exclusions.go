package app

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

var errAutonomyResourceIneligible = errors.New("automatic resource observation is not permitted")

// A short, closed leaf observation, never the protocol/network operation.
// The original round owner precedes Store admission; the callback uses only
// detached inputs and never calls Store, Gate, or a provider.
func (a *App) autonomyResourceGuard(ctx context.Context, p autonomy.Policy, s autonomy.Service, cfg config.Config, service catalog.Service) error {
	if ctx == nil || a.Store == nil || !a.autonomyConsent(p, s) {
		return dataplane.ErrReviewChanged
	}
	current, known := a.autonomyService(s.ID)
	if !known || autonomyDefinition(current) != s.Definition || autonomyDefinition(service) != s.Definition {
		return dataplane.ErrReviewChanged
	}
	store := a.Store
	leaf := func(ctx context.Context, devices []string) error {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return a.Operations.WithExclusiveContext(ctx, func() error {
			if a.Store != store {
				return dataplane.ErrReviewChanged
			}
			return store.WithResourceExclusionObservation(ctx, cfg, func(set config.EffectiveExclusionSet) error {
				return autonomyResourceEligibilityForDevices(ctx, cfg, s, service, set, devices)
			})
		})
	}
	// An original selected-device round remains bound to that owner even when
	// a fresh Store image changes mode. Dispatching from the new mode would
	// bypass the original intent and physical continuity checks.
	if carrier := ctx.Value(autonomyDeviceScopeKey{}); carrier != nil {
		d, ok := carrier.(*autonomyDeviceScope)
		if !ok || d == nil || d.app != a || d.store != store {
			return errAutonomyResourceIneligible
		}
		return d.use(ctx, cfg, s, leaf)
	}
	if cfg.NetworkPolicy != nil && cfg.NetworkPolicy.Clients.Mode == "selected_devices" {
		return errAutonomyResourceIneligible
	}
	return leaf(ctx, nil)
}

func autonomyResourceEligibility(ctx context.Context, cfg config.Config, s autonomy.Service, service catalog.Service, set config.EffectiveExclusionSet) error {
	return autonomyResourceEligibilityForDevices(ctx, cfg, s, service, set, nil)
}

func autonomyResourceEligibilityForDevices(ctx context.Context, cfg config.Config, s autonomy.Service, service catalog.Service, set config.EffectiveExclusionSet, devices []string) error {
	// Bound the work performed inside the Store observation. Larger definitions
	// require review rather than extending a closed leaf into unbounded work.
	if len(service.Domains)+len(service.Probes)+len(service.CIDRs) > 256 {
		return errAutonomyResourceIneligible
	}
	if !s.Enabled || s.Removing || service.ID != s.ID || !cfg.Services[s.ID].Enabled || cfg.SafeMode || cfg.ServiceControl.Stopped || cfg.ServiceControl.EffectiveMode() == "manual" {
		return errAutonomyResourceIneligible
	}
	if !s.AllLAN && len(s.Sources) == 0 {
		return errAutonomyResourceIneligible
	}
	sources, err := config.NormalizeSources(s.Sources)
	if err != nil {
		return errAutonomyResourceIneligible
	}
	// Only the original round's observed device cohort supplies these IDs.
	// The legacy path still refuses missing identities and device exclusions.
	if set.Clients.Mode == "selected_devices" {
		if len(devices) == 0 || len(devices) > 128 {
			return errAutonomyResourceIneligible
		}
		for _, id := range devices {
			if !slices.Contains(set.Clients.DeviceIDs, id) || slices.Contains(set.Clients.ExcludedDeviceIDs, id) {
				return errAutonomyResourceIneligible
			}
		}
	} else if len(devices) != 0 || len(set.Clients.ExcludedDeviceIDs) != 0 {
		return errAutonomyResourceIneligible
	}
	for _, excluded := range set.Clients.ExcludedCIDRs {
		negative, err := netip.ParsePrefix(excluded)
		if err != nil || s.AllLAN {
			return errAutonomyResourceIneligible
		}
		for _, source := range sources {
			positive, err := netip.ParsePrefix(source)
			if err != nil || positive.Overlaps(negative) {
				return errAutonomyResourceIneligible
			}
		}
	}
	check := func(target config.ResourceTarget) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		ids := devices
		if len(ids) == 0 {
			ids = []string{""}
		}
		for _, id := range ids {
			target.DeviceID = id
			excluded, err := set.Matches(target)
			if err != nil {
				return err
			}
			if excluded {
				return errAutonomyResourceIneligible
			}
		}
		return nil
	}
	if err := check(config.ResourceTarget{ServiceID: service.ID}); err != nil {
		return err
	}
	for _, domain := range service.Domains {
		if err := check(config.ResourceTarget{ServiceID: service.ID, Domain: domain}); err != nil {
			return err
		}
	}
	urls := []string{service.ProbeURL}
	for _, probe := range service.Probes {
		urls = append(urls, probe.URL)
	}
	// Auxiliary controls need no positive client entry, but their explicit
	// negatives are still stronger than permission to check the primary.
	urls = append(urls, "https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org/")
	for _, endpoint := range urls {
		if endpoint == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Hostname() == "" {
			return errAutonomyResourceIneligible
		}
		target := config.ResourceTarget{Domain: parsed.Hostname()}
		if address, err := netip.ParseAddr(parsed.Hostname()); err == nil {
			target.Domain, target.Address = "", address
		}
		if err := check(target); err != nil {
			return err
		}
	}
	// Parse address negatives once, before comparing all positive prefixes.
	var negativePrefixes []netip.Prefix
	appendPrefix := func(kind, value string) error {
		if kind == "ip" {
			address, err := netip.ParseAddr(value)
			if err != nil {
				return errAutonomyResourceIneligible
			}
			negativePrefixes = append(negativePrefixes, netip.PrefixFrom(address, address.BitLen()))
		} else if kind == "cidr" {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return errAutonomyResourceIneligible
			}
			negativePrefixes = append(negativePrefixes, prefix)
		}
		return nil
	}
	if len(service.CIDRs) != 0 {
		for _, negatives := range [][]config.ResourceMatch{set.Manual, set.Russian} {
			for _, negative := range negatives {
				if err := appendPrefix(negative.Kind, negative.Value); err != nil {
					return err
				}
			}
		}
		for _, negative := range set.LegacyRules {
			if len(devices) != 0 && len(negative.DeviceIDs) != 0 && !slices.ContainsFunc(devices, func(id string) bool { return slices.Contains(negative.DeviceIDs, id) }) {
				continue
			}
			if err := appendPrefix(negative.Kind, negative.Value); err != nil {
				return err
			}
		}
	}
	for _, cidr := range service.CIDRs {
		positive, err := netip.ParsePrefix(cidr)
		if err != nil || positive != positive.Masked() {
			return errAutonomyResourceIneligible
		}
		if err := check(config.ResourceTarget{ServiceID: service.ID, Address: positive.Addr()}); err != nil {
			return err
		}
		// A narrow excluded IP inside a wider positive CIDR cannot be waived
		// merely because the subnet's base address did not match it.
		for _, prefix := range negativePrefixes {
			if positive.Overlaps(prefix) {
				return errAutonomyResourceIneligible
			}
		}
	}
	return nil
}

// Freeze permission around an actual node check without holding Store RLock
// across protocol work. The node owner separately closes resolved-IP/redirect
// observations and history publication at its actual lower-level boundaries.
func (a *App) checkAutonomyCurrentNode(ctx context.Context, p autonomy.Policy, s autonomy.Service, cfg config.Config, engine, id string, service catalog.Service, profile string) (dataplane.NodeCheckResult, error) {
	store := a.Store
	if err := a.autonomyResourceGuard(ctx, p, s, cfg, service); err != nil {
		return dataplane.NodeCheckResult{}, err
	}
	checker, err := a.nodeCheckerForEngine(engine)
	if err != nil {
		return dataplane.NodeCheckResult{}, err
	}
	result, _, err := a.runAndRecordNode(ctx, engine, id, service, profile, 0, func(checkCtx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
		result, checkErr := checker.Check(checkCtx, request)
		closing := a.autonomyResourceGuard(checkCtx, p, s, cfg, service)
		if a.Store != store {
			closing = errors.Join(closing, dataplane.ErrReviewChanged)
		}
		if closing == nil {
			// The first-usable owner consumes only the exact unsupported
			// sentinel. Preserve it; joined local/refusal errors stay closed.
			return result, true, checkErr
		}
		return result, false, errors.Join(checkErr, closing)
	})
	return result, err
}

// Before own publication use the exact original config. After publication the
// service route may change, while the negative/client policy must remain exact.
func sameAutonomyResourcePolicy(current, before config.Config) bool {
	return reflect.DeepEqual(current.NetworkPolicy, before.NetworkPolicy) &&
		reflect.DeepEqual(current.InactiveResourceExclusions, before.InactiveResourceExclusions)
}
