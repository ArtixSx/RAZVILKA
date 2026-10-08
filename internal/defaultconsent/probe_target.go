package defaultconsent

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/ArtixSx/razvilka/internal/config"
)

var ErrProbeTargetExcluded = errors.New("probe target is excluded")
var ErrProbeTargetUnknown = errors.New("probe target exclusion decision is unknown")

// CheckProbeTarget checks explicit domain/address negatives against this actual
// retained owner before a producer's network leaf. It performs no resolution or
// network effect and grants no positive service/client/path permission. Original
// App review must separately classify primary/auxiliary service IDs from its
// real retained catalog and check those negatives; a hostname is not a service ID.
// Every resolved pin is checked, even one the producer does not intend to select.
func (r *Review) CheckProbeTarget(ctx context.Context, hostname string, pins []netip.Addr) error {
	name, err := config.PolicyDomain(hostname)
	if err != nil || len(pins) > 64 {
		return ErrProbeTargetUnknown
	}
	pins = slices.Clone(pins)
	return r.WithCurrent(ctx, func() error {
		return r.owner.store.WithResourceExclusionObservation(ctx, r.expectedConfig(), func(set config.EffectiveExclusionSet) error {
			check := func(target config.ResourceTarget) error {
				excluded, err := set.Matches(target)
				if err != nil {
					return errors.Join(ErrProbeTargetUnknown, err)
				}
				if excluded {
					return ErrProbeTargetExcluded
				}
				return nil
			}
			if err := check(config.ResourceTarget{Domain: name}); err != nil {
				return err
			}
			for _, pin := range pins {
				if !pin.IsValid() {
					return ErrProbeTargetUnknown
				}
				if err := check(config.ResourceTarget{Domain: name, Address: pin}); err != nil {
					return err
				}
			}
			return nil
		})
	})
}
