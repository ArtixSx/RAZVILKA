package defaultconsent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// Approve saves explicit authenticated review intent via the SAME Store CAS.
// App validates authenticated/CSRF request + known private-profile owner before
// calling. Every exact node/source/protocol is corroborated again here. The
// API does not set SafeMode, apply routes, run transport or authorize effects.
func (o *Owner) Approve(ctx context.Context, expected config.Config, policy *config.NetworkPolicy, grants []config.DefaultRouteGrant) (config.DefaultRouteConsent, error) {
	var saved config.DefaultRouteConsent
	err := o.withOwner(ctx, func() error {
		if !reflect.DeepEqual(o.store.Get(), expected) {
			return config.ErrRevisionChanged
		}
		if err := o.store.WithRevisionObservation(ctx, expected.Revision, func() error { return nil }); err != nil {
			return err
		}
		if err := o.control.Current(ctx); err != nil {
			return err
		}
		snapshot, err := o.nodes.Snapshot(ctx, time.Now().UTC())
		if err != nil {
			return ErrChanged
		}
		for _, g := range grants {
			if config.ValidateDefaultRouteGrant(g) != nil {
				return ErrChanged
			}
			engine, id, node := strings.Cut(g.Resolved, ":")
			if !node || engine != "xray" && engine != "sing-box" {
				continue
			}
			found := false
			for _, entry := range snapshot.Nodes {
				if entry.ID == id {
					found = allowedNode(entry, g, snapshot.Sources, time.Now().UTC())
					break
				}
			}
			if !found {
				return ErrChanged
			}
			if err := o.nodes.WithSecret(ctx, id, func(material []byte) error {
				if !allowedMaterial(material, g) {
					return ErrChanged
				}
				return nil
			}); err != nil {
				return ErrChanged
			}
			for i, id := range g.SourceIDs {
				known := false
				for _, source := range snapshot.Sources {
					if source.ID == id && source.Kind == g.SourceKinds[i] {
						known = true
						break
					}
				}
				if !known {
					return ErrChanged
				}
			}
		}
		epoch := o.control.Reference()
		saved, err = o.store.ApproveDefaultRouteConsent(ctx, expected, policy, grants, epoch.InstallationID, epoch.Sequence)
		if err != nil {
			return err
		}
		// Exact new config-file postimage + source generation + durable epoch
		// close this observation. A concurrent Stop leaves saved intent revoked.
		actual := o.store.Get()
		if !config.CurrentDefaultRouteConsent(actual) || actual.DefaultRouteConsent.Digest != saved.Digest {
			return ErrChanged
		}
		if err := o.store.WithRevisionObservation(ctx, actual.Revision, func() error { return nil }); err != nil {
			return err
		}
		closing, err := o.nodes.Snapshot(ctx, time.Now().UTC())
		if err != nil || closing.Generation != snapshot.Generation {
			return ErrChanged
		}
		return o.control.Current(ctx)
	})
	if err != nil {
		return config.DefaultRouteConsent{}, errors.Join(ErrChanged, err)
	}
	return saved, nil
}
