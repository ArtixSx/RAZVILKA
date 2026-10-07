package defaultconsent

import (
	"context"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// AcceptCommitted consumes only the exact successful original policy CAS
// postimage. App calls under its private reviewed Plan/control operation after
// Store publication. Approved intent, source/material and original transport
// expiry are not renewed. Unrelated edits/revisions cannot advance this handle.
func (r *Review) AcceptCommitted(ctx context.Context, after config.Config, started, finished time.Time) error {
	if r == nil || r.self != r || r.owner == nil {
		return ErrChanged
	}
	return r.owner.withOwner(ctx, func() error {
		before := r.expectedConfig()
		at, err := time.Parse(time.RFC3339, after.LastAppliedAt)
		if err != nil || started.IsZero() || finished.Before(started) || at.Before(started.Truncate(time.Second)) || at.After(finished) {
			return ErrChanged
		}
		expected, err := config.ReviewedNetworkPolicyCommitImage(before, after.AppliedNetworkPolicy, before.Services, at)
		if err != nil || !reflect.DeepEqual(expected, after) || !reflect.DeepEqual(r.owner.store.Get(), expected) {
			return ErrChanged
		}
		if after.DefaultRouteConsent == nil || after.DefaultRouteConsent.Digest != r.ref.ConsentDigest || after.DefaultRouteConsent.ApprovalRevision != r.ref.ApprovalRevision {
			return ErrChanged
		}
		if err := r.owner.store.WithRevisionObservation(ctx, after.Revision, func() error { return nil }); err != nil {
			return err
		}
		if err := r.owner.control.Current(ctx); err != nil {
			return err
		}
		if r.ref.NodeID != "" {
			if err := r.currentNode(ctx); err != nil {
				return err
			}
			if err := r.owner.nodes.WithSecret(ctx, r.ref.NodeID, func(material []byte) error {
				if materialDigest(material) != r.ref.NodeMaterialSHA256 || !allowedMaterial(material, r.grant) {
					return ErrChanged
				}
				return nil
			}); err != nil {
				return err
			}
			if err := r.currentNode(ctx); err != nil {
				return err
			}
		}
		if !reflect.DeepEqual(r.owner.store.Get(), after) {
			return ErrChanged
		}
		if err := r.owner.store.WithRevisionObservation(ctx, after.Revision, func() error { return nil }); err != nil {
			return err
		}
		if err := r.owner.control.Current(ctx); err != nil {
			return err
		}
		r.cfgMu.Lock()
		defer r.cfgMu.Unlock()
		if !reflect.DeepEqual(r.cfg, before) {
			return ErrChanged
		}
		// The sanctioned image is privately cloned by the shared constructor;
		// retaining the caller's detached after DTO would permit later edits.
		r.cfg = expected
		return nil
	})
}
