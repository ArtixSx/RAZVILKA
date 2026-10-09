package app

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// acceptCommitted is the source portion of the original Xray assembly's
// Manager commit callback. Call only after SAME Store's successful unchanged-
// intent policy CAS, outside Store/scope callbacks, using the actual CAS times.
// It reads the postimage from that Store rather than accepting a caller DTO.
// This transition supplies neither runtime health nor command admission.
func (r *XrayListRuntimeSource) acceptCommitted(ctx context.Context, started, finished time.Time) error {
	if r == nil || r.self != r || xrayListSourceContext(ctx) != nil || r.closed.Load() {
		return ErrXrayListSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.invalid || r.control == nil || r.registration == nil || r.cidrs == nil || r.node == nil {
		return ErrXrayListSource
	}
	deadline, _ := r.ctx.Deadline()
	c, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	err := r.app.Operations.WithExclusiveContext(r.ctx, func() error {
		return r.app.Operations.WithExclusiveContext(c, func() error {
			if err := r.commitOwnersCurrent(); err != nil {
				return err
			}
			after := r.store.Get()
			if !defaultRouteCommittedConfig(r.expected, after, r.expected.NetworkPolicy, r.expected.Services, started, finished) {
				return ErrXrayListSource
			}
			if err := r.control.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			wan, err := r.app.freshNetworkProfile(c)
			if err != nil || wan != r.wan || r.scope.facts.Identity != r.identity {
				return errors.Join(ErrXrayListSource, err)
			}
			material, err := r.currentNodeMaterial(c)
			if err != nil || material != r.materialHash {
				return errors.Join(ErrXrayListSource, err)
			}
			if err := r.cidrs.Current(c); err != nil {
				return err
			}
			if err := r.registration.Current(c); err != nil {
				return err
			}
			if err := r.commitOwnersCurrent(); err != nil {
				return err
			}
			if !reflect.DeepEqual(r.store.Get(), after) {
				return ErrXrayListSource
			}
			if err := r.control.Current(c); err != nil {
				return err
			}
			// The retained ScopeReview accepts this exact CAS and verifies the
			// original physical incarnation before our config reference advances.
			if err := r.scope.AcceptCommitted(c, after, started, finished); err != nil {
				return err
			}
			r.expected = after // defensive original Store clone, never a DTO
			return r.currentLocked(c)
		})
	})
	if err != nil {
		r.invalid = true
		return errors.Join(ErrXrayListSource, err)
	}
	return nil
}

// The only omitted currentApp predicate is its old config preimage. All other
// original owner identities remain mandatory during the sanctioned transition.
func (r *XrayListRuntimeSource) commitOwnersCurrent() error {
	if r.closed.Load() || r.app == nil || r.app.Store != r.store || r.app.Dataplane != r.manager || r.app.Nodes != r.nodes || r.app.Sources != r.sources ||
		r.app.CustomServices != r.custom || r.app.DNS != r.dns || r.app.SelfUpdateFiles != r.files || r.files.ControlRoot != r.root ||
		r.scope.self != r.scope || r.scope.app != r.app || r.scope.store != r.store ||
		applyReviewHash(r.app.catalogSnapshot()) != r.catalog || !wgListBaselineDNS(r.dns, r.service) {
		return ErrXrayListSource
	}
	return nil
}
