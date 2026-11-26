package dataplane

import (
	"context"
	"errors"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This comparison freezes one original cleanup/source association, not an
// absence result. The tool producer retains and revokes its own read scope.
type mihomoSameBootAbsenceRead struct {
	owner  *mihomoSameBootCleanup
	frozen mihomoSameBootCleanup
	read   mihomoColdReadRunner
}

func (o *mihomoSameBootCleanup) freezeAbsenceRead() *mihomoSameBootAbsenceRead {
	if o == nil || o.self != o || o.read == nil || o.inputs == nil {
		return nil
	}
	r := &mihomoSameBootAbsenceRead{owner: o, frozen: *o, read: *o.read}
	r.frozen.planRecords = slices.Clone(o.planRecords)
	r.frozen.planMissing = slices.Clone(o.planMissing)
	r.read.engineSpec.Args = slices.Clone(o.read.engineSpec.Args)
	r.read.sidecarSpec.Args = slices.Clone(o.read.sidecarSpec.Args)
	return r
}

func (r *mihomoSameBootAbsenceRead) current(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.owner == nil {
		return ErrMihomoLiveRetirement
	}
	o, f := r.owner, &r.frozen
	if o.self != o || o.read != f.read || o.inputs != f.inputs ||
		o.control != f.control || o.cleanup != f.cleanup || o.controlRoot != f.controlRoot ||
		o.policy != f.policy || o.static != f.static || o.sidecar != f.sidecar ||
		o.effectsClosed != f.effectsClosed || o.effectUnknown ||
		!slices.Equal(o.planRecords, f.planRecords) || !slices.Equal(o.planMissing, f.planMissing) ||
		o.read == nil || !o.sourceCoordinatesCurrent() {
		return ErrMihomoLiveRetirement
	}
	a, b := o.read, &r.read
	if a.original != b.original || !sameNetworkPolicyDependency(a.source, b.source) ||
		a.proxy != b.proxy || a.parent != b.parent || a.sidecarKind != b.sidecarKind || a.sidecarBin != b.sidecarBin ||
		a.ip6 != b.ip6 || a.tools.Provider != b.tools.Provider || !sameNetworkPolicyDependency(a.tools.Runner, b.tools.Runner) ||
		a.tools.IP != b.tools.IP || a.tools.IPTables != b.tools.IPTables || a.tools.ReviewSHA256 != b.tools.ReviewSHA256 || a.tools.Identity != b.tools.Identity ||
		!sameMihomoLiveSpec(a.engineSpec, b.engineSpec) || !sameMihomoLiveSpec(a.sidecarSpec, b.sidecarSpec) ||
		a.tools.Identity != o.inputs.definition.NetworkIdentity {
		return ErrMihomoLiveRetirement
	}
	return nil
}

// The only borrowed operation is the hardcoded pure absence observer. No
// callback, publication, effect or Close is exposed to this derived context.
// Both original Current calls and every actual kernel/process read remain.
func (o *mihomoSameBootCleanup) observeOriginalAbsence(ctx context.Context) (netidentity.Identity, error) {
	r := o.freezeAbsenceRead()
	if r == nil {
		return netidentity.Identity{}, ErrMihomoLiveRetirement
	}
	original, supported := r.read.source.(domainTCPToolObserver)
	if !supported {
		return o.absentUnscoped(ctx)
	}
	if err := r.current(ctx); err != nil {
		return netidentity.Identity{}, err
	}
	defer mihomoSameBootNativeOwnerTiming(o, "absence-tool-read")()
	var identity netidentity.Identity
	var callbackErr error
	uses := 0
	err := original.WithReadOnlyToolObservation(ctx, r.read.tools.Identity, r.read.tools.ReviewSHA256, func(observed context.Context) error {
		uses++
		if uses != 1 {
			callbackErr = errors.Join(callbackErr, ErrMihomoLiveRetirement)
			return callbackErr
		}
		if err := r.current(observed); err != nil {
			callbackErr = err
			return callbackErr
		}
		var err error
		identity, err = o.absentUnscoped(observed)
		callbackErr = errors.Join(err, r.current(observed))
		return callbackErr
	})
	err = errors.Join(err, callbackErr, r.current(ctx), ctx.Err())
	if uses != 1 || identity != r.read.tools.Identity || identity.Validate() != nil {
		err = errors.Join(err, ErrMihomoLiveRetirement)
	}
	if err != nil {
		return netidentity.Identity{}, err
	}
	return identity, nil
}
