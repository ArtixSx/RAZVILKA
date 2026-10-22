package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
)

type recoveryReviewSourceKey struct{}
type committedRecoveryReviewKey struct{}

// WithRecoveryReview supplies a trusted startup caller's current applied-intent
// observation. It grants nothing until Recover binds it to the full plan read
// from its own committed journal. Never supply a callback from an HTTP DTO.
func WithRecoveryReview(ctx context.Context, review func(Plan) error) context.Context {
	return context.WithValue(ctx, recoveryReviewSourceKey{}, review)
}

type committedRecoveryReview struct {
	manager  *Manager
	image    []byte
	review   func(Plan) error
	previous func(context.Context) error
}

func recoveryPlanImage(plan Plan) ([]byte, error) { return json.Marshal(plan) }

func (r *committedRecoveryReview) check(ctx context.Context, expected Plan) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	image, err := recoveryPlanImage(expected)
	if err != nil || !bytes.Equal(image, r.image) {
		return ErrReviewChanged
	}
	if err := r.manager.checkExecutionRecovery(); err != nil {
		return err
	}
	current, exists, err := r.manager.Committed()
	if err != nil || !exists || current.State != "committed" || !current.Ready || current.SafeMode || current.Noop {
		return ErrReviewChanged
	}
	image, err = recoveryPlanImage(current)
	if err != nil || !bytes.Equal(image, r.image) {
		return ErrReviewChanged
	}
	// Each callback receives a detached copy. Mutating a by-value Plan must
	// not rewrite the original route slices and become a new admission grant.
	var detached Plan
	if json.Unmarshal(r.image, &detached) != nil {
		return ErrReviewChanged
	}
	if r.previous != nil {
		if err := r.previous(ctx); err != nil {
			return err
		}
	}
	if err := r.review(detached); err != nil {
		return err
	}
	return ctx.Err()
}

// CheckCommittedRecoveryReview is the pre-effect check for a new controlled
// boot start. An ordinary transaction guard, advisory availability, or copied
// subset of the committed plan cannot substitute for this startup binding.
func CheckCommittedRecoveryReview(ctx context.Context, fullPlan Plan) error {
	if ctx == nil {
		return ErrReviewChanged
	}
	r, ok := ctx.Value(committedRecoveryReviewKey{}).(*committedRecoveryReview)
	if !ok || r == nil || r.manager == nil || r.review == nil {
		return ErrReviewChanged
	}
	return r.check(ctx, fullPlan)
}

func (m *Manager) reviewedRecoveryContext(ctx context.Context, fullPlan Plan) (context.Context, error) {
	// Managed list/client recovery retains its existing executor authority.
	// The new caller source is deliberately a legacy NFQ boot-start review,
	// never a substitute grant for a LAN owner or a reason to disable it.
	if fullPlan.LAN != nil {
		return ctx, nil
	}
	source, _ := ctx.Value(recoveryReviewSourceKey{}).(func(Plan) error)
	if source == nil {
		return ctx, nil
	} // Legacy reconciliation cannot issue a boot-start grant.
	image, err := recoveryPlanImage(fullPlan)
	if err != nil {
		return ctx, ErrReviewChanged
	}
	previous, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	r := &committedRecoveryReview{manager: m, image: image, review: source, previous: previous}
	if err := r.check(ctx, fullPlan); err != nil {
		return ctx, err
	}
	bound := context.WithValue(ctx, committedRecoveryReviewKey{}, r)
	return WithReviewGuard(bound, func(c context.Context) error {
		var expected Plan
		if json.Unmarshal(image, &expected) != nil {
			return ErrReviewChanged
		}
		return r.check(c, expected)
	}), nil
}
