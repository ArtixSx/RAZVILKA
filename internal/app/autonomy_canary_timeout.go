package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Only a live Manager-certified, joined isolated Xray timeout can resume the
// pending traversal. This path grants no Apply, node failure or cooldown.
func (a *App) autonomyCandidateCanaryTimeout(ctx context.Context, p autonomy.Policy, s autonomy.Service, base config.Config, profile, id string, err error) bool {
	// Require the actual complete application error, not a matching typed
	// child concealed alongside another failure (for example scope release).
	failed, ok := err.(*autonomyApplyFailure)
	if !ok || failed == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	// Manager uses errors.Join for journal publication; its own certificate
	// validates all leaves before issuing permission. The accessor below also
	// rejects an additional cause introduced after that boundary.
	timeout := dataplane.ExactCandidateCanaryTimeout(failed.Cause)
	if timeout == nil || failed.Plan.NetworkProfileID != profile || a.Store == nil ||
		!reflect.DeepEqual(a.Store.Get(), base) || !a.autonomyConsent(p, s) || a.autonomyDiskCurrent(ctx) != nil {
		return false
	}
	service, known := a.autonomyService(s.ID)
	if !known || autonomyDefinition(service) != s.Definition || a.autonomyResourceGuard(ctx, p, s, base, service) != nil {
		return false
	}
	observed, networkErr := a.freshNetworkProfile(ctx)
	if networkErr != nil || observed != profile {
		return false
	}
	for _, route := range failed.Plan.Routes {
		if route.ServiceID == s.ID && route.Resolved == "xray:"+id &&
			sameNodeRecoveryStrings(route.Sources, s.Sources) && nodeRecoveryServiceMatches(route, service) &&
			timeout.Matches(ctx, a.Dataplane, failed.Plan, failed.Execution, route, time.Now()) {
			return true
		}
	}
	return false
}

// Publish the scheduling change only around fresh owner checks. A failed
// publication or closing guard restores the safety latch in the SAME runtime
// returned to the worker, so a later status save cannot overwrite the latch.
func (a *App) resumeAutonomyAfterCanary(ctx context.Context, serviceID string, r *autonomy.Runtime, guard func(context.Context) error) (bool, error) {
	if r == nil || r.Search == nil || !r.Search.Halted || guard == nil {
		return false, dataplane.ErrReviewChanged
	}
	if err := guard(ctx); err != nil {
		return false, err
	}
	r.Search.Halted = false
	err := a.persistAutonomySearch(ctx, serviceID, *r)
	if err == nil {
		err = guard(ctx)
	}
	if err == nil {
		return true, nil
	}
	r.Search.Halted = true
	// Restoring a refusal needs no forward authority and must survive parent
	// cancellation. It never starts a checker or issues runtime effects.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if restoreErr := a.persistAutonomySearch(cleanup, serviceID, *r); restoreErr != nil {
		a.Operations.FenceJournal()
		return false, errors.Join(err, restoreErr)
	}
	return false, err
}
