package main

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The existing offline CLI dispatch keeps the original runtime sources alive
// until Stop and fresh inactivity settlement have both finished.
func deactivateDataplaneWithHookRecovery(ctx context.Context, m *dataplane.Manager, settings string, removal bool) (dataplane.Deactivation, error) {
	return runReviewedDataplaneDeactivation(
		func() (func() error, func(), error) { return app.ReviewNFQWS2HookStop(ctx, m, settings) },
		func() (dataplane.Deactivation, error) {
			if removal {
				return m.DeactivateForRemoval(ctx)
			}
			return m.Deactivate(ctx)
		},
	)
}
func runReviewedDataplaneDeactivation(review func() (func() error, func(), error), stop func() (dataplane.Deactivation, error)) (dataplane.Deactivation, error) {
	settle, closeReview, err := review()
	if err != nil {
		return dataplane.Deactivation{}, err
	}
	defer closeReview()
	result, err := stop()
	if err == nil {
		err = settle()
	}
	return result, err
}
