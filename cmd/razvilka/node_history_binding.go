package main

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/app"
)

// Trusted startup only, before any feed scheduler/job worker starts. Manual
// import/check/restore and every feed candidate page share the same OPS guard.
func bindNodeHistoryWriteAdmission(a *app.App, guard func(context.Context, int) error) error {
	if a == nil || guard == nil {
		return errNodeHistoryState
	}
	a.NodeHistoryWriteGuard = guard
	if a.NodeFeeds != nil {
		a.NodeFeeds.HistoryWriteAdmission = guard
	}
	return nil
}
