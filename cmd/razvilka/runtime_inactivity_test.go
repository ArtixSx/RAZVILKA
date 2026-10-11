package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestSelfUpdateRuntimeSourceRequiresOriginalFiniteContextBeforeOpeningManager(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled} {
		manager, closeSource, err := selfUpdateRuntimeManagerBound(ctx)
		if manager != nil || closeSource != nil || !errors.Is(err, dataplane.ErrRuntimeInactivity) {
			t.Fatal("unbounded helper acquired a runtime source", err)
		}
	}
}
