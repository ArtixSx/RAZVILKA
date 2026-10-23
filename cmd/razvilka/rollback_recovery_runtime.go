package main

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Source acquisition and the complete recovery use the original finite context.
// This scope closes the held tools before main can call log.Fatal or return a
// successful report; log.Fatal itself does not run deferred cleanup.
func withOfflineRollbackRuntime(ctx context.Context, manager *dataplane.Manager, dnsPath string, recover func() (dataplane.Execution, error), bind func(context.Context, func() (*dataplane.Manager, error), string) (*dataplane.Manager, func() error, error)) (result dataplane.Execution, resultErr error) {
	if manager == nil || recover == nil || bind == nil {
		return result, dataplane.ErrRuntimeInactivity
	}
	bound, closeSources, err := bind(ctx, func() (*dataplane.Manager, error) { return manager, nil }, dnsPath)
	if closeSources != nil {
		defer func() { resultErr = errors.Join(resultErr, closeSources()) }()
	}
	if err != nil || bound != manager || closeSources == nil {
		return result, errors.Join(dataplane.ErrRuntimeInactivity, err)
	}
	return recover()
}
