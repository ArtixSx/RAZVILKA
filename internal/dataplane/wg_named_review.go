package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
)

type wgNamedReviewKey struct{}

type wgNamedReviewScope struct {
	adapter *WARPWireGuardAdapter
	routes  []Route
	mu      sync.Mutex
	revoked error
}

func (a *WARPWireGuardAdapter) namedProfileReviewContext(ctx context.Context, routes []Route) (context.Context, error) {
	if err := checkWGNamedReviewContext(ctx); err != nil {
		return ctx, err
	}
	if err := a.verifyNamedProfileReview(ctx, routes); err != nil {
		return ctx, err
	}
	if a.ID() != "wireguard" {
		return ctx, nil
	}
	id, err := selectedWireGuardProfile(Plan{Routes: routes})
	if err != nil || id == "" || id == "main" {
		return ctx, err
	}
	return context.WithValue(ctx, wgNamedReviewKey{}, &wgNamedReviewScope{adapter: a, routes: cloneNetworkPolicyRoutes(routes)}), nil
}

func checkWGNamedReviewContext(ctx context.Context) error {
	scope, ok := ctx.Value(wgNamedReviewKey{}).(*wgNamedReviewScope)
	if !ok {
		return ctx.Err()
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.revoked == nil {
		scope.revoked = scope.adapter.verifyNamedProfileReview(ctx, scope.routes)
	}
	return errors.Join(ctx.Err(), scope.revoked)
}

// Removal and restoration are authorized by the retained immutable receipt,
// not by whichever catalog revision is present after a forward review failed.
// Keep every other context authority, including the common operation guard.
func wgNamedCleanupContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, wgNamedReviewKey{}, struct{}{})
}

type wgNamedForwardRunner struct{ base NFQWS2Runner }

func (r wgNamedForwardRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := checkWGNamedReviewContext(ctx); err != nil {
		return nil, err
	}
	if r.base == nil {
		return nil, errors.New("WireGuard command runner is unavailable")
	}
	output, err := r.base.Run(ctx, name, args...)
	reviewErr := checkWGNamedReviewContext(ctx)
	if err != nil {
		return output, errors.Join(err, reviewErr)
	}
	// Keep the successful command ACK: callers must install their exact
	// created-resource cleanup before the next forward check can refuse.
	// The scope latches a post-command revocation for that next check and
	// the phase's closing boundary, even if the catalog is later restored.
	return output, nil
}

// The plan binds the reviewed revision; the snapshot additionally binds the
// private bytes. Every forward lifecycle boundary reads the same registered
// provider again before command/file effects. Catalog changes never authorize
// binding whichever content currently has the selected name.
func (a *WARPWireGuardAdapter) verifyNamedProfileReview(ctx context.Context, routes []Route) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.ID() != "wireguard" {
		return nil
	}
	id, err := selectedWireGuardProfile(Plan{Routes: routes})
	if err != nil {
		return err
	}
	if id == "" || id == "main" {
		return nil
	}
	if a.Profiles == nil {
		return ErrWireGuardProfileRevision
	}
	revision := ""
	for _, route := range routes {
		if !strings.HasPrefix(route.Resolved, "wireguard:") {
			continue
		}
		current, err := FrozenWireGuardProfileRevision(route)
		if err != nil || revision != "" && revision != current {
			return ErrWireGuardProfileRevision
		}
		revision = current
	}
	profile, err := a.Profiles.Get(ctx, id)
	if err != nil {
		return err
	}
	if revision == "" || profile.Public().Revision != revision {
		return ErrWireGuardProfileRevision
	}
	return ctx.Err()
}
