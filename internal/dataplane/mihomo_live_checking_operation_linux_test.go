//go:build linux

package dataplane

import (
	"context"
	"testing"
)

// Actual original Gate/control tokens; COMMON rows remain documentary models,
// not native child, service, route or cleanup acknowledgments.
func TestMihomoRetainedCheckNestedCleanupNeverReplacesForwardToken(t *testing.T) {
	archive, held, cleanup := mihomoTransitArchiveFileModel(t)
	r, s := archive.owner, archive.owner.scope
	s.pending = false
	r.transitHistory = nil
	c := &mihomoLiveHealthCheck{owner: r, cleanup: cleanup, open: true}
	c.self = c
	r.healthCheck = c
	forward, end, err := r.operation(held, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	check := func(ctx context.Context, forward bool) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.checkRetainedMihomoOperation(ctx, forward)
	}
	nested, closeNested, err := r.healthCleanupOperation(forward)
	if err != nil {
		t.Fatal(err)
	}
	if check(forward, true) != nil || check(nested, false) != nil {
		t.Fatal("original roles refused")
	}
	if check(forward, false) == nil || check(nested, true) == nil {
		t.Fatal("role elevation")
	}
	closeNested()
	if check(nested, false) == nil || check(forward, true) != nil {
		t.Fatal("nested revoke changed original borrower")
	}
	parentToken := forward.Value(mihomoLiveOperationKey{}).(*mihomoLiveOperation)
	copyToken := mihomoLiveOperation{self: parentToken.self, owner: parentToken.owner, cleanup: parentToken.cleanup, forward: parentToken.forward}
	copyToken.open.Store(true)
	if check(context.WithValue(forward, mihomoLiveOperationKey{}, &copyToken), true) == nil {
		t.Fatal("copied token accepted")
	}
	end()
	if check(forward, true) == nil {
		t.Fatal("released parent token accepted")
	}
}
