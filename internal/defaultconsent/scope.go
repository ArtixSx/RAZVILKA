package defaultconsent

import (
	"context"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// ScopeReview is the original owner's private review of approved client scope
// and the entire current config/control image. It has no provider, engine or
// strategy permission. Reference is comparison data only; it cannot recreate
// this handle or authorize a local executable, route, probe or client traffic.
type ScopeReview struct {
	self   *ScopeReview
	review *Review
	mu     sync.RWMutex
	closed bool
}

func (*ScopeReview) String() string   { return "[private selected-list scope review]" }
func (*ScopeReview) GoString() string { return "[private selected-list scope review]" }

func (o *Owner) ReviewScope(ctx context.Context) (*ScopeReview, error) {
	r, err := o.review(ctx, "", true)
	if err != nil {
		return nil, err
	}
	s := &ScopeReview{review: r}
	s.self = s
	return s, nil
}

func (s *ScopeReview) withReview(use func(*Review) error) error {
	if s == nil || s.self != s || use == nil {
		return ErrChanged
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.review == nil || !s.review.scopeOnly {
		return ErrChanged
	}
	return use(s.review)
}

func (s *ScopeReview) Reference() Reference {
	var ref Reference
	_ = s.withReview(func(r *Review) error { ref = r.Reference(); return nil })
	return ref
}

func (s *ScopeReview) MatchesConfigStore(store *config.Store) bool {
	matches := false
	_ = s.withReview(func(r *Review) error {
		matches = store != nil && r.owner != nil && r.owner.store == store && r.owner.storeSlot != nil && *r.owner.storeSlot == store
		return nil
	})
	return matches
}

func (s *ScopeReview) Current(ctx context.Context) error {
	return s.withReview(func(r *Review) error { return r.Current(ctx) })
}

// WithCurrent bookends a bounded trusted use under original operation admission.
// use MUST NOT reenter or close this handle or span an entire NFQ start/transfer
// protocol whose callbacks recheck it. This reader calls Store; do not invoke
// any of its methods from within a Store observation callback.
func (s *ScopeReview) WithCurrent(ctx context.Context, use func() error) error {
	return s.withReview(func(r *Review) error { return r.WithCurrent(ctx, use) })
}

// AcceptCommitted consumes only the existing owner's exact sanctioned policy
// CAS postimage. It never adopts an ordinary edit, changes approval or renews
// source/probe expiry. Call outside Store observation under original admission.
func (s *ScopeReview) AcceptCommitted(ctx context.Context, after config.Config, started, finished time.Time) error {
	return s.withReview(func(r *Review) error { return r.AcceptCommitted(ctx, after, started, finished) })
}

func (s *ScopeReview) Close() error {
	if s == nil {
		return nil
	}
	if s.self != s {
		return ErrChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
