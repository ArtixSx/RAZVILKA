package startuptools

import (
	"context"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type toolReadObservationKey struct{}
type toolReadObservation struct {
	self     *toolReadObservation
	lease    *Lease
	review   *heldReview
	identity netidentity.Identity
	digest   string
	ctx      context.Context
	deadline time.Time
	mu       sync.Mutex
	active   bool
	users    sync.WaitGroup
}

func readObservationMarker(ctx context.Context) (*toolReadObservation, bool) {
	if ctx == nil {
		return nil, false
	}
	value := ctx.Value(toolReadObservationKey{})
	if value == nil {
		return nil, false
	}
	o, _ := value.(*toolReadObservation)
	return o, true
}
func (o *toolReadObservation) currentLocked(ctx context.Context, l *Lease) error {
	if o == nil || o.self != o || !o.active || o.lease != l || l == nil || l.review != o.review || l.digest != o.digest || l.identity != o.identity || l.closed.Load() || l.lifetime == nil || l.lifetime.Err() != nil || ctx == nil || ctx.Err() != nil || o.ctx == nil || o.ctx.Err() != nil || ctx.Value(toolReadObservationKey{}) != o {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline.After(o.deadline) || !time.Now().Before(deadline) {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	return nil
}
func (l *Lease) readObservationCurrent(ctx context.Context) error {
	o, present := readObservationMarker(ctx)
	if !present {
		return nil
	}
	if o == nil {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.currentLocked(ctx, l)
}
func (l *Lease) registerReadObservation(ctx context.Context) (func(), <-chan struct{}, error) {
	o, present := readObservationMarker(ctx)
	if !present {
		return nil, nil, nil
	}
	if o == nil {
		return nil, nil, at("READ_OBSERVATION_SCOPE", nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.currentLocked(ctx, l); err != nil {
		return nil, nil, err
	}
	o.users.Add(1)
	return o.users.Done, o.ctx.Done(), nil
}
func readObservationEffectRefusal(ctx context.Context) error {
	if _, present := readObservationMarker(ctx); present {
		return at("READ_OBSERVATION_EFFECT", nil)
	}
	return nil
}
