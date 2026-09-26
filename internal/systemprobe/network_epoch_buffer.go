package systemprobe

import (
	"context"
	"maps"
	"sync"
	"time"
)

// Drain kernel notifications between foreground observations. A long probe must
// not leave the socket unread for minutes. Only a change bit, watched interface
// IDs and the first error are retained, never an unbounded event queue. Fresh
// observations still take a complete snapshot and detect observed A-B-A changes.
type bufferedEpochSource struct {
	source     epochSource
	gate       chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	closeOnce  sync.Once
	interfaces map[uint32]bool
	changed    bool
	reason     string
	err        error
}

func newBufferedPlatformEpochSource(ctx context.Context) (epochSource, error) {
	source, err := newPlatformEpochSource(ctx)
	if err != nil {
		return nil, err
	}
	return newBufferedEpochSource(source, 250*time.Millisecond), nil
}

func newBufferedEpochSource(source epochSource, interval time.Duration) *bufferedEpochSource {
	ctx, cancel := context.WithCancel(context.Background())
	s := &bufferedEpochSource{source: source, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go s.observe(interval)
	return s
}

func (s *bufferedEpochSource) enter(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			s.leave()
			return err
		}
		if s.ctx.Err() != nil {
			s.leave()
			return ErrNetworkUnavailable
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return ErrNetworkUnavailable
	}
}

func (s *bufferedEpochSource) leave() { <-s.gate }

func (s *bufferedEpochSource) observe(interval time.Duration) {
	defer close(s.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		// Do not block a foreground snapshot. It drains before and after itself.
		select {
		case s.gate <- struct{}{}:
		default:
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, time.Second)
		s.drainLocked(ctx)
		cancel()
		failed := s.err != nil
		s.leave()
		if failed {
			return // An overflow or lost watch remains fatal until a new source.
		}
	}
}

func (s *bufferedEpochSource) drainLocked(ctx context.Context) {
	if s.err != nil {
		return
	}
	changed, err := s.source.Drain(ctx, s.interfaces)
	if err != nil {
		s.err = err
		return
	}
	if changed {
		s.changed = true
		s.reason = "observed-event"
		if source, ok := s.source.(interface{ ChangeReason() string }); ok {
			s.reason = source.ChangeReason()
		}
	}
}

func (s *bufferedEpochSource) Snapshot(ctx context.Context) (epochSnapshot, error) {
	if err := s.enter(ctx); err != nil {
		return epochSnapshot{}, err
	}
	defer s.leave()
	if s.err != nil {
		return epochSnapshot{}, s.err
	}
	snapshot, err := s.source.Snapshot(ctx)
	if err != nil {
		s.err = err
		return epochSnapshot{}, err
	}
	// Watch both sides of an uplink transition until the foreground detector
	// supplies its next scope. This copy never aliases a published snapshot.
	if s.interfaces == nil {
		s.interfaces = make(map[uint32]bool, len(snapshot.interfaces))
	}
	maps.Copy(s.interfaces, snapshot.interfaces)
	return snapshot, nil
}

func (s *bufferedEpochSource) Drain(ctx context.Context, interfaces map[uint32]bool) (bool, error) {
	if err := s.enter(ctx); err != nil {
		return false, err
	}
	defer s.leave()
	s.interfaces = maps.Clone(interfaces)
	s.drainLocked(ctx)
	if s.err != nil {
		return false, s.err
	}
	changed := s.changed
	s.changed = false
	return changed, nil
}

func (s *bufferedEpochSource) ChangeReason() string {
	s.gate <- struct{}{}
	defer s.leave()
	return s.reason
}

func (s *bufferedEpochSource) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.done
		s.gate <- struct{}{}
		defer s.leave()
		s.source.Close()
	})
}
