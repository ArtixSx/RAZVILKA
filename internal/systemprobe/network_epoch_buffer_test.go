package systemprobe

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type queuedEpochEvent struct {
	iface uint32
	err   error
}

type queuedEpochSource struct {
	events    chan queuedEpochEvent
	drained   chan struct{}
	closed    atomic.Int32
	snapshots atomic.Int32
	block     chan struct{}
}

func (s *queuedEpochSource) Snapshot(context.Context) (epochSnapshot, error) {
	s.snapshots.Add(1)
	return fakeEpochSnapshot(), nil
}

func (s *queuedEpochSource) Drain(ctx context.Context, interfaces map[uint32]bool) (bool, error) {
	if s.block != nil {
		select {
		case s.block <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return false, ctx.Err()
	}
	changed := false
	for {
		select {
		case event := <-s.events:
			changed = changed || interfaces[event.iface]
			s.drained <- struct{}{}
			if event.err != nil {
				return false, event.err
			}
		default:
			return changed, nil
		}
	}
}

func (*queuedEpochSource) ChangeReason() string { return "underlay-link-event" }
func (s *queuedEpochSource) Close()             { s.closed.Add(1) }

func queuedEpochFixture(t *testing.T) (*queuedEpochSource, *bufferedEpochSource) {
	t.Helper()
	raw := &queuedEpochSource{events: make(chan queuedEpochEvent, 32), drained: make(chan struct{}, 32)}
	s := newBufferedEpochSource(raw, time.Millisecond)
	t.Cleanup(s.Close)
	return raw, s
}

func waitEpochEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(3 * time.Second):
		t.Fatal("background notification reader did not finish")
	}
}

func TestBufferedEpochDrainsIdleNotificationsAndPreservesABA(t *testing.T) {
	raw, source := queuedEpochFixture(t)
	detector := newEpochDetector(func(context.Context) (epochSource, error) { return source, nil }, bytes.NewReader([]byte("12345678")), time.Now)
	first, err := detector.fresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reads := raw.snapshots.Load()
	// No foreground request takes place during these notifications, including
	// an A-B-A transition whose final full snapshot is identical to the first.
	for i := 0; i < 32; i++ {
		raw.events <- queuedEpochEvent{iface: 4}
	}
	for i := 0; i < 32; i++ {
		waitEpochEvent(t, raw.drained)
	}
	if raw.snapshots.Load() != reads {
		t.Fatal("idle drain ran expensive full network snapshots")
	}
	second, err := detector.fresh(context.Background())
	if err != nil || first.ID == second.ID || detector.diagnostic().Reason != "underlay-link-event" {
		t.Fatal("coalesced notifications lost their epoch or cause", err)
	}
	third, err := detector.fresh(context.Background())
	if err != nil || third.ID != second.ID {
		t.Fatal("consumed notifications changed the epoch twice")
	}
	// A candidate TUN event outside the observed underlay is still irrelevant.
	raw.events <- queuedEpochEvent{iface: 99}
	waitEpochEvent(t, raw.drained)
	fourth, err := detector.fresh(context.Background())
	if err != nil || fourth.ID != third.ID {
		t.Fatal("unrelated interface revoked network proof")
	}
}

func TestBufferedEpochRetainsFirstFailureUntilReplaced(t *testing.T) {
	raw, source := queuedEpochFixture(t)
	want := epochObservationFailure{"netlink-overflow", errors.New("lost notifications")}
	raw.events <- queuedEpochEvent{err: want}
	waitEpochEvent(t, raw.drained)
	for i := 0; i < 2; i++ {
		if changed, err := source.Drain(context.Background(), nil); changed || epochFailureDetail(err) != "netlink-overflow" {
			t.Fatal("a later empty drain cleared an observation failure", err)
		}
	}
	if _, err := source.Snapshot(context.Background()); epochFailureDetail(err) != "netlink-overflow" || raw.snapshots.Load() != 0 {
		t.Fatal("snapshot restored proof after lost notifications", err)
	}
	source.Close()
	source.Close()
	if raw.closed.Load() != 1 {
		t.Fatal("source cleanup was not joined exactly once")
	}
}

func TestBufferedEpochCloseCancelsAndJoinsActiveDrain(t *testing.T) {
	raw := &queuedEpochSource{block: make(chan struct{}, 1)}
	source := newBufferedEpochSource(raw, time.Millisecond)
	t.Cleanup(source.Close)
	waitEpochEvent(t, raw.block)
	done := make(chan struct{})
	go func() {
		source.Close()
		close(done)
	}()
	waitEpochEvent(t, done)
	if raw.closed.Load() != 1 {
		t.Fatal("close returned before underlying cleanup")
	}
	if _, err := source.Snapshot(context.Background()); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatal("closed observer was reusable", err)
	}
}

func TestBufferedEpochForegroundCancellationDoesNotConsumeEvents(t *testing.T) {
	raw, source := queuedEpochFixture(t)
	if _, err := source.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw.events <- queuedEpochEvent{iface: 4}
	waitEpochEvent(t, raw.drained)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Drain(ctx, map[uint32]bool{4: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	changed, err := source.Drain(context.Background(), map[uint32]bool{4: true})
	if err != nil || !changed {
		t.Fatal("canceled request discarded an observed network change", err)
	}
}
