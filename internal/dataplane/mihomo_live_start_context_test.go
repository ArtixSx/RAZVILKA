package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMihomoLiveStartContextPreservesOriginalBoundary(t *testing.T) {
	for _, parent := range []context.Context{nil, context.Background()} {
		if child, cancel, err := mihomoLiveStartContext(parent); err == nil || child != nil || cancel != nil {
			t.Fatal("unbounded caller acquired startup admission")
		}
	}
	for _, budget := range []time.Duration{110 * time.Second, 8 * time.Minute} {
		parent, stop := context.WithTimeout(context.WithValue(context.Background(), struct{}{}, "original"), budget)
		before := time.Now()
		child, cancel, err := mihomoLiveStartContext(parent)
		after := time.Now()
		if err != nil {
			stop()
			t.Fatal(err)
		}
		deadline, finite := child.Deadline()
		original, _ := parent.Deadline()
		if !finite || child.Value(struct{}{}) != "original" || deadline.After(original) {
			t.Fatal("lost original deadline or values")
		}
		if budget < 2*time.Minute && !deadline.Equal(original) {
			t.Fatal("extended or shortened existing operation deadline")
		}
		if budget > 2*time.Minute && (deadline.Before(before.Add(2*time.Minute)) || deadline.After(after.Add(2*time.Minute))) {
			t.Fatal("startup cap was not two minutes")
		}
		cancel()
		if child.Err() != context.Canceled || parent.Err() != nil {
			t.Fatal("startup cancellation changed original transaction")
		}
		stop()
	}
	parent, stop := context.WithTimeout(context.Background(), time.Minute)
	child, cancel, err := mihomoLiveStartContext(parent)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	defer cancel()
	stop()
	if child.Err() != context.Canceled {
		t.Fatal("startup lost original cancellation")
	}
	if _, _, err := mihomoLiveStartContext(parent); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller granted startup")
	}
	expired, stopExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stopExpired()
	if _, _, err := mihomoLiveStartContext(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired caller granted startup")
	}
}
