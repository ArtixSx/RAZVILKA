package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

type startupHistoryContextKey struct{}

func TestStartupNodeHistoryBindingSharesTrustedAdmissionBeforeWorkers(t *testing.T) {
	a := &app.App{NodeFeeds: providerfeed.New(nil)}
	defer a.NodeFeeds.Close()
	denied := errors.New("modeled old controller cannot read incoming history")
	calls := 0
	guard := func(ctx context.Context, wanted int) error {
		calls++
		if ctx.Value(startupHistoryContextKey{}) != "original" {
			t.Fatal("startup binding replaced the owning operation context")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if wanted > 2 {
			return denied
		}
		return nil
	}
	if err := bindNodeHistoryWriteAdmission(a, guard); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("startup binding executed an admission probe")
	}
	ctx := context.WithValue(context.Background(), startupHistoryContextKey{}, "original")
	for _, consumer := range []func(context.Context, int) error{a.NodeHistoryWriteGuard, a.NodeFeeds.HistoryWriteAdmission} {
		if consumer == nil {
			t.Fatal("startup omitted a history consumer")
		}
		if err := consumer(ctx, 2); err != nil {
			t.Fatal("RAW history lost its minimum2 admission", err)
		}
		if err := consumer(ctx, 3); !errors.Is(err, denied) {
			t.Fatal("incoming XHTTP bypassed the same trusted admission", err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := consumer(canceled, 2); !errors.Is(err, context.Canceled) {
			t.Fatal("startup binding lost cancellation", err)
		}
	}
	if bindNodeHistoryWriteAdmission(nil, guard) == nil || bindNodeHistoryWriteAdmission(a, nil) == nil {
		t.Fatal("startup silently accepted a missing admission owner")
	}
}
