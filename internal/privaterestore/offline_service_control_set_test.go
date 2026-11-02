package privaterestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Genuine private journal leases and idle records. No dataplane, process,
// configuration owner or native command permission is supplied by this model.
func offlineControlSetFixture(t *testing.T) (context.Context, Layout, []*Coordinator) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("original private lease ownership requires Linux")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	layout, owners := offlineControlSetFixtureContext(t, ctx)
	return ctx, layout, owners
}

func offlineControlSetFixtureContext(t *testing.T, ctx context.Context) (Layout, []*Coordinator) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("original private lease ownership requires Linux")
	}
	base := t.TempDir()
	layout := testLayout(base)
	var owners []*Coordinator
	for i, name := range offlineServiceControlGenerations {
		layout.JournalRoot = filepath.Join(base, name)
		if i >= 1 {
			layout.NodeRoot = filepath.Join(base, "nodes")
		}
		if i >= 2 {
			layout.WarpRoot = filepath.Join(base, "warp")
		}
		if i >= 3 {
			layout.FeedRoot = filepath.Join(base, "subscriptions-private")
		}
		if i >= 4 {
			layout.StrategyLabPath = filepath.Join(base, "strategy-lab.json")
		}
		seed, _, err := Open(ctx, layout)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed.Close(); err != nil {
			t.Fatal(err)
		}
		c, err := OpenForOfflineServiceControl(ctx, layout)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, c)
	}
	t.Cleanup(func() {
		for i := len(owners) - 1; i >= 0; i-- {
			if err := owners[i].Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return layout, owners
}

func TestOfflineServiceControlSetRetainsExactlyFiveOriginalIdleLifetimes(t *testing.T) {
	ctx, layout, owners := offlineControlSetFixture(t)
	var saved *OfflineServiceControlSet
	err := WithOfflineServiceControlSet(ctx, layout.Config, owners, func(actual context.Context, s *OfflineServiceControlSet) error {
		saved = s
		if actual != ctx || s.Current(actual) != nil {
			t.Fatal("original set unavailable")
		}
		if path, err := s.ConfigurationPath(actual); err != nil || path != layout.Config {
			t.Fatal("config coordinate changed", err)
		}
		for _, c := range owners {
			if c.mu.TryLock() {
				c.mu.Unlock()
				t.Fatal("original coordinator not held")
			}
			other, err := OpenForOfflineServiceControl(ctx, c.layout)
			if other != nil || !errors.Is(err, restorejournal.ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("original lifetime not retained", err)
			}
		}
		copy := &OfflineServiceControlSet{self: s, ctx: ctx, config: layout.Config, coordinators: owners, active: true}
		if copy.Current(ctx) == nil {
			t.Fatal("copied set admitted")
		}
		if s.Current(context.WithValue(ctx, struct{ foreign bool }{true}, true)) == nil {
			t.Fatal("renewed context admitted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved == nil || saved.Current(ctx) == nil {
		t.Fatal("returned callback retained admission")
	}
	if _, err := saved.ConfigurationPath(ctx); err == nil {
		t.Fatal("expired set returned a live coordinate")
	}
	for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot, layout.NodeRoot, layout.WarpRoot, layout.FeedRoot, layout.StrategyLabPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("set opened or created a target", err)
		}
	}
}

func TestOfflineServiceControlSetRejectsMissingDuplicateReorderedAndForeignOwners(t *testing.T) {
	for _, change := range []string{"missing", "duplicate", "reordered", "foreign-layout", "wrong-config", "canceled"} {
		t.Run(change, func(t *testing.T) {
			ctx, layout, owners := offlineControlSetFixture(t)
			passed := append([]*Coordinator(nil), owners...)
			path := layout.Config
			switch change {
			case "missing":
				passed = passed[:4]
			case "duplicate":
				passed[4] = passed[3]
			case "reordered":
				passed[0], passed[1] = passed[1], passed[0]
			case "foreign-layout":
				owners[4].layout.ProviderRoot = filepath.Join(filepath.Dir(path), "foreign-provider") // Refusal-only private corruption.
			case "wrong-config":
				path += ".foreign"
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			called := false
			err := WithOfflineServiceControlSet(ctx, path, passed, func(context.Context, *OfflineServiceControlSet) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("incomplete/foreign set issued authority", change, err)
			}
		})
	}
}

func TestOfflineServiceControlSetRevokesOnOriginalCallbackErrorAndPanic(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, layout, owners := offlineControlSetFixture(t)
			original := errors.New("original callback failure")
			var saved *OfflineServiceControlSet
			var result error
			func() {
				defer func() {
					p := recover()
					if mode == "panic" && p != original {
						t.Fatal("original panic lost", p)
					}
					if mode != "panic" && p != nil {
						panic(p)
					}
				}()
				result = WithOfflineServiceControlSet(ctx, layout.Config, owners, func(_ context.Context, s *OfflineServiceControlSet) error {
					saved = s
					if mode == "panic" {
						panic(original)
					}
					return original
				})
			}()
			if mode == "error" && !errors.Is(result, original) {
				t.Fatal("original callback cause hidden", result)
			}
			if saved == nil || saved.Current(ctx) == nil {
				t.Fatal("failed callback retained a set")
			}
			for _, c := range owners {
				if !c.mu.TryLock() {
					t.Fatal("callback leaked coordinator lock")
				}
				c.mu.Unlock()
			}
		})
	}
}

type offlineControlBlockingContext struct {
	context.Context
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *offlineControlBlockingContext) Err() error {
	if c.block.CompareAndSwap(true, false) {
		c.once.Do(func() { close(c.entered) })
		select {
		case <-c.release:
		case <-c.Context.Done():
		}
	}
	return c.Context.Err()
}

func TestOfflineServiceControlSetRevocationJoinsOriginalInFlightCurrent(t *testing.T) {
	base, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	ctx := &offlineControlBlockingContext{Context: base, entered: make(chan struct{}), release: make(chan struct{})}
	layout, owners := offlineControlSetFixtureContext(t, ctx)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(ctx.release) }) }
	defer release()
	original := errors.New("original callback refused after launching observer")
	done := make(chan error, 1)
	readDone := make(chan error, 1)
	go func() {
		done <- WithOfflineServiceControlSet(ctx, layout.Config, owners, func(_ context.Context, s *OfflineServiceControlSet) error {
			ctx.block.Store(true)
			go func() { readDone <- s.Current(ctx) }()
			select {
			case <-ctx.entered:
				return original
			case <-base.Done():
				return base.Err()
			}
		})
	}()
	select {
	case <-ctx.entered:
	case <-base.Done():
		t.Fatal("actual reader did not enter", base.Err())
	}
	select {
	case err := <-done:
		t.Fatal("callback returned before original reader joined", err)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-base.Done():
		t.Fatal("original reader did not join", base.Err())
	}
	select {
	case err := <-done:
		if !errors.Is(err, original) {
			t.Fatal("callback exception hidden", err)
		}
	case <-base.Done():
		t.Fatal("revoke failed to complete", base.Err())
	}
}
