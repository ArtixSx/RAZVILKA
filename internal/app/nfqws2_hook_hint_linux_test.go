//go:build linux

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"golang.org/x/sys/unix"
)

var nfqws2HookHintFast = nfqws2HookHintTiming{quiet: 200 * time.Millisecond, max: 800 * time.Millisecond, interval: 300 * time.Millisecond, retryFor: 3 * time.Second, rearmMin: 50 * time.Millisecond, rearmMax: 200 * time.Millisecond}

type nfqws2HookWakes struct {
	mu       sync.Mutex
	at       []time.Time
	refuse   int
	attempts int
}

func (w *nfqws2HookWakes) wake() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.attempts++
	if w.refuse > 0 {
		w.refuse--
		return false
	}
	w.at = append(w.at, time.Now())
	return true
}

func (w *nfqws2HookWakes) snapshot() ([]time.Time, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Time(nil), w.at...), w.attempts
}

func (w *nfqws2HookWakes) waitFor(t *testing.T, count int, limit time.Duration) []time.Time {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		at, _ := w.snapshot()
		if len(at) >= count || time.Now().After(deadline) {
			return at
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startNFQWS2HookHint(t *testing.T, path string, timing nfqws2HookHintTiming, wake func() bool) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNFQWS2HookHint(ctx, path, timing, wake)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			started := time.Now()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("hint did not stop after cancellation")
			}
			if time.Since(started) > time.Second {
				t.Fatal("hint stopped slowly", time.Since(started))
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// nfqws2HookWatched reports whether an inotify descriptor of this process
// watches the file's current inode, read from /proc/self/fdinfo.
func nfqws2HookWatched(t *testing.T, path string) bool {
	t.Helper()
	var stat unix.Stat_t
	if unix.Stat(path, &stat) != nil {
		return false
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	needle := fmt.Sprintf(" ino:%x ", stat.Ino)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil || target != "anon_inode:inotify" {
			continue
		}
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", entry.Name()))
		if err == nil && strings.Contains(string(info), needle) {
			return true
		}
	}
	return false
}

func waitNFQWS2HookWatched(t *testing.T, path string, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for nfqws2HookWatched(t, path) != want {
		if time.Now().After(deadline) {
			t.Fatalf("watch state of %s did not become %v", filepath.Base(path), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openNFQWS2Hook(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
}

func nfqws2HookFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "100-nfqws2.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNFQWS2HookHintWakesOnceAfterSettle(t *testing.T) {
	path := nfqws2HookFile(t)
	wakes := &nfqws2HookWakes{}
	startNFQWS2HookHint(t, path, nfqws2HookHintDefaults, wakes.wake)
	waitNFQWS2HookWatched(t, path, true)
	opened := time.Now()
	openNFQWS2Hook(t, path)
	at := wakes.waitFor(t, 1, 4*time.Second)
	if len(at) != 1 || at[0].Sub(opened) < 1400*time.Millisecond || at[0].Sub(opened) > 3*time.Second {
		t.Fatal("one hook execution did not wake once after the 1.5 s settle", at)
	}
	time.Sleep(2500 * time.Millisecond)
	if at, _ := wakes.snapshot(); len(at) != 1 {
		t.Fatal("one hook execution woke more than once", len(at))
	}
}

func TestNFQWS2HookHintCoalescesBursts(t *testing.T) {
	path := nfqws2HookFile(t)
	wakes := &nfqws2HookWakes{}
	startNFQWS2HookHint(t, path, nfqws2HookHintFast, wakes.wake)
	waitNFQWS2HookWatched(t, path, true)
	for i := 0; i < 10; i++ {
		openNFQWS2Hook(t, path)
		time.Sleep(10 * time.Millisecond)
	}
	wakes.waitFor(t, 2, 1500*time.Millisecond)
	if at, _ := wakes.snapshot(); len(at) != 1 {
		t.Fatal("a short burst did not produce exactly one wake", len(at))
	}
	// A burst longer than the hard limit wakes during the burst, never
	// more often than the interval, and once more after it settles.
	started := time.Now()
	for time.Since(started) < 1500*time.Millisecond {
		openNFQWS2Hook(t, path)
		time.Sleep(50 * time.Millisecond)
	}
	ended := time.Now()
	at := wakes.waitFor(t, 10, 1500*time.Millisecond)
	if len(at) < 3 || !at[1].Before(ended) {
		t.Fatal("a long burst was not capped by the hard settle limit", at, ended)
	}
	for i := 1; i < len(at); i++ {
		if at[i].Sub(at[i-1]) < nfqws2HookHintFast.interval-20*time.Millisecond {
			t.Fatal("wakes exceeded the rate limit", at)
		}
	}
	if len(at) > 2+int(1500*time.Millisecond/nfqws2HookHintFast.interval) {
		t.Fatal("too many wakes for one long burst", len(at))
	}
}

func TestNFQWS2HookHintRearmsReplacedFile(t *testing.T) {
	path := nfqws2HookFile(t)
	wakes := &nfqws2HookWakes{}
	startNFQWS2HookHint(t, path, nfqws2HookHintFast, wakes.wake)
	waitNFQWS2HookWatched(t, path, true)
	// A package reinstall removes and recreates the hook.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n# reinstalled\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	waitNFQWS2HookWatched(t, path, true)
	if at, _ := wakes.snapshot(); len(at) != 0 {
		t.Fatal("replacing the hook was taken for its execution", len(at))
	}
	openNFQWS2Hook(t, path)
	if at := wakes.waitFor(t, 1, 2*time.Second); len(at) != 1 {
		t.Fatal("recreated hook was not re-armed", len(at))
	}
	// An upgrade may also rename a new file over the old one.
	next := filepath.Join(filepath.Dir(path), ".100-nfqws2.sh.new")
	if err := os.WriteFile(next, []byte("#!/bin/sh\n# upgraded\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	waitNFQWS2HookWatched(t, path, true)
	time.Sleep(nfqws2HookHintFast.interval)
	openNFQWS2Hook(t, path)
	if at := wakes.waitFor(t, 2, 2*time.Second); len(at) != 2 {
		t.Fatal("renamed-over hook was not re-armed", len(at))
	}
}

func TestNFQWS2HookHintMissingFileFallsBackAndArmsLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "100-nfqws2.sh")
	wakes := &nfqws2HookWakes{}
	stop := startNFQWS2HookHint(t, path, nfqws2HookHintFast, wakes.wake)
	time.Sleep(400 * time.Millisecond)
	if at, attempts := wakes.snapshot(); len(at) != 0 || attempts != 0 {
		t.Fatal("an absent hook produced a wake")
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	waitNFQWS2HookWatched(t, path, true)
	openNFQWS2Hook(t, path)
	if at := wakes.waitFor(t, 1, 2*time.Second); len(at) != 1 {
		t.Fatal("hook installed later was not armed", len(at))
	}
	stop()
	waitNFQWS2HookWatched(t, path, false)
	// No path (no registered NFQWS2 adapter) returns at once.
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNFQWS2HookHint(context.Background(), "", nfqws2HookHintFast, wakes.wake)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("hint without a path did not return")
	}
}

func TestNFQWS2HookHintRetriesWhileRecoveryRuns(t *testing.T) {
	path := nfqws2HookFile(t)
	wakes := &nfqws2HookWakes{refuse: 2}
	startNFQWS2HookHint(t, path, nfqws2HookHintFast, wakes.wake)
	waitNFQWS2HookWatched(t, path, true)
	openNFQWS2Hook(t, path)
	at := wakes.waitFor(t, 1, 3*time.Second)
	if _, attempts := wakes.snapshot(); len(at) != 1 || attempts != 3 {
		t.Fatal("a hint refused by a running round was not retried", len(at), attempts)
	}
}

// The production lifecycle: StartServiceReconciler arms the hint on the
// registered adapter's hook, a hook execution wakes only node recovery long
// before its 30-second schedule, and shutdown joins the watcher.
func TestNFQWS2HookHintWakesReconcilerThroughLifecycle(t *testing.T) {
	a, _, model := nfqws2HookAppFixture(t)
	prefix := filepath.Join(t.TempDir(), "opt")
	nfq := dataplane.NewNFQWS2Adapter()
	nfq.InitPath = filepath.Join(prefix, "etc", "init.d", "S51nfqws2")
	a.Dataplane.Adapters["nfqws2"] = nfq
	path := filepath.Join(prefix, "etc", "ndm", "netfilter.d", "100-nfqws2.sh")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	initRecoveryScheduleFixture(t, a, now)
	model.class = dataplane.NFQWS2HooksFull
	observations := make(chan struct{}, 16)
	model.observe = func(context.Context, dataplane.Plan) { observations <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartServiceReconciler(ctx)
	defer func() { _ = a.WaitServiceReconciler(context.Background()) }()
	select {
	case <-observations:
	case <-time.After(10 * time.Second):
		t.Fatal("first scheduled round did not observe")
	}
	waitNFQWS2HookWatched(t, path, true)
	time.Sleep(200 * time.Millisecond)
	opened := time.Now()
	openNFQWS2Hook(t, path)
	select {
	case <-observations:
		if elapsed := time.Since(opened); elapsed < 1400*time.Millisecond || elapsed > 10*time.Second {
			t.Fatal("hint woke node recovery outside its settle", elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("hook execution did not wake node recovery before its schedule")
	}
	for _, op := range a.reconcilerSnapshot()["operations"].([]automationOperation) {
		if op.Kind != "node-recovery" && !op.NextRun.Equal(now.Add(time.Hour)) {
			t.Fatalf("hint made %s due", op.Kind)
		}
	}
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := a.WaitServiceReconciler(shutdown); err != nil {
		t.Fatal("reconciler shutdown did not join", err)
	}
	if nfqws2HookWatched(t, path) {
		t.Fatal("hook watch outlived the reconciler")
	}
}
