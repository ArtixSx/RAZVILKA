package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func dispatcherFixture(t *testing.T, slots int) (*ExactNodeDispatcher, *ExactNodeChecker, *ExactNodeChecker) {
	t.Helper()
	s := slottedFakeChecker(t, slots)
	x := fakeExactXrayChecker(t)
	x.gate = NewExactNodeCheckerSlots(x.StateRoot, slots).gate
	x.Port = 19181 + MaxExactNodeSlots
	d, err := NewExactNodeDispatcher(slots, s, x)
	if err != nil {
		t.Fatal(err)
	}
	return d, s, x
}

func waitDispatcherEntry(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case engine := <-entered:
		return engine
	case <-time.After(5 * time.Second):
		t.Fatal("checker did not enter")
		return ""
	}
}

func TestDispatcherSharesQuotaAcrossEnginesThroughCleanup(t *testing.T) {
	d, s, x := dispatcherFixture(t, 2)
	entered := make(chan string, 4)
	cleanupEntered := make(chan string, 2)
	release, releaseCleanup := make(chan struct{}), make(chan struct{})
	for _, checker := range []*ExactNodeChecker{s, x} {
		prepare := checker.prepare
		checker.prepare = func(ctx context.Context, session exactNodeSession, request NodeCheckRequest, endpoint exactNodeEndpoint) (exactNodeSession, error) {
			entered <- checker.EngineID()
			<-release
			return prepare(ctx, session, request, endpoint)
		}
		checker.cleanup = func(context.Context, exactNodeSession) error {
			cleanupEntered <- checker.EngineID()
			<-releaseCleanup
			return nil
		}
	}
	sv, _ := d.ForEngine("sing-box")
	xv, _ := d.ForEngine("xray")
	if d.Capacity() != 2 || sv.Capacity() != 2 || xv.Capacity() != 2 || xv.EngineID() != "xray" {
		t.Fatal("incorrect capacity/engine")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, run := range []struct {
		checker *DispatchedNodeChecker
		request NodeCheckRequest
	}{{sv, checkedNodeRequest()}, {xv, xrayCheckedRequest()}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := run.checker.Check(context.Background(), run.request)
			if err == nil && (!r.Available || r.RoutePathID != run.checker.EngineID()+":"+run.request.NodeID) {
				err = errors.New("engine lost or proof failed")
			}
			results <- err
		}()
	}
	first, second := waitDispatcherEntry(t, entered), waitDispatcherEntry(t, entered)
	if first == second {
		t.Fatal("one engine monopolized test")
	}
	assertBusy := func() {
		t.Helper()
		for _, run := range []struct {
			checker *DispatchedNodeChecker
			request NodeCheckRequest
		}{{sv, checkedNodeRequest()}, {xv, xrayCheckedRequest()}} {
			if r, err := run.checker.Check(context.Background(), run.request); !errors.Is(err, ErrExactNodeBusy) || r.ProbeID != "" {
				t.Fatal("quota exceeded", err)
			}
			if r, decided, err := run.checker.ScreenTransport(context.Background(), run.request); !errors.Is(err, ErrExactNodeBusy) || decided || r.ProbeID != "" {
				t.Fatal("screen bypassed quota", err)
			}
		}
		if err := d.Recover(context.Background()); !errors.Is(err, ErrExactNodeBusy) {
			t.Fatal("recovery overlapped active check", err)
		}
	}
	assertBusy()
	close(release)
	waitDispatcherEntry(t, cleanupEntered)
	waitDispatcherEntry(t, cleanupEntered)
	assertBusy() // A process being cleaned still owns the shared quota.
	close(releaseCleanup)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(d.gate) != 0 {
		t.Fatal("shared quota leaked")
	}
	// Fresh checks can use both slots after cleanup completes.
	s.cleanup, x.cleanup = func(context.Context, exactNodeSession) error { return nil }, func(context.Context, exactNodeSession) error { return nil }
	if r, err := xv.Check(context.Background(), xrayCheckedRequest()); err != nil || !r.Available {
		t.Fatal(r, err)
	}
}

func TestDispatcherUnsupportedBeforeQuotaDNSAndReputation(t *testing.T) {
	d, _, x := dispatcherFixture(t, 1)
	x.resolve = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("unsupported reached DNS")
		return nil, nil
	}
	d.gate <- struct{}{} // All shared capacity is already in use.
	defer func() { <-d.gate }()
	xv, _ := d.ForEngine("xray")
	request := xrayCheckedRequest()
	request.Outbound = []byte(strings.TrimSuffix(xrayNodeMaterial, "}") + `,"transport":{"type":"xhttp"}}`)
	for _, screen := range []bool{false, true} {
		var result NodeCheckResult
		var err error
		if screen {
			var decided bool
			result, decided, err = xv.ScreenTransport(context.Background(), request)
			if decided {
				t.Fatal("unsupported decided node health")
			}
		} else {
			result, err = xv.Check(context.Background(), request)
		}
		if !errors.Is(err, ErrExactNodeUnsupported) || result.ProbeID != "" || result.NodeID != "" || result.Available || len(d.gate) != 1 || len(x.gate) != 1 {
			t.Fatal("unsupported produced reputation observation or took slot", result, err)
		}
	}
	if _, err := d.ForEngine("mihomo"); !errors.Is(err, ErrExactNodeUnsupported) {
		t.Fatal("implicit engine fallback", err)
	}
}

func TestDispatcherScreenAndCancellationReleaseQuota(t *testing.T) {
	d, s, _ := dispatcherFixture(t, 1)
	sv, _ := d.ForEngine("sing-box")
	entered, release := make(chan string, 1), make(chan struct{})
	s.resolve = func(context.Context, string) ([]netip.Addr, error) {
		entered <- "screen"
		<-release
		return nil, errors.New("DNS fixture failed")
	}
	finished := make(chan error, 1)
	go func() { _, _, err := sv.ScreenTransport(context.Background(), checkedNodeRequest()); finished <- err }()
	waitDispatcherEntry(t, entered)
	xv, _ := d.ForEngine("xray")
	if _, err := xv.Check(context.Background(), xrayCheckedRequest()); !errors.Is(err, ErrExactNodeBusy) {
		t.Fatal("DNS escaped quota", err)
	}
	if err := d.Recover(context.Background()); !errors.Is(err, ErrExactNodeBusy) {
		t.Fatal("recovery overlapped screening", err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := xv.Check(ctx, xrayCheckedRequest()); !errors.Is(err, context.Canceled) || r.ProbeID != "" || len(d.gate) != 0 {
		t.Fatal("canceled request took quota", err)
	}
	if r, err := xv.Check(context.Background(), xrayCheckedRequest()); err != nil || !r.Available {
		t.Fatal("screen retained quota", r, err)
	}
}

func TestDispatcherRecoveryVisitsBothAndKeepsPoisonFence(t *testing.T) {
	d, s, x := dispatcherFixture(t, 1)
	s.poisoned.Store(true)
	x.poisoned.Store(true)
	sCalls, xCalls := 0, 0
	s.cleanup = func(context.Context, exactNodeSession) error { sCalls++; return errors.New("unconfirmed cleanup") }
	x.cleanup = func(context.Context, exactNodeSession) error { xCalls++; return nil }
	if err := d.Recover(context.Background()); err == nil || sCalls != 1 || xCalls != 1 || !s.poisoned.Load() || x.poisoned.Load() || len(d.gate) != 0 {
		t.Fatal("recovery skipped runtime/lost fence", err)
	}
	sv, _ := d.ForEngine("sing-box")
	if _, err := sv.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeUnavailable) {
		t.Fatal("cleanup fence bypassed", err)
	}
	xv, _ := d.ForEngine("xray")
	if r, err := xv.Check(context.Background(), xrayCheckedRequest()); err != nil || !r.Available {
		t.Fatal("unrelated runtime poisoned", r, err)
	}
	s.cleanup = func(context.Context, exactNodeSession) error { return nil }
	if err := sv.Recover(context.Background()); err != nil || s.poisoned.Load() {
		t.Fatal("view did not recover dispatcher", err)
	}
}

func TestDispatcherRejectsSharedResourcesAndInvalidQuota(t *testing.T) {
	for _, mode := range []string{"same-root", "nested-root", "overlapping-ports", "duplicate-engine", "root-directory", "relative-root", "zero", "too-many", "nil"} {
		t.Run(mode, func(t *testing.T) {
			s, x := fakeExactNodeChecker(t), fakeExactXrayChecker(t)
			x.Port = s.Port + MaxExactNodeSlots
			slots := 2
			switch mode {
			case "same-root":
				x.StateRoot = s.StateRoot
			case "nested-root":
				x.StateRoot = filepath.Join(s.StateRoot, "nested")
			case "overlapping-ports":
				x.Port = s.Port + MaxExactNodeSlots - 1
			case "duplicate-engine":
				x.engine = "sing-box"
			case "root-directory":
				x.StateRoot = filepath.VolumeName(x.StateRoot) + string(filepath.Separator)
			case "relative-root":
				x.StateRoot = "relative"
			case "zero":
				slots = 0
			case "too-many":
				slots = MaxExactNodeSlots + 1
			case "nil":
				x = nil
			}
			if _, err := NewExactNodeDispatcher(slots, s, x); !errors.Is(err, ErrExactNodeUnavailable) {
				t.Fatal("unsafe dispatcher accepted", err)
			}
		})
	}
}

func TestDispatcherBusyRecoveryReturnsPartialQuota(t *testing.T) {
	d, s, x := dispatcherFixture(t, 2)
	s.cleanup = func(context.Context, exactNodeSession) error { t.Fatal("partial recovery reached cleanup"); return nil }
	x.cleanup = s.cleanup
	d.gate <- struct{}{}
	if err := d.Recover(context.Background()); !errors.Is(err, ErrExactNodeBusy) || len(d.gate) != 1 {
		t.Fatal("busy recovery retained partial quota", err)
	}
	<-d.gate
	if d.Capacity() != 2 {
		t.Fatal("quota changed")
	}
}
