package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func slottedFakeChecker(t *testing.T, slots int) *ExactNodeChecker {
	t.Helper()
	checker := fakeExactNodeChecker(t)
	checker.gate = NewExactNodeCheckerSlots(checker.StateRoot, slots).gate
	return checker
}

// Each slot has its own directory, loopback port and process identity, so
// parallel checks cannot collide; slot 0 keeps the single-slot layout.
func TestExactNodeCheckerSlotSessionsAreDisjoint(t *testing.T) {
	checker := NewExactNodeCheckerSlots(t.TempDir(), 9)
	if checker.Capacity() != MaxExactNodeSlots {
		t.Fatalf("capacity %d not bounded", checker.Capacity())
	}
	if NewExactNodeCheckerSlots(t.TempDir(), 0).Capacity() != 1 {
		t.Fatal("zero slots not raised to one")
	}
	seen := map[string]bool{}
	for slot := range MaxExactNodeSlots {
		session := checker.session(slot)
		for _, key := range []string{session.Root, session.Address, session.Spec.ID, session.Spec.PIDPath} {
			if seen[key] {
				t.Fatalf("slot %d shares %s", slot, key)
			}
			seen[key] = true
		}
		if session.Port != checker.Port+slot || filepath.Dir(session.Spec.MatchArg) != session.Root {
			t.Fatalf("slot %d session %+v", slot, session)
		}
	}
	if first := checker.session(0); first.Root != checker.StateRoot || first.Spec.ID != "node-check-sing-box" {
		t.Fatalf("slot 0 changed the single-slot layout: %+v", first)
	}
}

func TestExactNodeCheckerRunsOneCheckPerFreeSlot(t *testing.T) {
	checker := slottedFakeChecker(t, 2)
	entered := make(chan exactNodeSession, 2)
	release := make(chan struct{})
	checker.prepare = func(_ context.Context, session exactNodeSession, _ NodeCheckRequest, _ exactNodeEndpoint) (exactNodeSession, error) {
		session.Spec.Binary = "sing-box"
		entered <- session
		<-release
		return session, nil
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := checker.Check(context.Background(), checkedNodeRequest())
			if err == nil && !result.Available {
				err = errors.New(result.Message)
			}
			results <- err
		}()
	}
	first, second := <-entered, <-entered
	if first.Root == second.Root || first.Port == second.Port {
		t.Fatalf("parallel checks share a slot: %+v %+v", first, second)
	}
	if _, err := checker.Check(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeBusy) {
		t.Fatalf("check beyond capacity: %v", err)
	}
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(checker.gate) != 2 {
		t.Fatalf("slots not returned: %d free", len(checker.gate))
	}
}

// Screening decides only nodes that fail DNS or transport, with the result a
// full check would record; it takes no slot, so it runs beside full checks.
func TestExactNodeScreenTransport(t *testing.T) {
	checker := fakeExactNodeChecker(t)
	<-checker.gate // A full check holds the only slot.
	checker.dialTransport = func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error) {
		return true, errors.New("refused")
	}
	screened, decided, err := checker.ScreenTransport(context.Background(), checkedNodeRequest())
	full := fakeExactNodeChecker(t)
	full.dialTransport = checker.dialTransport
	checked, checkErr := full.Check(context.Background(), checkedNodeRequest())
	if err != nil || checkErr != nil || !decided || screened.ErrorCode != "node-transport-failed" || screened.ErrorCode != checked.ErrorCode ||
		screened.Stage != checked.Stage || screened.TestLevel != checked.TestLevel || screened.Verdict != checked.Verdict || screened.RoutePathID != checked.RoutePathID || screened.ExpiresAt.IsZero() {
		t.Fatalf("screen %+v differs from check %+v (%v, %v)", screened, checked, err, checkErr)
	}
	checker.dialTransport = func(context.Context, exactNodeEndpoint, []netip.Addr) (bool, error) { return true, nil }
	screened, decided, err = checker.ScreenTransport(context.Background(), checkedNodeRequest())
	if err != nil || decided || screened.Available {
		t.Fatalf("reachable node decided by screening: %+v decided=%t err=%v", screened, decided, err)
	}
	checker.FreshProfile = func(context.Context) (string, error) { return "wan-ffffffffffff", nil }
	if _, _, err := checker.ScreenTransport(context.Background(), checkedNodeRequest()); !errors.Is(err, ErrExactNodeNetworkChanged) {
		t.Fatalf("screen in another network: %v", err)
	}
}

func TestExactNodeRecoverCleansEverySlot(t *testing.T) {
	checker := slottedFakeChecker(t, 2)
	// A previous run with four slots left its last slot behind.
	if err := os.MkdirAll(checker.session(3).Root, 0o700); err != nil {
		t.Fatal(err)
	}
	cleaned := map[string]bool{}
	checker.cleanup = func(_ context.Context, session exactNodeSession) error {
		cleaned[session.Root] = true
		return nil
	}
	if err := checker.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cleaned) != 3 || !cleaned[checker.session(0).Root] || !cleaned[checker.session(1).Root] || !cleaned[checker.session(3).Root] || cleaned[checker.session(2).Root] {
		t.Fatalf("recovered slots %v", cleaned)
	}
	if len(checker.gate) != 2 {
		t.Fatal("recovery kept slots")
	}
	<-checker.gate
	if err := checker.Recover(context.Background()); !errors.Is(err, ErrExactNodeBusy) {
		t.Fatalf("recovery beside a running check: %v", err)
	}
	if len(checker.gate) != 1 {
		t.Fatal("busy recovery kept a slot")
	}
}
