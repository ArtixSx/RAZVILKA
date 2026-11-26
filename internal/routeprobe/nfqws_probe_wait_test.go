package routeprobe

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestNFQWSProbeWaitCancelsWithoutTakingTheOwnerSlot(t *testing.T) {
	m := &Manager{System: func() systemprobe.Snapshot { return systemprobe.Snapshot{} }}
	release, err := m.acquireNFQWSProbe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	held := true
	defer func() {
		if held {
			release()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	waiting := make(chan testlab.Result, 1)
	go func() {
		close(started)
		// An unacceptable port makes a wrongly admitted probe harmless and
		// distinguishable without contacting any external address.
		waiting <- m.probeNFQWS(ctx, catalog.Service{ID: "test", ProbeURL: "https://example.com:444/"})
	}()
	<-started
	directDone := make(chan testlab.Result, 1)
	go func() {
		directDone <- m.Probe(context.Background(), catalog.Service{ID: "test", ProbeURL: "https://example.com/"}, "direct")
	}()
	select {
	case result := <-directDone:
		if result.Route != "direct" || result.RouteConfirmed || result.Detail == "" {
			t.Fatalf("unexpected independent probe: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent direct probe waited for NFQWS2")
	}
	select {
	case result := <-waiting:
		t.Fatalf("second probe bypassed the held owner slot: %+v", result)
	default:
	}
	cancel()
	select {
	case result := <-waiting:
		if result.RouteConfirmed || result.Detail != context.Canceled.Error() {
			t.Fatalf("canceled waiter entered a probe: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled probe kept waiting for the active owner")
	}

	release()
	held = false
	next, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	releaseNext, err := m.acquireNFQWSProbe(next)
	if err != nil {
		t.Fatalf("canceled waiter retained the owner slot: %v", err)
	}
	releaseNext()
}
