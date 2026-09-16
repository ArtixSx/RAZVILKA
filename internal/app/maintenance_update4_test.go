package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"testing"
	"time"
)

func TestMaintenanceChannelChangeDoesNotReuseStableCompletion(t *testing.T) {
	a, p, now := maintenanceFixture(t)
	calls := 0
	a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
		calls++
		return true, false, "test"
	}
	a.autonomyMaintenance(context.Background(), p, now)
	a.autonomy.mu.Lock()
	p.UpdateChannel = "preview"
	p.Revision++
	a.autonomy.doc.Policy = p
	a.autonomy.mu.Unlock()
	a.autonomyMaintenance(context.Background(), p, now.Add(time.Minute))
	if calls != 2 {
		t.Fatal("new channel skipped", calls)
	}
}
func TestCurrentSafeModePreventsAutomaticRefreshAndProbe(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	if e := a.Store.SetSafeMode(true); e != nil {
		t.Fatal(e)
	}
	prober := &pausedRouteProber{entered: make(chan struct{}), resume: make(chan struct{})}
	a.RouteProber = prober
	a.backgroundRound(context.Background(), 1)
	select {
	case <-prober.entered:
		t.Fatal("network probe entered Safe Mode")
	default:
	}
}
