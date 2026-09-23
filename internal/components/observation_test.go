package components

import (
	"context"
	"testing"
	"time"
)

func TestObservationYieldsToInstallerAndDoesNotRefreshSources(t *testing.T) {
	m := &Manager{BinDir: t.TempDir(), StateDir: t.TempDir()}
	m.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := m.Observe(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("busy observation succeeded")
		}
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("observation queued behind installer")
	}
	m.mu.Unlock()
	// No opkg executable and no release cache: observation stays local.
	m.Client = nil
	views, err := m.Observe(context.Background())
	if err != nil || len(views) == 0 {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.Provider == "github-release" && (view.Available || view.CheckedAt != "") {
			t.Fatal("invented release observation")
		}
	}
}
