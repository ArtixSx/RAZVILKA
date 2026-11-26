package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engine"
)

func TestPanelInventoryCollectsOutsideAdmissionAndRejectsInterveningWork(t *testing.T) {
	a := savedPanelFixture(t)
	data := panelInventoryData{Components: []components.View{{Spec: components.Spec{ID: "sing-box"}, Installed: true, InstalledVersion: "1.2.3"}}, Engines: []engine.Status{}}
	collect := func(context.Context) (panelInventoryData, error) {
		if a.Operations.Snapshot().Active != 0 {
			t.Fatal("collector retained admission")
		}
		return data, nil
	}
	if !a.collectPanelInventory(context.Background(), strings.Repeat("a", 32), collect) {
		t.Fatal("initial publication failed")
	}
	first := a.panelSnapshots.inventory.Load()
	data.Components[0].InstalledVersion = "4.5.6"
	var saved panelInventoryData
	_ = json.Unmarshal(first.Data, &saved)
	if saved.Components[0].InstalledVersion != "1.2.3" {
		t.Fatal("mutable presentation")
	}
	for _, exclusive := range []bool{false, true} {
		if a.collectPanelInventory(context.Background(), "same", func(ctx context.Context) (panelInventoryData, error) {
			enter := a.Operations.Enter
			if exclusive {
				enter = a.Operations.Exclusive
			}
			release, err := enter(ctx)
			if err != nil {
				t.Fatal(err)
			}
			release()
			return data, nil
		}) {
			t.Fatal("intervening completed operation accepted")
		}
	}
	if a.panelSnapshots.inventory.Load() != first {
		t.Fatal("valid observation lost")
	}
	if a.collectPanelInventory(context.Background(), "same", func(context.Context) (panelInventoryData, error) { return data, errors.New("inventory failed") }) {
		t.Fatal("failure published")
	}
	data.Components[0].Name = strings.Repeat("x", maxPanelSnapshotBytes)
	if a.collectPanelInventory(context.Background(), "same", collect) {
		t.Fatal("oversized inventory published")
	}
	for _, offset := range []time.Duration{panelInventoryLifetime + time.Second, -time.Minute} {
		v := a.panelInventoryAt(first.ObservedAt.Add(offset))
		if v.State != "expired" || len(v.Data) != 0 {
			t.Fatal("expired image exposed")
		}
	}
}

func TestPanelInventoryHTTPNeverInvokesCollector(t *testing.T) {
	a := savedPanelFixture(t)
	if !a.collectPanelInventory(context.Background(), strings.Repeat("a", 32), func(context.Context) (panelInventoryData, error) {
		return panelInventoryData{Components: []components.View{{Spec: components.Spec{ID: "sing-box"}, Installed: true}}, Engines: []engine.Status{}}, nil
	}) {
		t.Fatal("publication failed")
	}
	a.Store, a.Components = nil, nil
	a.EngineInventory = func() []engine.Status { panic("HTTP reached observation") }
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	for _, fence := range []bool{false, true} {
		if fence {
			a.Operations.Fence()
		}
		for _, method := range []string{"GET", "HEAD", "POST", "DELETE"} {
			for _, auth := range []bool{false, true} {
				r, _ := http.NewRequest(method, server.URL+panelInventoryPath, nil)
				r.Header.Set("Content-Type", "application/json")
				if auth {
					r.Header.Set("Authorization", "Bearer "+panelTestToken)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				want := 200
				if method == "POST" || method == "DELETE" {
					want = 405
				}
				if !auth {
					want = 401
				}
				if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal(method, auth, response.StatusCode, string(body))
				}
				if auth && method == "GET" {
					var value panelInventoryResponse
					if json.Unmarshal(body, &value) != nil || value.State != "retained" || value.Dataplane != "not-checked" || len(value.Data) == 0 {
						t.Fatal(string(body))
					}
				}
			}
		}
	}
	if !a.Operations.Snapshot().Exclusive {
		t.Fatal("read released worker")
	}
}

func TestPanelInventoryCleanupAndPublisherAreIndependent(t *testing.T) {
	a := savedPanelFixture(t)
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	go func() {
		done <- a.collectPanelInventory(context.Background(), "instance", func(context.Context) (panelInventoryData, error) {
			close(entered)
			<-finish
			return panelInventoryData{}, nil
		})
	}()
	<-entered
	// Saved settings remain publishable while inventory is blocked, without
	// invalidating this local read-only collection.
	if !a.publishPanelSnapshot(context.Background(), "instance", time.Now()) {
		t.Fatal("settings publisher blocked")
	}
	close(finish)
	if !<-done {
		t.Fatal("read-only publisher invalidated inventory")
	}
	// Busy/recovery never invokes collection at all.
	release, _ := a.Operations.Exclusive(context.Background())
	defer release()
	if a.collectPanelInventory(context.Background(), "instance", func(context.Context) (panelInventoryData, error) { panic("collection during worker") }) {
		t.Fatal("collected during worker")
	}
}
