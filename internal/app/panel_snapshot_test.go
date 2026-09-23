package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engine"
)

func savedPanelFixture(t *testing.T) *App {
	t.Helper()
	a := panelTestApp(t)
	var err error
	a.Store, err = config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram", ProbeURL: "https://private.invalid/secret"}}}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "auto", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPanelSnapshotPublicationAndExpiry(t *testing.T) {
	a := savedPanelFixture(t)
	now := time.Now()
	if !a.publishPanelSnapshot(context.Background(), strings.Repeat("a", 32), now) {
		t.Fatal("initial snapshot missing")
	}
	first := a.panelSnapshotAt(now)
	if first.Revision != 1 || first.State != "available" || first.Dataplane != "not-checked" || strings.Contains(string(first.Data), "secret") {
		t.Fatalf("invalid presentation: %+v", first)
	}
	var data panelSavedData
	if json.Unmarshal(first.Data, &data) != nil || data.Services[0].Applied.Enabled || !data.Services[0].Desired.Enabled || data.Services[0].Applied.Route != "auto" {
		t.Fatalf("desired/applied/proof confused: %+v", data)
	}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if !a.publishPanelSnapshot(context.Background(), strings.Repeat("a", 32), now.Add(time.Second)) || a.panelSnapshotAt(now.Add(time.Second)).Revision != 2 {
		t.Fatal("completed transition not published")
	}
	var unchanged panelSavedData
	_ = json.Unmarshal(first.Data, &unchanged)
	if !unchanged.Services[0].Desired.Enabled || unchanged.Services[0].Sources[0] != "192.168.1.40/32" {
		t.Fatal("published snapshot shared mutable Store memory")
	}
	for _, offset := range []time.Duration{panelSnapshotLifetime + time.Second, -time.Minute} {
		expired := a.panelSnapshotAt(now.Add(offset))
		if expired.State != "expired" || len(expired.Data) != 0 {
			t.Fatalf("expired or future data exposed: %+v", expired)
		}
	}
	previous := a.panelSnapshots.latest.Load()
	a.Catalog.Services[0].Name = strings.Repeat("x", maxPanelSnapshotBytes)
	if a.publishPanelSnapshot(context.Background(), "same", now) || a.panelSnapshots.latest.Load() != previous {
		t.Fatal("oversized replacement destroyed valid image")
	}
}

func TestPanelSnapshotRealHTTPBusyRecoveryAuth(t *testing.T) {
	a := savedPanelFixture(t)
	now := time.Now()
	a.publishPanelSnapshot(context.Background(), strings.Repeat("b", 32), now)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// If the request reaches a live Store or the inventory it will fail/panic.
	a.Store = nil
	a.EngineInventory = func() []engine.Status { panic("snapshot ran inventory") }
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	request := func(method string, auth bool) (int, string) {
		r, _ := http.NewRequest(method, server.URL+panelSnapshotPath, nil)
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.Header.Set("Authorization", "Bearer "+panelTestToken)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable snapshot")
		}
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.Fence()
		}
		before := a.Operations.Snapshot()
		if a.publishPanelSnapshot(context.Background(), "must-not-publish", now) {
			t.Fatal("published during mutation/recovery")
		}
		for _, method := range []string{"GET", "HEAD"} {
			if code, body := request(method, false); code != 401 || strings.Contains(body, "Telegram") {
				t.Fatal(code, body)
			}
		}
		for i := 0; i < 20; i++ {
			code, body := request("GET", true)
			var result panelSnapshotResponse
			if code != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Revision != 1 || result.State != "retained" || result.Admission != before {
				t.Fatal(code, body)
			}
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			if code, _ := request(method, true); code != 405 {
				t.Fatal(method, code)
			}
		}
		if a.Operations.Snapshot() != before {
			t.Fatal("read released admission")
		}
	}
}

func TestPanelSnapshotRemainsReadableDuringJobCancelCleanup(t *testing.T) {
	a, _ := serviceControlFixture(t, 1)
	a.Security = panelTestApp(t).Security
	a.publishPanelSnapshot(context.Background(), strings.Repeat("c", 32), time.Now())
	entered, cleanup, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, _ dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		close(entered)
		<-ctx.Done()
		close(cleanup)
		<-finish
		return dataplane.NodeCheckResult{}, ctx.Err()
	})
	revision := a.Store.Get().Revision
	done, err := a.startServiceControlJob(context.Background(), serviceControlJobRequest{ExpectedRevision: &revision, Kind: "select", ServiceIDs: []string{"telegram"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("checker not entered")
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	request := func(method, path string) int {
		r, _ := http.NewRequest(method, server.URL+path, nil)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+panelTestToken)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	id := a.panelSnapshotAt(time.Now()).Job.ID
	if request("DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", id+1)) != 409 {
		t.Fatal("stale cancel accepted")
	}
	if request("DELETE", fmt.Sprintf("/api/v1/service-control/current?job_id=%d", id)) != 200 {
		t.Fatal("cancel refused")
	}
	select {
	case <-cleanup:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup not entered")
	}
	if request("GET", panelSnapshotPath) != 200 || request("GET", "/api/v1/services") != 409 || a.Operations.Snapshot().State != "busy" {
		t.Fatal("cleanup ownership or presentation failed")
	}
	close(finish)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup not joined")
	}
	if a.Operations.Snapshot().State != "idle" {
		t.Fatal("job kept admission after cleanup")
	}
	if !a.publishPanelSnapshot(context.Background(), strings.Repeat("c", 32), time.Now()) {
		t.Fatal("publication not resumed")
	}
}

func TestPanelSnapshotPublisherRestartAndShutdown(t *testing.T) {
	a := savedPanelFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.StartPanelSnapshots(ctx)
	first := a.panelSnapshotAt(time.Now())
	cancel()
	stop, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	if a.WaitPanelSnapshots(stop) != nil || first.Revision != 1 {
		t.Fatal("publisher lifecycle")
	}
	b := savedPanelFixture(t)
	ctx2, cancel2 := context.WithCancel(context.Background())
	b.StartPanelSnapshots(ctx2)
	cancel2()
	if b.WaitPanelSnapshots(stop) != nil || b.panelSnapshotAt(time.Now()).InstanceID == first.InstanceID {
		t.Fatal("restart reused presentation identity")
	}
}
