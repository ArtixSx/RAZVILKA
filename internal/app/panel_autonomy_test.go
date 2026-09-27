package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPanelAutonomyReadDoesNotInitializeSidecars(t *testing.T) {
	a := autonomyAPIFixture(t)
	if a.collectPanelAutonomy(context.Background(), strings.Repeat("a", 32), a.localPanelAutonomy) || a.autonomy.loaded {
		t.Fatal("presentation initialized consent")
	}
	saveAutonomyFixturePolicy(t, a)
	if !a.collectPanelAutonomy(context.Background(), strings.Repeat("a", 32), a.localPanelAutonomy) {
		t.Fatal("no publication")
	}
	var image map[string]json.RawMessage
	if json.Unmarshal(a.panelAutonomyAt(time.Now()).Data, &image) != nil || len(image["policy"]) == 0 || len(image["starter"]) == 0 {
		t.Fatal("missing saved permissions/starter")
	}
	// Deleting the Store reference cannot affect this serialized publication.
	a.Store = nil
	if a.panelAutonomyAt(time.Now()).State != "available" {
		t.Fatal("presentation read Store")
	}
}

func TestPanelAutonomyCollectorRejectsMixedObservations(t *testing.T) {
	a := autonomyAPIFixture(t)
	data := map[string]any{"policy": map[string]any{"revision": 1}, "catalog_services": []string{"one"}}
	collect := func(context.Context, time.Time) (map[string]any, bool) {
		if a.Operations.Snapshot().Active != 0 {
			t.Fatal("file collection retained admission")
		}
		return data, true
	}
	if !a.collectPanelAutonomy(context.Background(), strings.Repeat("a", 32), collect) {
		t.Fatal("no publication")
	}
	first := a.panelSnapshots.autonomy.Load()
	data["catalog_services"].([]string)[0] = "changed"
	if strings.Contains(string(first.Data), "changed") {
		t.Fatal("mutable publication")
	}
	for _, exclusive := range []bool{false, true} {
		if a.collectPanelAutonomy(context.Background(), "same", func(ctx context.Context, _ time.Time) (map[string]any, bool) {
			enter := a.Operations.Enter
			if exclusive {
				enter = a.Operations.Exclusive
			}
			release, err := enter(ctx)
			if err != nil {
				t.Fatal(err)
			}
			release()
			return data, true
		}) {
			t.Fatal("intervening completed operation accepted")
		}
	}
	if a.collectPanelAutonomy(context.Background(), "same", func(context.Context, time.Time) (map[string]any, bool) { return data, false }) {
		t.Fatal("failed observation accepted")
	}
	data["oversized"] = strings.Repeat("x", maxPanelSnapshotBytes)
	if a.collectPanelAutonomy(context.Background(), "same", collect) {
		t.Fatal("unbounded publication")
	}
	if a.panelSnapshots.autonomy.Load() != first {
		t.Fatal("last valid image was destroyed")
	}
	for _, offset := range []time.Duration{panelAutonomyLifetime, -time.Minute} {
		v := a.panelAutonomyAt(first.ObservedAt.Add(offset))
		if v.State != "expired" || len(v.Data) != 0 {
			t.Fatal("expired/future data exposed")
		}
	}
	if a.panelAutonomyAt(first.ObservedAt.Add(16*time.Second)).State != "retained" {
		t.Fatal("old data presented as current")
	}
}

func TestPanelAutonomyHTTPAvailableWhileApplyOrRecoveryOwnsAdmission(t *testing.T) {
	a := autonomyAPIFixture(t)
	a.Security = panelTestApp(t).Security
	saveAutonomyFixturePolicy(t, a)
	if !a.collectPanelAutonomy(context.Background(), strings.Repeat("b", 32), a.localPanelAutonomy) {
		t.Fatal("no publication")
	}
	a.Store = nil // Any live collection in HTTP will panic, even without journal IO.
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	request := func(method, path string, auth bool) (int, string) {
		r, _ := http.NewRequest(method, server.URL+path, nil)
		r.Header.Set("Content-Type", "application/json")
		if auth {
			r.Header.Set("Authorization", "Bearer "+panelTestToken)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.Fence()
		}
		before := a.Operations.Snapshot()
		if a.collectPanelAutonomy(context.Background(), "never", func(context.Context, time.Time) (map[string]any, bool) {
			t.Fatal("collector ran during restore")
			return nil, false
		}) {
			t.Fatal("published busy image")
		}
		for _, method := range []string{"GET", "HEAD"} {
			if code, body := request(method, panelAutonomyPath, false); code != 401 || strings.Contains(body, "policy") {
				t.Fatal(code, body)
			}
		}
		for i := 0; i < 20; i++ {
			code, body := request("GET", panelAutonomyPath, true)
			var value panelAutonomyResponse
			if code != 200 || json.Unmarshal([]byte(body), &value) != nil || value.State != "retained" || value.Revision != 1 || value.Dataplane != "not-checked" {
				t.Fatal(code, body)
			}
		}
		if code, _ := request("HEAD", panelAutonomyPath, true); code != 200 {
			t.Fatal(code)
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			if code, _ := request(method, panelAutonomyPath, true); code != 405 {
				t.Fatal(method, code)
			}
		}
		want := 409
		if fenced {
			want = 503
		}
		if code, _ := request("GET", "/api/v1/autonomy", true); code != want {
			t.Fatal("live read escaped admission", code)
		}
		if a.Operations.Snapshot() != before {
			t.Fatal("read changed admission")
		}
	}
}
