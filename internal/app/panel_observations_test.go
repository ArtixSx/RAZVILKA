package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routerstats"
	"github.com/ArtixSx/razvilka/internal/telemetry"
)

func TestPanelMetricsAndConnectionsRemainReadableDuringExclusiveWork(t *testing.T) {
	a := panelTestApp(t)
	a.Stats = routerstats.New(routerstats.Collector{WANDetector: func() string { panic("HTTP sampled the network") }, DiskProbe: func(string) (uint64, uint64, error) { panic("HTTP inspected disk") }})
	a.Telemetry = telemetry.NewStore()
	a.Telemetry.Upsert(telemetry.Connection{ID: "test-row", ServiceID: "discord"})
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	handler := a.Handler(http.NotFoundHandler()) // no configuration Store
	for _, fence := range []bool{false, true} {
		if fence {
			a.Operations.Fence()
		}
		for _, path := range []string{"/api/v1/metrics?limit=1", "/api/v1/metrics?period=week&limit=1", "/api/v1/connections?include_closed=true"} {
			for _, method := range []string{"GET", "POST", "DELETE"} {
				for _, authenticated := range []bool{false, true} {
					r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
					r.Header.Set("Content-Type", "application/json")
					if authenticated {
						r.Header.Set("Authorization", "Bearer "+panelTestToken)
					}
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					want := 200
					if method != "GET" {
						want = 405
					}
					if !authenticated {
						want = 401
					}
					if w.Code != want || authenticated && w.Header().Get("Cache-Control") != "no-store" {
						t.Fatalf("%s %s auth=%v: %d %s", method, path, authenticated, w.Code, w.Body.String())
					}
					if w.Code == 200 {
						var body map[string]json.RawMessage
						if json.Unmarshal(w.Body.Bytes(), &body) != nil {
							t.Fatal("invalid response")
						}
						if strings.Contains(path, "connections") && (string(body["active"]) != "1" || !strings.Contains(string(body["connections"]), "test-row")) {
							t.Fatal(w.Body.String())
						}
					}
					if !a.Operations.Snapshot().Exclusive {
						t.Fatal("observation released the worker's admission")
					}
				}
			}
		}
	}
}
