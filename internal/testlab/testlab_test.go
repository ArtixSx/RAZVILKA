package testlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestProbeCurrent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	r := NewRunner()
	r.Client = ts.Client()
	r.Client.Timeout = 2 * time.Second
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "test", Name: "Test", ProbeURL: ts.URL}}}
	got := r.ProbeCurrent(context.Background(), cat, nil)
	if len(got) != 1 || got[0].Status != "pass" || got[0].HTTPStatus != 204 {
		t.Fatalf("unexpected result: %+v", got)
	}
	snap := r.Snapshot(cat)
	if len(snap.Current) != 1 {
		t.Fatalf("snapshot missing result: %+v", snap)
	}
}

func TestDecodeRunRequest(t *testing.T) {
	ids, err := DecodeRunRequest(strings.NewReader(`{"services":["youtube","chatgpt"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "youtube" {
		t.Fatalf("ids=%v", ids)
	}
}

type fakeRouteProber struct{}

func (fakeRouteProber) Probe(_ context.Context, service catalog.Service, route string) Result {
	return Result{ServiceID: service.ID, ServiceName: service.Name, Route: route, Status: "pass", RouteConfirmed: true, EvidenceSource: "test", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
}

func TestProbeRoutesStoresConfirmedMatrixEvidence(t *testing.T) {
	runner := NewRunner()
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", ProbeURL: "https://example.com/"}}}
	results := runner.ProbeRoutes(context.Background(), cat, []string{"video"}, []string{"warp-wg"}, fakeRouteProber{})
	if len(results) != 1 || !results[0].RouteConfirmed {
		t.Fatalf("results = %+v", results)
	}
	snapshot := runner.Snapshot(cat)
	found := false
	for _, cell := range snapshot.Matrix {
		if cell.ServiceID == "video" && cell.Route == "warp-wg" && cell.Last != nil {
			found = cell.Status == "pass" && cell.Last.RouteConfirmed
		}
	}
	if !found {
		t.Fatalf("confirmed matrix cell missing: %+v", snapshot.Matrix)
	}
}
