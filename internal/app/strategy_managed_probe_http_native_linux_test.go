//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func runManagedStrategyProbeNativeHTTP(t *testing.T, a *App, candidate string, readEmpty func(context.Context) error) {
	t.Helper()
	const token = "native-probe-original-api-token-1234567890"
	var err error
	a.Security, err = security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a.ExecutionHistory = updatecheck.NewExecutionHistoryAdmission(dataplane.InspectRetainedExecutionReadVersion)
	before := a.Store.Get()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	request := func(method, path, body, origin string, authenticated bool) (int, []byte) {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	path := "/api/v1/strategy-lab/candidates/" + candidate + "/probe"
	const body = `{"service_id":"native","ip_family":"ipv4"}`
	for _, negative := range []struct {
		auth   bool
		origin string
	}{{false, server.URL}, {true, "https://foreign.invalid"}} {
		code, data := request(http.MethodPost, path, body, negative.origin, negative.auth)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatal("actual authentication/origin negative admitted", code, string(data))
		}
	}
	for pass := 0; pass < strategylab.RequiredPasses; pass++ {
		code, data := request(http.MethodPost, path, body, server.URL, true)
		if code != http.StatusOK {
			t.Fatal("actual managed probe HTTP pass", pass, code, string(data))
		}
		if a.managedStrategyProbePending() || a.managedNFQList.probe.Pending() {
			t.Fatal("successful handler retained original operation")
		}
		if err := readEmpty(context.Background()); err != nil {
			t.Fatal("actual handler left packet resources", err)
		}
	}
	selection := `{"service_id":"native","protocol":"tcp","ip_family":"ipv4","candidate_id":"` + candidate + `","mode":"preferred"}`
	code, data := request(http.MethodPost, "/api/v1/strategy-lab/selections", selection, server.URL, true)
	if code != http.StatusOK {
		t.Fatal("actual managed selection HTTP", code, string(data))
	}
	code, data = request(http.MethodGet, "/api/v1/strategy-lab", "", server.URL, true)
	var snapshot strategylab.Snapshot
	if code != http.StatusOK || json.Unmarshal(data, &snapshot) != nil {
		t.Fatal("actual managed snapshot HTTP", code, string(data))
	}
	eligible := false
	for _, summary := range snapshot.Summaries {
		eligible = eligible || summary.CandidateID == candidate && summary.Eligible
	}
	healthy := false
	for _, selected := range snapshot.Selections {
		healthy = healthy || selected.CandidateID == candidate && selected.Healthy && selected.Mode == strategylab.ModePreferred
	}
	if len(snapshot.Evidence) != strategylab.RequiredPasses || !eligible || !healthy || snapshot.QuiescenceUnknown {
		t.Fatalf("actual App did not retain current three-pass authority: %s", data)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || a.StrategyLab.Executor != nil {
		t.Fatal("probe/selection mutated live config or enabled legacy executor")
	}
	t.Log("actual authenticated App HTTP: three native TLS/counter passes, per-request original admission, current preferred selection and snapshot; live routing unchanged; CI classification only, no router/LAN acceptance")
}
