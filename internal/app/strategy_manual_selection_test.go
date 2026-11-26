package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual HTTP authentication/admission, Store, control and StrategyLab files;
// no installed managed receipt is fabricated and no positive choice claimed.
func TestManualStrategySelectionHTTPMissingNativeSourceKeepsState(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}
	candidate, err := a.StrategyLab.AddCandidate("tcp-tls", "manual", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil {
		t.Fatal(err)
	}
	configBefore := a.Store.Get()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "POST", "/api/v1/strategy-lab/selections", map[string]any{"mode": "manual", "service_id": "telegram", "protocol": "tcp", "ip_family": "ipv4", "candidate_id": candidate.ID}, componentRecoveryToken, server.URL)
	after, err := os.ReadFile(a.StrategyLab.Path)
	if status != http.StatusServiceUnavailable || !bytes.Contains(data, []byte("MANAGED_NFQWS_SOURCE_UNAVAILABLE")) || err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(configBefore, a.Store.Get()) {
		t.Fatal("HTTP forged choice/source or changed config", status, string(data), err)
	}
	if state := a.Operations.Snapshot(); state.Active != 0 || state.Fenced || len(a.StrategyLab.Snapshot().Selections) != 0 {
		t.Fatal("refusal retained operation or selection", state)
	}
}

func TestManualStrategySelectionHTTPActualStopKeepsSourceAndReportsRefusal(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	a.Catalog = catalog.Catalog{Services: []catalog.Service{{ID: "telegram", Name: "Telegram"}}}
	candidate, err := a.StrategyLab.AddCandidate("tcp-tls", "manual", "--filter-tcp=443", "expert")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	control, present, err := operationgate.ReadSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil || !present {
		t.Fatal(err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot, control.InstallationID, control.Sequence); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "POST", "/api/v1/strategy-lab/selections", map[string]any{"mode": "manual", "service_id": "telegram", "protocol": "tcp", "ip_family": "ipv4", "candidate_id": candidate.ID}, componentRecoveryToken, server.URL)
	after, err := os.ReadFile(a.StrategyLab.Path)
	if status != http.StatusServiceUnavailable || !bytes.Contains(data, []byte("SELF_UPDATE_RECOVERY_REQUIRED")) || err != nil || !bytes.Equal(before, after) {
		t.Fatal("Stop was bypassed", status, string(data), err)
	}
}

func TestManualStrategySelectionDoesNotFallbackForUnsupportedModeOrAction(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	if _, err := a.StrategyLab.AddCandidate("tcp-tls", "original", "--filter-tcp=443", "expert"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []map[string]any{{"mode": "auto"}, {"mode": "manual", "action": "reset"}, {"mode": "manual", "service_id": "unknown", "candidate_id": "foreign", "protocol": "tcp", "ip_family": "ipv4"}} {
		body, _ := json.Marshal(input)
		response := httptest.NewRecorder()
		a.strategyLabSelections(response, httptest.NewRequest("POST", "/api/v1/strategy-lab/selections", bytes.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatal("invalid manual request fell through", response.Code, response.Body.String())
		}
	}
	after, err := os.ReadFile(a.StrategyLab.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid mode/action changed source", err)
	}
}
