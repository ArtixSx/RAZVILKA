package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComponentRecoveryInitialInstallAcceptedVersusPendingHTTP(t *testing.T) {
	for _, phase := range []string{"initial-install-prepared", "initial-install-started", "initial-install-verified-idle"} {
		t.Run(phase, func(t *testing.T) {
			a := managedNFQInitialControlFixture(t)
			accepted := phase == "initial-install-verified-idle"
			readback := ""
			if accepted {
				readback = `,"readback_sha256":"` + strings.Repeat("1", 64) + `"`
			}
			// Format-only retained journal fixture: the HTTP reader must report
			// its terminal result without manufacturing fresh runtime evidence.
			data := `{"schema_version":4,"transaction_id":"` + strings.Repeat("f", 32) + `","component":"nfqws2","phase":"` + phase + `","before_version":"absent","after_version":"1.3.1","updated_at":"2026-10-22T00:00:00Z","nfqws_initial_install":{"source_sha256":"28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054","source_size":2382102,"derived_sha256":"` + strings.Repeat("a", 64) + `","derived_size":100,"init_sha256":"` + strings.Repeat("b", 64) + `","owner":"` + strings.Repeat("c", 24) + `","architecture":"arm64","status_sha256":"` + strings.Repeat("d", 64) + `","installation_id":"` + strings.Repeat("e", 32) + `","sequence":1,"revision":0` + readback + `,"derivation":"inert-s51-and-root-owner-v1"},"package":"nfqws2-keenetic","package_file":"nfqws2-keenetic_1.3.1_razvilka-inert.ipk","package_sha256":"` + strings.Repeat("a", 64) + `","configs":null,"supervision_version":1}`
			dir := filepath.Join(a.Components.StateDir, "update-journal")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "current.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer server.Close()
			status, wire := componentHTTP(t, server, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, server.URL)
			var response struct {
				Pending      bool `json:"recovery_required"`
				Idle         bool `json:"installed_idle_accepted"`
				Capabilities struct {
					Idle     bool     `json:"installed_idle_accepted"`
					Error    string   `json:"error"`
					Actions  []string `json:"available_actions"`
					Quiet    bool     `json:"quiescence_confirmed"`
					Inactive bool     `json:"inactivity_confirmed"`
				} `json:"capabilities"`
			}
			if status != http.StatusOK || json.Unmarshal(wire, &response) != nil || response.Pending == accepted || response.Idle != accepted || response.Capabilities.Idle != accepted || (response.Capabilities.Error == "") != accepted {
				t.Fatalf("initial install terminal result misreported: %d %s", status, wire)
			}
			if len(response.Capabilities.Actions) != 0 || response.Capabilities.Quiet || response.Capabilities.Inactive {
				t.Fatalf("retained installation result fabricated action/runtime proof: %s", wire)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("status read changed the journal", err)
			}
		})
	}
}
