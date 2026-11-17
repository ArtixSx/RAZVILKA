package updatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestExternalBootstrapSourceConfigManagedNFQRelease(t *testing.T) {
	for _, route := range []string{"nfqws2", "auto", "xray:node-one", "stopped", "legacy"} {
		t.Run(route, func(t *testing.T) {
			cfg := config.Default()
			cfg.SchemaVersion = 0
			if route != "legacy" {
				cfg.AppliedNetworkPolicy = &config.NetworkPolicy{Schema: 1, Revision: 1,
					Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
					Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
			}
			if route == "stopped" {
				cfg.ServiceControl.Stopped = true
				cfg.ServiceControl.SuspendedServices = map[string]config.ServiceState{"service": {Enabled: true, Route: "nfqws2"}}
				cfg.ServiceControl.SuspendedRoutes = map[string]string{"service": "nfqws2"}
			} else {
				applied := route
				if route == "legacy" {
					applied = "nfqws2"
				}
				cfg.AppliedServices["service"] = config.ServiceState{Enabled: true, Route: applied}
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			err = inspectExternalBootstrapSourceConfig(path)
			refused := route == "nfqws2" || route == "auto"
			if errors.Is(err, config.ErrManagedNFQReleaseUpdate) != refused || !refused && err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("source preflight migrated or wrote config", err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("source preflight wrote side files", err)
			}
		})
	}
	if err := inspectExternalBootstrapSourceConfig(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
