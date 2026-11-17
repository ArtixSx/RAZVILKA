package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestPreflightManagedNFQRefusesBeforeMigration(t *testing.T) {
	cfg := config.Default()
	cfg.SchemaVersion = 0
	cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1, Revision: 1,
		Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
		Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	cfg.AppliedServices["service"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, migrate := range []bool{false, true} {
		// Missing catalogs would fail if the compatibility check ran too late.
		got, err := preflight(path, "absent-catalog", "absent-sources", "absent-community", migrate)
		if !errors.Is(err, config.ErrManagedNFQReleaseUpdate) || got.OK || got.Migrated {
			t.Fatal(got, err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, after) {
			t.Fatal("refusal modified config", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("refusal wrote side files", err)
	}
}

func TestPreflightManagedNFQCompatibilityKeepsStoppedAndOtherRoutes(t *testing.T) {
	for _, route := range []string{"xray:node-one", "wireguard", "direct", "stopped"} {
		t.Run(route, func(t *testing.T) {
			cfg := config.Default()
			cfg.NetworkPolicy = &config.NetworkPolicy{Schema: 1, Revision: 1,
				Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"},
				Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
			if route == "stopped" {
				cfg.ServiceControl.Stopped = true
				cfg.ServiceControl.SuspendedServices = map[string]config.ServiceState{"service": {Enabled: true, Route: "nfqws2"}}
				cfg.ServiceControl.SuspendedRoutes = map[string]string{"service": "nfqws2"}
			} else {
				cfg.AppliedServices["service"] = config.ServiceState{Enabled: true, Route: route}
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join("..", "..", "configs")
			got, err := preflight(path, filepath.Join(base, "service-catalog.json"), filepath.Join(base, "sources.json"), filepath.Join(base, "community-catalog.json"), false)
			if err != nil || !got.OK || got.Migrated {
				t.Fatal(got, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("check modified config", err)
			}
		})
	}
}
