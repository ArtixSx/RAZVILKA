package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLegacyLocationsIsolateCandidateConfig(t *testing.T) {
	root := t.TempDir()
	registry, err := cloudflareLegacySources(filepath.Join(root, "config.json"), "/opt/var/lib/razvilka/warp")
	if err != nil {
		t.Fatal(err)
	}
	if locations := registry.Locations(); len(locations) != 1 || locations[0].ID != "warp-profile" {
		t.Fatalf("candidate inherited production sources: %+v", locations)
	}
	registry, err = cloudflareLegacySources(filepath.Join(root, "config.json"), filepath.Join(root, "warp-state"))
	if err != nil || len(registry.Locations()) != 2 {
		t.Fatal("explicit isolated WARP source missing")
	}
	files, _ := os.ReadDir(root)
	if len(files) != 0 {
		t.Fatal("source inventory touched filesystem")
	}
}

func TestStandardLinuxLegacyLocations(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux standard layout")
	}
	registry, err := cloudflareLegacySources("/opt/etc/razvilka/config.json", "/opt/var/lib/razvilka/warp")
	if err != nil || len(registry.Locations()) != 6 {
		t.Fatalf("standard sources: %v", err)
	}
}
