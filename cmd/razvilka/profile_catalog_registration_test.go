package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestStartupWireGuardCatalogIsTheRegisteredRuntimeOwnerAndReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dataplane")
	manager, err := newDataplaneManager(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := manager.WireGuardProfileCatalog()
	if err != nil {
		t.Fatal("actual startup omitted catalog", err)
	}
	adapter, ok := manager.Adapters["wireguard"].(*dataplane.WARPWireGuardAdapter)
	if !ok || adapter.Profiles != catalog {
		t.Fatal("catalog is a second owner")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("startup construction created private state", err)
	}
	profiles, err := catalog.List(context.Background())
	if err != nil || len(profiles) != 0 {
		t.Fatal("cold registered catalog", profiles, err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("read initialized profile state", err)
	}
}
