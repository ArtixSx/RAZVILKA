package main

import (
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestColdMainRuntimeConstructorKeepsTypedInactivityOwnersWithoutConfigs(t *testing.T) {
	root := t.TempDir()
	manager, err := newDataplaneManager(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"usque", "sing-box", "xray"} {
		adapter, ok := manager.Adapters[id].(*dataplane.ProxyTunnelAdapter)
		if !ok || adapter.Configs != nil {
			t.Fatal("cold main changed config bootstrap", id)
		}
		if _, ok := any(adapter).(dataplane.RuntimeInactivityObserver); !ok {
			t.Fatal("cold main lost typed owner observer", id)
		}
	}
	for _, id := range []string{"wireguard", "warp-wg", "amneziawg", "nfqws2"} {
		if _, ok := manager.Adapters[id].(dataplane.RuntimeInactivityObserver); !ok {
			t.Fatal("main owner observer unavailable", id)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("cold constructor wrote runtime/catalog state", err)
	}
	// Availability is not a proof: the actual Manager observer still requires
	// complete fresh platform/kernel/process inventories from every owner.
}
