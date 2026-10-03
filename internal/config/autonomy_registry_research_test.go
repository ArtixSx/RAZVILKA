package config

import (
	"github.com/ArtixSx/razvilka/internal/routekind"
	"path/filepath"
	"reflect"
	"testing"
)

// Real Store/persistence test, not the isolated double used by the offline
// review harness. Must pass in the full project before integration is accepted.
func TestResearchAllPreferredRoutesPersistReloadAndUndo(t *testing.T) {
	for _, route := range routekind.PreferredIDs() {
		t.Run(route, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			store, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.SetSafeMode(false); err != nil {
				t.Fatal(err)
			}
			before := store.Get()
			undo, err := store.ApplyAutonomyRouteWithRollback("research-service", route, []string{"192.168.1.50"}, before.Revision)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			got := reloaded.Get().AppliedServices["research-service"]
			if got.Route != route || !reflect.DeepEqual(got.Sources, []string{"192.168.1.50/32"}) {
				t.Fatal(got)
			}
			if err = undo(); err != nil || !reflect.DeepEqual(store.Get(), before) {
				t.Fatal("undo", err)
			}
			if err = undo(); err != nil {
				t.Fatal("idempotence", err)
			}
		})
	}
}
