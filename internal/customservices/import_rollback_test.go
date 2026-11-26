package customservices

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestImportCatalogRollbackOwnsNestedProbeSnapshots(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	input := []catalog.Service{{ID: "custom-probe", Name: "Probe", Domains: []string{"probe.example"}, Probes: []catalog.Probe{{ID: "web", Label: "Web", Required: true, URL: "https://probe.example/", Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, JSON: true, JSONFields: []string{"ok"}}}}}}
	undo, err := m.MergeWithRollback(input, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Probes[0].Expect.StatusCodes[0] = 503
	public := m.List()
	public[0].Probes[0].Expect.JSONFields[0] = "changed"
	if got := m.List()[0].Probes[0].Expect; got.StatusCodes[0] != 200 || got.JSONFields[0] != "ok" {
		t.Fatal("caller modified stored probe through alias")
	}
	if err := undo(); err != nil || len(m.List()) != 0 {
		t.Fatal("caller modified rollback snapshot")
	}
}

func TestImportCatalogGuardedRollback(t *testing.T) {
	for _, change := range []string{"none", "edit", "write-failure"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custom.json")
			m, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Create(catalog.Service{Name: "Before", Domains: []string{"before.example"}}, nil); err != nil {
				t.Fatal(err)
			}
			before := m.List()
			undo, err := m.MergeWithRollback([]catalog.Service{{ID: "custom-import", Name: "Imported", Domains: []string{"import.example"}}}, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			if change == "edit" {
				if _, err := m.Create(catalog.Service{Name: "Later", Domains: []string{"later.example"}}, nil); err != nil {
					t.Fatal(err)
				}
			}
			if change == "write-failure" {
				m.path = filepath.Join(path, "impossible.json")
			}
			current := m.List()
			err = undo()
			if change != "none" {
				if err == nil || !reflect.DeepEqual(current, m.List()) {
					t.Fatal("undo overwrote concurrent catalog or lost state after I/O failure")
				}
				if change == "edit" {
					return
				}
				m.path = path
				if err := undo(); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, m.List()) {
				t.Fatal("catalog not restored")
			}
			if err := undo(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := Load(path)
			if err != nil || !reflect.DeepEqual(before, reloaded.List()) {
				t.Fatal("catalog undo not persisted")
			}
		})
	}
}
