package community

import (
	"strings"
	"testing"
)

func TestBrowseDefinitionsBoundsAndPublicProjection(t *testing.T) {
	m := &Manager{registry: Registry{Schema: 1, Entries: []Entry{{ID: "public", Name: "Public", Category: "Test", Description: "Display", DomainsURL: "private-source", Access: Access{Status: "blocked"}}}}}
	if _, ok := (&Manager{}).BrowseDefinitions(); ok {
		t.Fatal("uninitialized manager claimed empty catalog")
	}
	rows, ok := m.BrowseDefinitions()
	if !ok || len(rows) != 1 || rows[0] != (BrowseDefinition{"public", "Public", "Test", "Display"}) {
		t.Fatal("display projection unavailable")
	}
	rows[0].Name = "changed"
	if m.registry.Entries[0].Name != "Public" {
		t.Fatal("projection aliases manager storage")
	}
	for _, change := range []string{"count", "string", "bytes"} {
		x := &Manager{registry: m.registry}
		switch change {
		case "count":
			x.geo = make([]Entry, maxGeoServices+1)
		case "string":
			x.geo = []Entry{{ID: "extra", Name: strings.Repeat("n", 513)}}
		case "bytes":
			x.geo = make([]Entry, 100)
			for i := range x.geo {
				x.geo[i] = Entry{ID: "extra", Name: "Name", Description: strings.Repeat("d", 4096)}
			}
		}
		if _, ok := x.BrowseDefinitions(); ok {
			t.Fatal("unbounded projection accepted", change)
		}
	}
}
