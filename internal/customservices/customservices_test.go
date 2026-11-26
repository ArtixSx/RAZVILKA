package customservices

import (
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestCreatePersistsAndNormalizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-services.json")
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := m.Create(catalog.Service{
		Name: "My Video", Domains: []string{" Example.COM. ", "example.com"},
		CIDRs: []string{"203.0.113.0/24"},
	}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "custom-my-video" || len(created.Domains) != 1 || created.Domains[0] != "example.com" {
		t.Fatalf("unexpected normalized service: %#v", created)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].ID != created.ID {
		t.Fatalf("unexpected reload: %#v", got)
	}
}

func TestRejectsCollisionAndInvalidCIDR(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "custom-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(catalog.Service{Name: "YouTube", Domains: []string{"youtube.com"}}, map[string]bool{"custom-youtube": true}); err == nil {
		t.Fatal("expected id collision")
	}
	if _, err := m.Create(catalog.Service{Name: "Broken", CIDRs: []string{"not-a-cidr"}}, map[string]bool{}); err == nil {
		t.Fatal("expected invalid CIDR")
	}
}

func TestUpdateAndDelete(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "custom-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := m.Create(catalog.Service{Name: "One", Domains: []string{"one.example"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := m.Update(created.ID, catalog.Service{Name: "Two", Domains: []string{"two.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Name != "Two" {
		t.Fatalf("unexpected update: %#v", updated)
	}
	if err := m.Delete(created.ID); err != nil {
		t.Fatal(err)
	}
	if len(m.List()) != 0 {
		t.Fatal("service was not deleted")
	}
}
