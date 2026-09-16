package onboarding

import (
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"reflect"
	"testing"
)

func fixture() (catalog.Catalog, ConfigView, autonomy.Policy, autonomy.Policy) {
	c := catalog.NFQWS2Starter()
	c.Services = append(c.Services, catalog.Service{ID: "extra-example", Name: "Extra", Category: "Мои сервисы", Domains: []string{"example.org"}, Strategy: []string{"auto"}, ProbeURL: "https://example.org/"})
	cfg := ConfigView{Services: map[string]State{}, AppliedServices: map[string]State{}, ServicePolicies: map[string]bool{}}
	old := autonomy.Default()
	next := autonomy.Default()
	next.Enabled = true
	next.SetupComplete = true
	next.AllLAN = true
	next.PreferredRoutes = []string{"nfqws2"}
	return c, cfg, old, next
}
func TestRepair2StarterAndExplicitExtrasAreOnePureSelection(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(map[bool]string{false: "base-only", true: "explicit-extra"}[extra], func(t *testing.T) {
			c, cfg, old, next := fixture()
			m := map[string]autonomy.Service{}
			r := map[string]autonomy.Runtime{}
			review := Starter(c, cfg, old, m)
			ids := []string{}
			if extra {
				ids = append(ids, "extra-example")
			}
			got, states, e := Enroll(c, cfg, old, next, m, r, review.SHA256, ids)
			if e != nil || len(got) != 6+len(ids) || len(states) != len(got) {
				t.Fatal(e, len(got))
			}
			if len(m) != 0 || len(r) != 0 {
				t.Fatal("mutated inputs")
			}
			for id, s := range got {
				want := "nfqws2"
				if id == "extra-example" {
					want = "auto"
				}
				if s.ExpectedRoute != want || !s.Enabled || !s.AllLAN || states[id].State != "pending" {
					t.Fatal(id, s)
				}
			}
		})
	}
}
func TestRepair2StarterRejectsStaleAndUnrequestedAuthority(t *testing.T) {
	for _, kind := range []string{"hash", "unknown-extra", "duplicate-extra", "base-as-extra", "second-setup", "scope", "modified-catalogue", "existing-managed"} {
		t.Run(kind, func(t *testing.T) {
			c, cfg, old, next := fixture()
			m := map[string]autonomy.Service{}
			r := map[string]autonomy.Runtime{}
			review := Starter(c, cfg, old, m)
			extra := []string{}
			switch kind {
			case "hash":
				review.SHA256 = "bad"
			case "unknown-extra":
				extra = []string{"not-present"}
			case "duplicate-extra":
				extra = []string{"extra-example", "extra-example"}
			case "base-as-extra":
				extra = []string{c.Services[0].ID}
			case "second-setup":
				old.SetupComplete = true
			case "scope":
				next.AllLAN = false
			case "modified-catalogue":
				c.Services[0].Domains = append(c.Services[0].Domains, "other.example")
			case "existing-managed":
				m["extra-example"] = autonomy.Service{ID: "extra-example", Enabled: true}
				extra = []string{"extra-example"}
			}
			if _, _, e := Enroll(c, cfg, old, next, m, r, review.SHA256, extra); e == nil {
				t.Fatal("unexpected admission")
			}
		})
	}
}
func TestRepair2StarterPreservesInstalledAndSuspendedServices(t *testing.T) {
	c, cfg, old, _ := fixture()
	id := c.Services[0].ID
	cfg.AppliedServices[id] = State{Enabled: true, Route: "sing-box:node-private"}
	before := cfg.AppliedServices[id]
	r := Starter(c, cfg, old, nil)
	if r.Skipped != 1 || len(r.Items) != 5 || !reflect.DeepEqual(before, cfg.AppliedServices[id]) {
		t.Fatal("existing route adopted")
	}
	old.SetupComplete = true
	if Starter(c, cfg, old, nil).Eligible {
		t.Fatal("second setup re-enrolls deleted services")
	}
}
