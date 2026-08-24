package catalog

import "testing"

func TestValidateCatalog(t *testing.T) {
	good := Catalog{Services: []Service{{ID: "x", Name: "X", Category: "AI", Domains: []string{"example.com"}, Strategy: []string{"direct"}, ProbeURL: "https://example.com/"}}}
	if err := Validate(good); err != nil {
		t.Fatal(err)
	}
	bad := Catalog{Services: []Service{{ID: "x", Name: "X", Category: "AI", Domains: []string{"com"}, Strategy: []string{"direct"}}}}
	if err := Validate(bad); err == nil {
		t.Fatal("expected invalid domain")
	}
}

func TestValidateServiceProbeScenarios(t *testing.T) {
	service := Service{ID: "telegram", Name: "Telegram", Category: "Messaging", Domains: []string{"telegram.org"}, Strategy: []string{"direct"}, Probes: []Probe{{ID: "web", Label: "Web", URL: "https://web.telegram.org/", Required: true}}}
	if err := Validate(Catalog{Services: []Service{service}}); err != nil {
		t.Fatal(err)
	}
	service.Probes = append(service.Probes, Probe{ID: "web", Label: "Duplicate", URL: "https://telegram.org/"})
	if err := Validate(Catalog{Services: []Service{service}}); err == nil {
		t.Fatal("duplicate probe id must fail validation")
	}
}
