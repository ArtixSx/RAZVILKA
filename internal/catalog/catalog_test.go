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
