package catalog

import (
	"net/url"
	"reflect"
	"slices"
	"testing"
)

func TestWebDefaultsPreserveExistingServiceDefinition(t *testing.T) {
	stock := NFQWS2Starter()
	custom := Service{
		ID: "telegram-web", Name: "Local Telegram", Category: "Custom",
		Domains: []string{"local.example"}, Strategy: []string{"direct"},
	}
	input := Catalog{Services: append(slices.Clone(stock.Services), custom)}
	merged := WithWebDefaults(input)
	if err := Validate(merged); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged.Services[:len(input.Services)], input.Services) || len(merged.Services) != len(stock.Services)+3 {
		t.Fatal("adding built-in web entries replaced a local or stock definition")
	}
	for _, service := range merged.Services[:len(stock.Services)] {
		if !IsNFQWS2Starter(service) {
			t.Fatal("stock scope changed", service.ID)
		}
	}
	defaults := WithWebDefaults(Catalog{})
	for _, service := range defaults.Services {
		probe, err := url.Parse(service.ProbeURL)
		if err != nil || len(service.Domains) != 1 || probe.Hostname() != service.Domains[0] ||
			len(service.CIDRs) != 0 || len(service.Probes) != 1 || len(service.Probes[0].Expect.BodyContains) == 0 ||
			!service.Probes[0].Required || IsNFQWS2Starter(service) {
			t.Fatalf("web entry escaped its reviewed scope: %+v", service)
		}
	}
	defaults.Services[0].Domains[0] = "changed.example"
	if WithWebDefaults(Catalog{}).Services[0].Domains[0] == "changed.example" {
		t.Fatal("mutable shared default web scope")
	}
}
