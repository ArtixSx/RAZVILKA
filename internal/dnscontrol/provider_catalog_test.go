package dnscontrol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// Reference from 38a9833c: build and transform all providers before lookup.
func providerCatalogOriginalFor(doc document) []Provider {
	providers := buildProviderCatalog()
	for index := range providers {
		switch providers[index].ID {
		case "nextdns":
			if validNextDNSProfileID(doc.NextDNSProfileID) {
				providers[index].Configured = true
				providers[index].DoH = "https://dns.nextdns.io/" + doc.NextDNSProfileID
				providers[index].DoT = doc.NextDNSProfileID + ".dns.nextdns.io:853"
			}
		case "custom":
			if doc.CustomProvider != nil {
				providers[index] = withProviderMetadata(cloneProvider(*doc.CustomProvider))
			}
		}
		providers[index] = withTypedEndpoints(providers[index])
	}
	return providers
}

func providerCatalogOriginalLookup(id string, doc document) (Provider, bool) {
	for _, provider := range providerCatalogOriginalFor(doc) {
		if provider.ID == id {
			return provider, true
		}
	}
	return Provider{}, false
}

func TestProviderCatalogPublicParity(t *testing.T) {
	if !reflect.DeepEqual(Providers(), buildProviderCatalog()) {
		t.Fatal("public catalog differs")
	}
}

func providerCatalogDocumentJSON(t *testing.T, doc document) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func providerCatalogTestDocuments() []document {
	custom := Provider{ID: "custom", Name: "caller", Scope: "custom", Configured: true,
		Servers: []string{"192.0.2.8:53"}, DoH: "https://resolver.invalid/dns-query", DoT: "resolver.invalid:853",
		ServiceHints: []string{"service"}, Filters: []string{"filter"}, Warnings: []string{"warning"}, RecommendedFor: []string{"purpose"},
		Endpoints: []DNSEndpoint{{Transport: "doh", URL: "https://resolver.invalid/dns-query", Scope: "custom", BootstrapIPs: []string{"192.0.2.9"}}},
	}
	docs := []document{{}, {NextDNSProfileID: "abcdef"}, {NextDNSProfileID: "123456"}, {NextDNSProfileID: "ABCDEF"}, {NextDNSProfileID: "invalid"}, {CustomProvider: &custom}}
	for _, id := range []string{"", "cloudflare", "malw", "unknown"} {
		p := cloneProvider(custom)
		p.ID = id
		docs = append(docs, document{NextDNSProfileID: "a1b2c3", CustomProvider: &p})
	}
	return docs
}

func TestProviderCatalogLookupParity(t *testing.T) {
	ids := []string{"", "unknown", " CLOUDFlare ", "CLOUDFLARE"}
	for _, provider := range buildProviderCatalog() {
		ids = append(ids, provider.ID)
	}
	for n, doc := range providerCatalogTestDocuments() {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			before := providerCatalogDocumentJSON(t, doc)
			if !reflect.DeepEqual(providersFor(doc), providerCatalogOriginalFor(doc)) {
				t.Fatal("complete document catalog differs")
			}
			for _, id := range ids {
				got, ok := providerByIDFor(id, doc)
				want, wantOK := providerCatalogOriginalLookup(id, doc)
				if ok != wantOK || !reflect.DeepEqual(got, want) {
					t.Fatalf("lookup %q differs: got=%+v/%t want=%+v/%t", id, got, ok, want, wantOK)
				}
			}
			if providerCatalogDocumentJSON(t, doc) != before {
				t.Fatal("document mutated")
			}
		})
	}
}

func corruptProviderCatalogValue(p *Provider) {
	p.Name = "changed"
	p.ID = "changed"
	p.Scope = "changed"
	p.Configured = !p.Configured
	for _, field := range []*[]string{&p.ServiceHints, &p.Servers, &p.Filters, &p.Warnings, &p.RecommendedFor} {
		for i := range *field {
			(*field)[i] = "changed"
		}
		*field = append(*field, "changed")
	}
	for i := range p.Endpoints {
		p.Endpoints[i].Address = "changed"
		for j := range p.Endpoints[i].BootstrapIPs {
			p.Endpoints[i].BootstrapIPs[j] = "changed"
		}
		p.Endpoints[i].BootstrapIPs = append(p.Endpoints[i].BootstrapIPs, "changed")
	}
	p.Endpoints = append(p.Endpoints, DNSEndpoint{Address: "changed"})
}

func TestProviderCatalogMutationIsolation(t *testing.T) {
	want := buildProviderCatalog()
	for iteration := 0; iteration < 2; iteration++ {
		public := Providers()
		for i := range public {
			corruptProviderCatalogValue(&public[i])
		}
		for _, doc := range providerCatalogTestDocuments() {
			before := providerCatalogDocumentJSON(t, doc)
			all := providersFor(doc)
			for i := range all {
				corruptProviderCatalogValue(&all[i])
			}
			for _, p := range want {
				one, ok := providerByIDFor(p.ID, doc)
				if ok {
					corruptProviderCatalogValue(&one)
				}
			}
			if providerCatalogDocumentJSON(t, doc) != before {
				t.Fatal("caller modified document via returned provider")
			}
		}
		if !reflect.DeepEqual(providerCatalog, want) || !reflect.DeepEqual(Providers(), want) {
			t.Fatal("caller mutated private templates")
		}
	}
}

func TestProviderCatalogConcurrentIsolation(t *testing.T) {
	want := buildProviderCatalog()
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 30; iteration++ {
				for _, p := range Providers() {
					got, ok := providerByIDFor(p.ID, document{})
					if !ok || !reflect.DeepEqual(got, p) {
						t.Error("concurrent lookup changed")
						return
					}
					corruptProviderCatalogValue(&got)
					corruptProviderCatalogValue(&p)
				}
			}
		}()
	}
	workers.Wait()
	if !reflect.DeepEqual(providerCatalog, want) {
		t.Fatal("concurrent caller mutated private templates")
	}
}

func TestProviderCatalogFreshDocumentIdentity(t *testing.T) {
	first := document{NextDNSProfileID: "abcdef"}
	before, err := profileDefinitionIdentity(first, "nextdns", false)
	if err != nil {
		t.Fatal(err)
	}
	first.NextDNSProfileID = "123456"
	after, err := profileDefinitionIdentity(first, "nextdns", false)
	if err != nil || before == after {
		t.Fatal("nextdns document change hidden")
	}
	custom := Provider{ID: "custom", Name: "original", DoH: "https://first.invalid/dns-query", Configured: true, Scope: "custom"}
	doc := document{CustomProvider: &custom}
	before, err = profileDefinitionIdentity(doc, "custom", false)
	if err != nil {
		t.Fatal(err)
	}
	custom.DoH = "https://second.invalid/dns-query"
	after, err = profileDefinitionIdentity(doc, "custom", false)
	if err != nil || before == after {
		t.Fatal("custom document change hidden")
	}
	if _, err = profileDefinitionIdentity(doc, "unknown", false); err != ErrScopedDNS {
		t.Fatal("unknown identity error changed")
	}
	if _, err = profileDefinitionIdentity(doc, "custom", true); err != ErrScopedDNS {
		t.Fatal("scoped custom refusal changed")
	}
}

var providerCatalogBenchmarkSink Provider

func BenchmarkProviderCatalogLookup(b *testing.B) {
	cases := []struct {
		name, id string
		doc      document
	}{
		{"known", "cloudflare", document{}},
		{"nextdns-changing", "nextdns", document{NextDNSProfileID: "abcdef"}},
		{"custom-changing", "custom", document{CustomProvider: &Provider{ID: "custom", Name: "custom", DoH: "https://first.invalid/dns-query", Configured: true}}},
		{"unknown", "unknown", document{}},
	}
	for _, c := range cases {
		for _, variant := range []string{"original", "candidate"} {
			b.Run(c.name+"/"+variant, func(b *testing.B) {
				doc := cloneDocument(c.doc)
				lookup := providerCatalogOriginalLookup
				if variant == "candidate" {
					lookup = providerByIDFor
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if c.name == "nextdns-changing" {
						if i%2 == 0 {
							doc.NextDNSProfileID = "abcdef"
						} else {
							doc.NextDNSProfileID = "123456"
						}
					}
					if c.name == "custom-changing" {
						if i%2 == 0 {
							doc.CustomProvider.DoH = "https://first.invalid/dns-query"
						} else {
							doc.CustomProvider.DoH = "https://second.invalid/dns-query"
						}
					}
					providerCatalogBenchmarkSink, _ = lookup(c.id, doc)
				}
			})
		}
	}
}
