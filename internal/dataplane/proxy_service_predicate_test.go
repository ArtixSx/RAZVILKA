package dataplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func proxyPredicateFixtureService() catalog.Service {
	service := nodeRouterFixtureCatalog("https://example.com/health")
	service.CIDRs = []string{"198.51.100.0/24"}
	service.SourceRefs = []string{"fixture-source"}
	service.Provenance = &catalog.Provenance{Provider: "fixture", EntryID: "entry"}
	service.Probes = []catalog.Probe{{ID: "catalog-check", Label: "Catalog check", URL: service.ProbeURL, Required: true,
		Expect: catalog.ProbeExpectation{StatusCodes: []int{200}, RedirectPolicy: "none", RedirectHosts: []string{"example.com"},
			ContentTypes: []string{"application/json"}, JSON: true, JSONFields: []string{"result.accepted"}, BodyContains: []string{`"accepted":true`}}}}
	return service
}

func proxyPredicateFixtureResponse(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestProxyServicePredicateUsesCompleteSelectedCatalogSemantics(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body, code string
		status                        int
		change                        func(*catalog.Service)
	}{
		{name: "accepted", status: 200, contentType: "application/json", body: `{"result":{"accepted":true}}`},
		{name: "login", status: 200, contentType: "text/html", body: `<html>Sign in</html>`, code: "body-predicate-mismatch", change: func(s *catalog.Service) {
			s.Probes[0].Expect = catalog.ProbeExpectation{BodyContains: []string{"service-ready"}}
		}},
		{name: "soft-block", status: 200, contentType: "text/html", body: `<html>Temporarily unavailable</html>`, code: "body-predicate-mismatch", change: func(s *catalog.Service) {
			s.Probes[0].Expect = catalog.ProbeExpectation{BodyContains: []string{"service-ready"}}
		}},
		{name: "content-type", status: 200, contentType: "text/plain", body: `{"result":{"accepted":true}}`, code: "content-type-mismatch"},
		{name: "invalid-JSON", status: 200, contentType: "application/json", body: `<html>not JSON</html>`, code: "invalid-json"},
		{name: "JSON-schema", status: 200, contentType: "application/json", body: `{"accepted":true}`, code: "json-schema-mismatch"},
		{name: "JSON-truncated", status: 200, contentType: "application/json", body: `{"result":{"accepted":true},"padding":"` + strings.Repeat("x", probecheck.MaxBodyBytes) + `"}`, code: "json-sample-incomplete"},
		{name: "known-block-page", status: 200, contentType: "text/html", body: `<html>Доступ к информационному ресурсу ограничен</html>`, code: "known-block-page", change: func(s *catalog.Service) { s.Probes[0].Expect = catalog.ProbeExpectation{} }},
		{name: "status", status: 204, contentType: "application/json", body: "", code: "unexpected-http-status"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := proxyPredicateFixtureService()
			if test.change != nil {
				test.change(&service)
			}
			predicate, err := newProxyServicePredicate(service)
			if err != nil {
				t.Fatal(err)
			}
			body, err := predicate.evaluateResponse(context.Background(), proxyPredicateFixtureResponse(test.status, test.contentType, test.body))
			defer clear(body)
			if test.code == "" {
				if err != nil || string(body) != test.body {
					t.Fatal("full catalog positive was rejected", err)
				}
				return
			}
			var semantic *serviceResponseError
			if !errors.As(err, &semantic) || semantic.code != test.code {
				t.Fatalf("semantic expectation weakened: err=%v want=%s", err, test.code)
			}
		})
	}
}

func TestProxyServicePredicateFreezesAllCallerOwnedData(t *testing.T) {
	service := proxyPredicateFixtureService()
	predicate, err := newProxyServicePredicate(service)
	if err != nil {
		t.Fatal(err)
	}
	id, rawURL, hash := service.ID, service.ProbeURL, predicate.digest()
	service.ID, service.ProbeURL, service.Name = "changed", "https://changed.example/", "Changed"
	service.Domains[0], service.CIDRs[0], service.Strategy[0], service.SourceRefs[0] = "changed.example", "10.0.0.0/8", "direct", "changed"
	service.Provenance.Provider = "changed"
	service.Probes[0].ID, service.Probes[0].URL = "changed", "https://changed.example/"
	service.Probes[0].Expect.StatusCodes[0] = 204
	service.Probes[0].Expect.RedirectHosts[0] = "changed.example"
	service.Probes[0].Expect.ContentTypes[0] = "text/html"
	service.Probes[0].Expect.JSONFields[0] = "changed"
	service.Probes[0].Expect.BodyContains[0] = "changed"
	if !predicate.matches(id, rawURL) || predicate.digest() != hash || predicate.probe.ID != "catalog-check" {
		t.Fatal("caller mutation changed frozen predicate")
	}
	body, err := predicate.evaluateResponse(context.Background(), proxyPredicateFixtureResponse(200, "application/json", `{"result":{"accepted":true}}`))
	defer clear(body)
	if err != nil {
		t.Fatal("original frozen expectations changed", err)
	}
}

func TestProxyServicePredicateBoundsAndSelectionRejectBeforeCopy(t *testing.T) {
	for _, mode := range []string{"missing-id", "missing-URL", "unselected", "ambiguous", "too-many-probes", "too-many-fields", "string-limit", "aggregate-limit", "JSON-fields-without-JSON", "empty-marker", "invalid-UTF8"} {
		t.Run(mode, func(t *testing.T) {
			service := proxyPredicateFixtureService()
			switch mode {
			case "missing-id":
				service.ID = ""
			case "missing-URL":
				service.ProbeURL = ""
			case "unselected":
				service.Probes[0].URL = "https://example.com/another"
			case "ambiguous":
				other := service.Probes[0]
				other.ID = "another-check"
				service.Probes = append(service.Probes, other)
			case "too-many-probes":
				service.Probes = make([]catalog.Probe, proxyServicePredicateMaxProbes+1)
			case "too-many-fields":
				service.Probes[0].Expect.JSONFields = make([]string, proxyServicePredicateMaxItems+1)
			case "string-limit":
				service.Description = strings.Repeat("x", proxyServicePredicateMaxString+1)
			case "aggregate-limit":
				service.Probes[0].Expect.BodyContains = make([]string, 5)
				for i := range service.Probes[0].Expect.BodyContains {
					service.Probes[0].Expect.BodyContains[i] = strings.Repeat("x", proxyServicePredicateMaxString)
				}
			case "JSON-fields-without-JSON":
				service.Probes[0].Expect.JSON = false
			case "empty-marker":
				service.Probes[0].Expect.BodyContains[0] = ""
			case "invalid-UTF8":
				service.Name = string([]byte{0xff})
			}
			if predicate, err := newProxyServicePredicate(service); !errors.Is(err, errProxyServicePredicate) || predicate != nil {
				t.Fatal("invalid catalog predicate accepted", predicate, err)
			}
		})
	}
}

func TestProxyServicePredicateLegacyDefaultKeepsYouTube204(t *testing.T) {
	service := nodeRouterFixtureCatalog("https://www.youtube.com/generate_204")
	predicate, err := newProxyServicePredicate(service)
	if err != nil || predicate.probe.ID != "primary" {
		t.Fatal(err)
	}
	for _, status := range []int{200, 204} {
		body, err := predicate.evaluateResponse(context.Background(), proxyPredicateFixtureResponse(status, "text/plain", ""))
		clear(body)
		if (err == nil) != (status == 204) {
			t.Fatal("legacy catalog default weakened YouTube semantics", status, err)
		}
	}
}

func TestProxyServicePredicateExactLimitJSONIsComplete(t *testing.T) {
	predicate, err := newProxyServicePredicate(proxyPredicateFixtureService())
	if err != nil {
		t.Fatal(err)
	}
	prefix, suffix := `{"result":{"accepted":true},"padding":"`, `"}`
	exact := prefix + strings.Repeat("x", probecheck.MaxBodyBytes-len(prefix)-len(suffix)) + suffix
	for _, body := range []string{exact, exact[:len(exact)-2] + "x" + suffix} {
		sample, err := predicate.evaluateResponse(context.Background(), proxyPredicateFixtureResponse(200, "application/json", body))
		clear(sample)
		if (err == nil) != (len(body) == probecheck.MaxBodyBytes) {
			t.Fatal("exact-limit completion/truncation was not honest", len(body), err)
		}
	}
}
