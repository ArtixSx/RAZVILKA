package probecheck

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestStrictNegativeFixtures(t *testing.T) {
	service := catalog.Service{ProbeURL: "https://service.example/api", Domains: []string{"service.example"}}
	jsonProbe := catalog.Probe{Expect: catalog.ProbeExpectation{JSON: true, JSONFields: []string{"result.ok"}, ContentTypes: []string{"application/json"}}}
	cases := []struct {
		name        string
		probe       catalog.Probe
		observation Observation
		want        evidence.Verdict
	}{
		{"no-content", catalog.Probe{}, Observation{HTTPStatus: 204}, evidence.VerdictPass},
		{"302-isp-portal", catalog.Probe{}, Observation{HTTPStatus: 302, RedirectChain: []string{"https://portal.isp.example/login?secret=hidden"}}, evidence.VerdictBlocked},
		{"intermediate-portal", catalog.Probe{}, Observation{HTTPStatus: 200, FinalURL: "https://service.example/", RedirectChain: []string{"https://portal.isp.example/", "https://service.example/"}}, evidence.VerdictBlocked},
		{"owned-redirect", catalog.Probe{}, Observation{HTTPStatus: 200, RedirectChain: []string{"https://web.service.example/"}}, evidence.VerdictPass},
		{"suffix-trick", catalog.Probe{}, Observation{HTTPStatus: 200, RedirectChain: []string{"https://service.example.attacker.example/"}}, evidence.VerdictBlocked},
		{"tls-downgrade", catalog.Probe{}, Observation{HTTPStatus: 200, RedirectChain: []string{"http://service.example/"}}, evidence.VerdictBlocked},
		{"unresolved-302", catalog.Probe{}, Observation{HTTPStatus: 302}, evidence.VerdictInconclusive},
		{"403", catalog.Probe{}, Observation{HTTPStatus: 403}, evidence.VerdictBlocked},
		{"451", catalog.Probe{}, Observation{HTTPStatus: 451}, evidence.VerdictBlocked},
		{"429", catalog.Probe{}, Observation{HTTPStatus: 429}, evidence.VerdictPartial},
		{"200-block-page", catalog.Probe{}, Observation{HTTPStatus: 200, ContentType: "text/html", Body: []byte("<html>Доступ к запрашиваемому ресурсу ограничен</html>")}, evidence.VerdictBlocked},
		{"fake-json", jsonProbe, Observation{HTTPStatus: 200, ContentType: "application/json", Body: []byte("<html>not JSON</html>")}, evidence.VerdictError},
		{"wrong-json-schema", jsonProbe, Observation{HTTPStatus: 200, ContentType: "application/json", Body: []byte(`{"portal":true}`)}, evidence.VerdictError},
		{"valid-json", jsonProbe, Observation{HTTPStatus: 200, ContentType: "application/json; charset=utf-8", Body: []byte(`{"result":{"ok":true}}`)}, evidence.VerdictPass},
		{"truncated-json", jsonProbe, Observation{HTTPStatus: 200, ContentType: "application/json", Body: []byte(`{"result":`), BodyTruncated: true}, evidence.VerdictInconclusive},
		{"wrong-content-type", jsonProbe, Observation{HTTPStatus: 200, ContentType: "text/html", Body: []byte(`{"result":{"ok":true}}`)}, evidence.VerdictError},
		{"direct-leak", catalog.Probe{}, Observation{HTTPStatus: 200, ExpectedRoutePathID: "isolated:warp-wg", ObservedRoutePathID: "isolated:direct"}, evidence.VerdictMisrouted},
		{"negative-control-leak", catalog.Probe{}, Observation{HTTPStatus: 200, NegativeControlMatched: true}, evidence.VerdictMisrouted},
		{"wrong-204-status", catalog.Probe{Expect: catalog.ProbeExpectation{StatusCodes: []int{204}}}, Observation{HTTPStatus: 200}, evidence.VerdictInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.observation.RequestedURL = service.ProbeURL
			got := Evaluate(service, tc.probe, tc.observation)
			if got.Verdict != tc.want {
				t.Fatalf("got %+v, want %s", got, tc.want)
			}
			if tc.want != evidence.VerdictPass && (got.Status == "pass" || got.Outcome == evidence.OutcomeServiceAccepted) {
				t.Fatalf("negative fixture became service success: %+v", got)
			}
			if strings.Contains(got.Detail, "secret=hidden") {
				t.Fatal("query secret leaked into diagnostics")
			}
		})
	}
}

func TestClientDoesNotVisitExternalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://portal.invalid/login", http.StatusFound)
	}))
	defer server.Close()
	service := catalog.Service{ProbeURL: server.URL}
	chain := []string{}
	response, err := RecordingClient(server.Client(), service, &chain).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 302 || len(chain) != 1 {
		t.Fatalf("redirect was not stopped: status=%d chain=%v", response.StatusCode, chain)
	}
}

func TestClientRetainsExistingRedirectGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	called := false
	client.CheckRedirect = func(*http.Request, []*http.Request) error { called = true; return http.ErrUseLastResponse }
	chain := []string{}
	response, err := RecordingClient(client, catalog.Service{ProbeURL: server.URL}, &chain).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if !called || response.StatusCode != 302 {
		t.Fatal("existing guard was lost")
	}
}

func TestLegacyYouTubeProbeKeepsStrict204Predicate(t *testing.T) {
	service := catalog.Service{ProbeURL: "https://www.youtube.com/generate_204", Probes: []catalog.Probe{{URL: "https://www.youtube.com/generate_204"}}}
	probe := ServiceProbe(service)
	if len(probe.Expect.StatusCodes) != 1 || probe.Expect.StatusCodes[0] != 204 || probe.Expect.RedirectPolicy != "none" {
		t.Fatalf("legacy predicate lost: %+v", probe)
	}
}
