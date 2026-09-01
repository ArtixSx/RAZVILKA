package dataplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

type cloudflareRoundTrip func(*http.Request) (*http.Response, error)

func (roundTrip cloudflareRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func cloudflareProbeClient(trace string, serviceStatus int, serviceBody string) *http.Client {
	return &http.Client{Transport: cloudflareRoundTrip(func(request *http.Request) (*http.Response, error) {
		status, body, contentType := http.StatusOK, trace, "text/plain"
		if request.URL.Hostname() == "service.example" {
			status, body, contentType = serviceStatus, serviceBody, "text/plain"
		}
		return &http.Response{
			StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}},
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}
}

func TestCloudflareScanHTTPProbeBuildsExactEvidence(t *testing.T) {
	now := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)
	direct := cloudflareProbeClient("ip=9.9.9.9\ncolo=DME\nwarp=off\n", 200, "ok")
	bound := cloudflareProbeClient("ip=8.8.8.8\ncolo=AMS\nwarp=on\n", 200, "ok")
	probe := cloudflareScanHTTPProbe{
		directClient: direct, traceURL: "https://trace.example/cdn-cgi/trace",
		boundClient: func(source string) (*http.Client, func(), error) {
			if source != "172.16.0.2" {
				t.Fatal("unexpected source", source)
			}
			return bound, func() {}, nil
		},
		now: func() time.Time { now = now.Add(time.Millisecond); return now },
	}
	routeID := "cloudflare-wg:0123456789abcdef"
	facts, err := probe.observe(context.Background(), "172.16.0.2", routeID, catalog.Service{ID: "telegram", ProbeURL: "https://service.example/check"})
	if err != nil || facts.DirectEgressIP != "9.9.9.9" || facts.EgressIP != "8.8.8.8" || facts.Trace.WARP != "on" {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	service := facts.Service
	if service.Service != "telegram" || service.RoutePathID != routeID || service.ExpectedRoutePathID != routeID || service.ObservedRoutePathID != routeID ||
		service.EgressIP != facts.EgressIP || service.AssuranceLevel() != evidence.Service || service.Verdict != evidence.VerdictPass || service.Outcome != evidence.OutcomeServiceAccepted {
		t.Fatalf("service evidence=%+v", service)
	}
}

func TestCloudflareScanHTTPProbeKeepsBlockedServiceUnverified(t *testing.T) {
	probe := cloudflareScanHTTPProbe{
		directClient: cloudflareProbeClient("ip=9.9.9.9\ncolo=DME\nwarp=off\n", 200, "ok"),
		traceURL:     "https://trace.example/cdn-cgi/trace",
		boundClient: func(string) (*http.Client, func(), error) {
			return cloudflareProbeClient("ip=8.8.8.8\ncolo=AMS\nwarp=on\n", http.StatusUnavailableForLegalReasons, "blocked"), func() {}, nil
		},
	}
	facts, err := probe.observe(context.Background(), "172.16.0.2", "cloudflare-wg:route", catalog.Service{ID: "telegram", ProbeURL: "https://service.example/check"})
	if err != nil || facts.Service.AssuranceLevel() == evidence.Service || facts.Service.Verdict == evidence.VerdictPass || facts.Service.Outcome == evidence.OutcomeServiceAccepted {
		t.Fatalf("blocked service was promoted: %+v err=%v", facts.Service, err)
	}
}

func TestCloudflareScanHTTPProbeRejectsAmbiguousTraceAndUnsafeInput(t *testing.T) {
	badTrace := "ip=8.8.8.8\nip=1.1.1.1\ncolo=AMS\nwarp=on\n"
	probe := cloudflareScanHTTPProbe{
		directClient: cloudflareProbeClient(badTrace, 200, "ok"), traceURL: "https://trace.example/cdn-cgi/trace",
		boundClient: func(string) (*http.Client, func(), error) { return nil, nil, errors.New("must not run") },
	}
	if _, err := probe.observe(context.Background(), "172.16.0.2", "cloudflare-wg:route", catalog.Service{ID: "telegram", ProbeURL: "https://service.example/check"}); err == nil || strings.Contains(err.Error(), badTrace) {
		t.Fatal("ambiguous trace was accepted or leaked", err)
	}
	if _, err := probe.observe(context.Background(), "172.16.0.2", "direct", catalog.Service{ID: "Telegram", ProbeURL: "http://127.0.0.1/"}); err == nil {
		t.Fatal("unsafe scan identity was accepted")
	}
}
