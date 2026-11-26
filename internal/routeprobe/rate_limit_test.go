package routeprobe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

func TestHTTP429RetainsOnlyBoundedRetryHint(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader("limited")), Request: r}, nil
	})}
	r := probeHTTP(context.Background(), client, catalog.Service{ID: "speedtest", ProbeURL: "https://speed.example/"}, "nfqws2", "test-model", true)
	r.NormalizeEvidence()
	if calls != 1 || r.RetryAfterSeconds != 120 || r.Verdict != evidence.VerdictPartial || r.ErrorCode != "http-429" || r.Status == "pass" {
		t.Fatalf("rate limit promoted or retried: %+v calls=%d", r, calls)
	}
}
