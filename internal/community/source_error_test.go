package community

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFailedCIDRDoesNotImportPartialOrReplaceReviewedSource(t *testing.T) {
	m := budgetManager(t)
	m.registry.Entries[0].CIDRsURL = "https://raw.githubusercontent.com/example/data/main/ips.txt"
	fail := false
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := "good.example\n"
		if strings.HasSuffix(req.URL.Path, "/ips.txt") {
			if fail {
				return nil, context.DeadlineExceeded
			}
			body = "149.154.160.0/20\n"
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	first, err := m.Preview(context.Background(), "budget", nil, true)
	if err != nil || len(first.Service.CIDRs) != 1 {
		t.Fatalf("initial preview: %v", err)
	}
	fail = true
	p, err := m.Preview(context.Background(), "budget", nil, true)
	var sourceErr *SourceError
	if !errors.As(err, &sourceErr) || sourceErr.Part != "cidrs" || !errors.Is(err, context.DeadlineExceeded) || p.ImportGuard != "" {
		t.Fatalf("failed required source became importable or lost cause: %+v %v", p, err)
	}
	cached, err := m.Preview(context.Background(), "budget", nil, false)
	if err != nil || !cached.FromCache || cached.SourceSHA != first.SourceSHA || len(cached.Service.CIDRs) != 1 {
		t.Fatalf("failed refresh changed reviewed source: %+v %v", cached, err)
	}
}
