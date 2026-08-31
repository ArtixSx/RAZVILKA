package community

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func budgetManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Registry{Schema: 1, Entries: []Entry{{ID: "budget", Name: "Budget", Category: "Test", Provider: "Test", SourcePage: "https://github.com/v2fly/domain-list-community", DomainsURL: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/root", Access: Access{Region: "RU", Status: "catalog", Note: "Test"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCommunityRejectsPartialAndHTMLResponsesPreservingCachedPreview(t *testing.T) {
	m := budgetManager(t)
	body, contentType := "good.example\n", "text/plain"
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) > 25*time.Second {
			t.Fatal("preview has no bounded deadline")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	first, err := m.Preview(context.Background(), "budget", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<html>\nplausible.example\n", "<!doctype html>\nplausible.example\n", "partial.example\n" + strings.Repeat("x", 1<<20)} {
		body = bad
		if _, err := m.Preview(context.Background(), "budget", nil, true); err == nil {
			t.Fatal("bad response accepted")
		}
		cached, err := m.Preview(context.Background(), "budget", nil, false)
		if err != nil || !cached.FromCache || cached.SourceSHA != first.SourceSHA {
			t.Fatal("failed refresh replaced cached preview")
		}
	}
	body, contentType = "plausible.example\n", "text/html"
	if _, err := m.Preview(context.Background(), "budget", nil, true); err == nil {
		t.Fatal("HTML media type accepted")
	}
}

func TestCommunityIncludeTreeHasAggregateByteAndEntryLimits(t *testing.T) {
	for _, mode := range []string{"bytes", "entries"} {
		t.Run(mode, func(t *testing.T) {
			m := budgetManager(t)
			calls := 0
			m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				var body strings.Builder
				if strings.HasSuffix(req.URL.Path, "/root") {
					if mode == "entries" {
						for n := 0; n < 2001; n++ {
							fmt.Fprintf(&body, "item%d.example\n", n)
						}
					}
					for n := 0; n < 12; n++ {
						fmt.Fprintf(&body, "include:child%d\n", n)
					}
				} else {
					body.WriteString(strings.Repeat("#"+strings.Repeat("a", 32768)+"\n", 33))
					body.WriteString("valid.example\n")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body.String()))}, nil
			})})
			if _, err := m.Preview(context.Background(), "budget", nil, true); err == nil {
				t.Fatal("aggregate budget ignored")
			}
			if mode == "entries" && calls != 1 || mode == "bytes" && calls > 9 {
				t.Fatalf("rejection happened too late: %d fetches", calls)
			}
		})
	}
}

type failedBody struct{}

func (failedBody) Read([]byte) (int, error) { return 0, errors.New("private-body-token") }
func (failedBody) Close() error             { return nil }

func TestCommunityReadErrorsAreRedactedAndCancellationStopsBeforeFetch(t *testing.T) {
	m := budgetManager(t)
	calls := 0
	m.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: failedBody{}}, nil
	})})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Preview(ctx, "budget", nil, true); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancellation: %v calls=%d", err, calls)
	}
	if _, err := m.Preview(context.Background(), "budget", nil, true); err == nil || strings.Contains(err.Error(), "private-body-token") {
		t.Fatalf("unsafe body error: %v", err)
	}
}
