package dataplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCandidateProbeRejectsPolicyResponsesAndBlockPages(t *testing.T) {
	for _, status := range []int{302, 403, 451, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		for name, probe := range map[string]func(context.Context, string) error{"nfqws2": defaultNFQWS2Probe, "tunnel": defaultTunnelProbe} {
			if err := probe(context.Background(), server.URL); err == nil {
				t.Errorf("%s accepted HTTP %d", name, status)
			}
		}
		server.Close()
	}
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html>Доступ к информационному ресурсу ограничен</html>"))}
	if _, err := strictServiceResponse("https://telegram.org/", response); err == nil {
		t.Fatal("candidate accepted a 200 block page")
	}
}

func TestCandidateProbeAccepts204(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	if err := defaultNFQWS2Probe(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
	if err := defaultTunnelProbe(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
}
