package probecheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
)

func TestNetworkTimingActualTLSRedirectBodyAndExistingHooks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final?private=secret", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "private-response")
	}))
	defer server.Close()
	ctx, m := WithNetworkMeasurements(context.Background())
	calls := 0
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { calls++ }})
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/start?token=secret", nil)
	client := server.Client()
	prior := client.Transport
	response, err := TimingClient(ctx, client).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	rows := m.Close()
	if len(rows) != 2 || calls != 2 || string(body) != "private-response" || client.Transport != prior {
		t.Fatal("changed request/transport/redirect hooks", len(rows), calls)
	}
	if !rows[0].TLS.Observed || rows[0].TLS.Status != "complete" || !rows[0].TTFB.Observed || !rows[1].TTFB.Observed || rows[1].Body.Status != "complete" || !rows[1].Headers {
		t.Fatal("missing actual completed phases", rows)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"private", "secret", server.URL, "/start", "/final"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("network diagnostics leaked material")
		}
	}
	rows[0].Kind = "changed"
	if m.Close()[0].Kind != "service-http" {
		t.Fatal("snapshot borrowed mutable rows")
	}
}

type networkTimingTestTransport func(*http.Request) (*http.Response, error)

func (f networkTimingTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNetworkTimingCancellationAndLateCallbacks(t *testing.T) {
	ctx, m := WithNetworkMeasurements(context.Background())
	var trace *httptrace.ClientTrace
	client := &http.Client{Transport: networkTimingTestTransport(func(r *http.Request) (*http.Response, error) {
		trace = httptrace.ContextClientTrace(r.Context())
		trace.TLSHandshakeStart()
		finish := BeginSOCKSConnect(r.Context())
		finish(context.Canceled)
		return nil, context.Canceled
	})}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.org/secret", nil)
	_, err := TimingClient(ctx, client).Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation lost")
	}
	rows := m.Close()
	before, _ := json.Marshal(rows)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 30 {
				trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
				trace.GotFirstResponseByte()
				_ = m.Close()
			}
		}()
	}
	group.Wait()
	after, _ := json.Marshal(m.Close())
	if string(before) != string(after) || rows[0].Status != "failed" || rows[0].Headers || rows[0].SOCKS.Status != "failed" || rows[0].TLS.Status != "incomplete" {
		t.Fatal("late callback mutated frozen failure", rows)
	}
}
func TestNetworkTimingEarlyCloseBoundsAndLocalDNS(t *testing.T) {
	ctx, m := WithNetworkMeasurements(context.Background())
	finish := BeginLocalServiceDNS(ctx)
	finish(errors.New("private resolver error"))
	client := &http.Client{Transport: networkTimingTestTransport(func(r *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		trace.TLSHandshakeStart()
		trace.TLSHandshakeStart()
		trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
		for range 2 {
			end := BeginSOCKSConnect(r.Context())
			end(nil)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unconsumed")), Request: r}, nil
	})}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.org/", nil)
	resp, err := TimingClient(ctx, client).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, _ = resp.Body.Read(buf)
	_ = resp.Body.Close()
	for range 50 {
		end := BeginLocalServiceDNS(ctx)
		end(nil)
	}
	rows := m.Close()
	if len(rows) != 32 || !rows[31].LaterRowsOmitted || rows[0].DNS.Status != "failed" || rows[1].Body.Status != "incomplete" || rows[1].TLS.Status != "multiple" || rows[1].SOCKS.Status != "multiple" || rows[1].SOCKSAttempts != 2 {
		t.Fatal("invented complete or singleton measurement", rows[:2])
	}
	if TimingClient(context.Background(), client) != client {
		t.Fatal("unobserved transport changed")
	}
}

func TestNetworkTimingCanceledSecondAttemptCannotBorrowFirstDuration(t *testing.T) {
	ctx, m := WithNetworkMeasurements(context.Background())
	client := &http.Client{Transport: networkTimingTestTransport(func(r *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		trace.TLSHandshakeStart()
		trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
		first := BeginSOCKSConnect(r.Context())
		first(nil)
		trace.TLSHandshakeStart()
		_ = BeginSOCKSConnect(r.Context())
		return nil, context.Canceled
	})}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.org/", nil)
	_, err := TimingClient(ctx, client).Do(request)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	rows := m.Close()
	if len(rows) != 1 || rows[0].TLSAttempts != 2 || rows[0].SOCKSAttempts != 2 || rows[0].TLS.Status != "multiple" || rows[0].SOCKS.Status != "multiple" || rows[0].TLS.DurationUS != 0 || rows[0].SOCKS.DurationUS != 0 {
		t.Fatal("unfinished retry borrowed prior completed interval", rows)
	}
}
