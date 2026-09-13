package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/security"
)

// All request cases below terminate before external DNS. The DNS manager's
// exchange injection tests cover actual query calls in its own package.
func TestDNSServiceComparisonHTTPGuards(t *testing.T) {
	a, send := awgAPITest(t)
	var err error
	a.DNS, err = dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	rev := a.Store.Get().Revision
	body := func() map[string]any {
		return map[string]any{"service_id": "arbitrary-site", "profile_ids": []string{"private"}, "config_revision": rev, "confirm": "COMPARE_SERVICE_DNS"}
	}
	before := a.Store.Get()
	for _, c := range []struct {
		name, method string
		want         int
		mutate       func(map[string]any)
	}{
		{"wrong-method", "GET", 405, func(map[string]any) {}},
		{"consent", "POST", 400, func(q map[string]any) { delete(q, "confirm") }},
		{"missing-revision", "POST", 400, func(q map[string]any) { delete(q, "config_revision") }},
		{"unknown-field", "POST", 400, func(q map[string]any) { q["url"] = "https://private.example" }},
		{"stale-revision", "POST", 409, func(q map[string]any) { q["config_revision"] = rev + 1 }},
		{"missing-service", "POST", 404, func(q map[string]any) { q["service_id"] = "does-not-exist" }},
		{"invalid-profile", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{"does-not-exist"} }},
		{"unconfigured-profile", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{"geohide"} }},
		{"empty-profiles", "POST", 400, func(q map[string]any) { q["profile_ids"] = []string{} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := body()
			c.mutate(q)
			w := send(c.method, "/api/v1/dns/service-compare", q)
			if w.Code != c.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("read-only comparison changed config")
	}
	raw, _ := json.Marshal(body())
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/service-compare", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	a.dnsServiceCompare(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated", w.Code)
	}
}

type serviceDNSCompareFunc func(context.Context, []string, string, func(context.Context) error) (dnscontrol.ServiceDNSComparison, error)

func (f serviceDNSCompareFunc) CompareServiceDNSGuarded(ctx context.Context, ids []string, host string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
	return f(ctx, ids, host, guard)
}

func serviceDNSHTTPBody(a *App) []byte {
	data, _ := json.Marshal(map[string]any{"service_id": "arbitrary-site", "profile_ids": []string{"private"}, "config_revision": a.Store.Get().Revision, "confirm": "COMPARE_SERVICE_DNS"})
	return data
}

func serviceDNSHTTPRequest(t *testing.T, client *http.Client, url string, body []byte, token string, cookie *http.Cookie, origin string) (int, http.Header, []byte) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url+"/api/v1/dns/service-compare", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}

func TestDNSServiceComparisonRealHTTPAuthenticatesSessionAndPreservesAutomation(t *testing.T) {
	a, _ := awgAPITest(t)
	a.DNS, _ = dnscontrol.New("")
	var calls, autoCanceled atomic.Int32
	a.reconciler.started = true
	a.reconciler.cancel = func() { autoCanceled.Add(1) }
	a.nodeAutofallback.attemptCancel = func() { autoCanceled.Add(1) }
	a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, ids []string, host string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		calls.Add(1)
		if err := guard(ctx); err != nil {
			return dnscontrol.ServiceDNSComparison{}, err
		}
		return dnscontrol.ServiceDNSComparison{Host: host, Results: []dnscontrol.ServiceDNSAnswer{}, CheckedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	})
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	token, err := a.Security.Setup("dnsadmin", "fixture-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	security.SetSessionCookie(w, httptest.NewRequest(http.MethodGet, "http://example.test/", nil), token)
	cookie := w.Result().Cookies()[0]
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	body := serviceDNSHTTPBody(a)
	beforeConfig, beforeDNS := a.Store.Get(), a.DNS.Snapshot()
	for _, tc := range []struct {
		name, bearer, origin string
		cookie               *http.Cookie
		status               int
	}{
		{"unauthenticated", "", server.URL, nil, http.StatusUnauthorized},
		{"cross-origin", "", "https://other.example", cookie, http.StatusForbidden},
		{"session", "", server.URL, cookie, http.StatusOK},
		{"bearer", awgAPIToken, server.URL, nil, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, headers, data := serviceDNSHTTPRequest(t, server.Client(), server.URL, body, tc.bearer, tc.cookie, tc.origin)
			if status != tc.status {
				t.Fatalf("status=%d want=%d", status, tc.status)
			}
			if status == http.StatusOK && (headers.Get("Cache-Control") != "no-store" || !bytes.Contains(data, []byte(`"live_applied":false`)) || !bytes.Contains(data, []byte(`"service_verified":false`))) {
				t.Fatal("missing no-store or diagnostic-only contract")
			}
		})
	}
	if calls.Load() != 2 || autoCanceled.Load() != 0 || !a.reconciler.doc.ManualUntil.IsZero() || !reflect.DeepEqual(beforeConfig, a.Store.Get()) || !reflect.DeepEqual(beforeDNS, a.DNS.Snapshot()) {
		t.Fatal("DNS-only request touched automation/configuration or bypassed authentication")
	}
}

func TestDNSServiceComparisonHTTPChangedContextAndTypedErrors(t *testing.T) {
	for _, mode := range []string{"revision", "catalog", "catalog-slice", "deadline", "canceled", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := awgAPITest(t)
			a.DNS, _ = dnscontrol.New("")
			a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, _ []string, _ string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
				switch mode {
				case "revision":
					if err := a.Store.SetSafeMode(!a.Store.Get().SafeMode); err != nil {
						return dnscontrol.ServiceDNSComparison{}, err
					}
				case "catalog":
					a.Catalog.Services[0].ProbeURL = "https://changed.example/probe"
				case "catalog-slice":
					a.Catalog.Services[0].Domains[0] = "changed.example"
				case "deadline":
					<-ctx.Done()
					return dnscontrol.ServiceDNSComparison{}, ctx.Err()
				case "canceled":
					return dnscontrol.ServiceDNSComparison{}, context.Canceled
				case "unavailable":
					return dnscontrol.ServiceDNSComparison{}, errors.New("private-upstream-error-fixture")
				}
				return dnscontrol.ServiceDNSComparison{}, guard(ctx)
			})
			handler := a.Handler(http.NotFoundHandler())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "deadline" {
					ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
					defer cancel()
					r = r.WithContext(ctx)
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			status, headers, data := serviceDNSHTTPRequest(t, server.Client(), server.URL, serviceDNSHTTPBody(a), awgAPIToken, nil, server.URL)
			wantStatus, wantCode := http.StatusConflict, "DNS_COMPARE_CHANGED"
			switch mode {
			case "deadline":
				wantStatus, wantCode = http.StatusGatewayTimeout, "DNS_COMPARE_TIMEOUT"
			case "canceled":
				wantStatus, wantCode = http.StatusRequestTimeout, "DNS_COMPARE_CANCELED"
			case "unavailable":
				wantStatus, wantCode = http.StatusServiceUnavailable, "DNS_COMPARE_UNAVAILABLE"
			}
			if status != wantStatus || headers.Get("Cache-Control") != "no-store" || !bytes.Contains(data, []byte(wantCode)) || bytes.Contains(data, []byte("private-upstream-error-fixture")) || bytes.Contains(data, []byte(`"result":`)) {
				t.Fatalf("wrong status/code, partial result or raw error: status=%d want=%d", status, wantStatus)
			}
		})
	}
}

func TestDNSServiceComparisonProtectedPolicyRefusesBeforeComparer(t *testing.T) {
	a, send := awgAPITest(t)
	a.DNS, _ = dnscontrol.New("")
	p := config.DefaultServicePolicy("arbitrary-site", config.ServiceState{})
	p.TerminalAction = "block"
	if _, err := a.Store.UpdateServicePolicy(p, a.Store.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	a.dnsServiceComparer = serviceDNSCompareFunc(func(context.Context, []string, string, func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		t.Fatal("protected hostname reached DNS comparer")
		return dnscontrol.ServiceDNSComparison{}, nil
	})
	var body map[string]any
	_ = json.Unmarshal(serviceDNSHTTPBody(a), &body)
	w := send(http.MethodPost, "/api/v1/dns/service-compare", body)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "DNS_PROBE_PATH_POLICY") {
		t.Fatal("protected policy was not refused")
	}
}

func TestDNSServiceComparisonClientCancellationJoinsAndKeepsEmergencyAPIAvailable(t *testing.T) {
	a, _ := awgAPITest(t)
	a.DNS, _ = dnscontrol.New("")
	started, finished := make(chan struct{}), make(chan struct{})
	a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, _ []string, _ string, _ func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		close(started)
		<-ctx.Done()
		return dnscontrol.ServiceDNSComparison{}, ctx.Err()
	})
	handler := a.Handler(http.NotFoundHandler())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/api/v1/dns/service-compare" {
			close(finished) // Request lease has been released, not just canceled.
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/dns/service-compare", bytes.NewReader(serviceDNSHTTPBody(a)))
	r.Header.Set("Authorization", "Bearer "+awgAPIToken)
	r.Header.Set("Content-Type", "application/json")
	done := make(chan error, 1)
	go func() {
		response, err := server.Client().Do(r)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("comparison did not start")
	}
	for _, path := range []string{"/api/v1/node-checks/current", "/api/v1/service-control/current"} {
		r, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		r.Header.Set("Authorization", "Bearer "+awgAPIToken)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("emergency memory API blocked: %s status=%d", path, response.StatusCode)
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request retained worker or admission")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("client cancellation not observed: %v", err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("admission leaked after cancellation")
	}
	release()
}
