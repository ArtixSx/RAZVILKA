package providerfeed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This fixture performs a genuine TLS HTTP exchange over loopback. Only its
// trusted test transport maps the public-shaped source hostname to the local
// listener; it does not demonstrate public DNS, WAN access or a native fetch.
func observationLoopbackTLS(t *testing.T, m *Manager, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	certificate := server.Certificate()
	if len(certificate.DNSNames) > 0 {
		transport.TLSClientConfig.ServerName = certificate.DNSNames[0]
	} else {
		transport.TLSClientConfig.ServerName = certificate.IPAddresses[0].String()
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	m.client = &http.Client{Transport: transport}
}

func requireObservation(t *testing.T, result Result, status int, before, after time.Time) *FetchObservation {
	t.Helper()
	fetch := result.Fetch
	if fetch == nil || fetch.HTTPStatus != status {
		t.Fatal("fetch observation missing or did not retain actual HTTP status")
	}
	if fetch.RequestStartedAt.Location() != time.UTC || fetch.ResponseFinishedAt.Location() != time.UTC ||
		fetch.RequestStartedAt.Before(before) || fetch.ResponseFinishedAt.After(after) ||
		fetch.ResponseFinishedAt.Before(fetch.RequestStartedAt) {
		t.Fatal("fetch timestamps are not actual ordered UTC wall time")
	}
	return fetch
}

func TestFetchObservationGenuineLoopbackTLSExactBytesAndQuarantine(t *testing.T) {
	m, nodes, _ := testManager(t)
	body := "\n" + goodURI + "\r\n\n"
	observationLoopbackTLS(t, m, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/private-fetch-token" {
			t.Error("fixture received an unexpected request")
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	})
	before := time.Now().UTC()
	result, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/private-fetch-token"})
	after := time.Now().UTC()
	if err != nil || result.Imported != 1 {
		t.Fatal("loopback TLS import failed", err)
	}
	fetch := requireObservation(t, result, http.StatusOK, before, after)
	if !fetch.BodyClosed || !fetch.FreshBody || fetch.BodyBytes != int64(len(body)) || fetch.BodySHA256 != snapshotDigest([]byte(body)) {
		t.Fatal("fresh digest did not describe the exact completely read source bytes")
	}
	snapshot, err := nodes.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 1 || len(snapshot.Groups) != 0 {
		t.Fatal("unexpected candidate state")
	}
	node := snapshot.Nodes[0]
	if node.State != "quarantined" || node.Trust != "untrusted" || node.Health.State != "not_checked" {
		t.Fatal("fetch telemetry granted health or route authority")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-fetch-token", "feed.example.org", "11111111-1111-4111-8111-111111111111", "node.example.org", "private-label", "text/plain"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("public result leaked private request or source material")
		}
	}
}

func TestFetchObservationGenuineLoopbackTLSIncompleteAndRedirect(t *testing.T) {
	for _, mode := range []string{"truncated", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			m, nodes, _ := testManager(t)
			status := http.StatusOK
			wantBytes := int64(len(goodURI))
			if mode == "redirect" {
				status, wantBytes = http.StatusFound, 0
			}
			observationLoopbackTLS(t, m, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/original" {
					t.Error("redirect was followed")
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://feed.example.org/redirected-private-token")
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(len(goodURI)+1))
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, goodURI)
			})
			before := time.Now().UTC()
			result, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/original"})
			fetch := requireObservation(t, result, status, before, time.Now().UTC())
			if !errors.Is(err, ErrFetch) || result.Imported != 0 || fetch.BodyBytes != wantBytes ||
				!fetch.BodyClosed || fetch.FreshBody || fetch.BodySHA256 != "" {
				t.Fatal("actual HTTP failure was promoted to a complete fresh response", err)
			}
			snapshot, err := nodes.Snapshot(context.Background(), testTime)
			if err != nil || len(snapshot.Nodes) != 0 {
				t.Fatal("actual HTTP failure imported candidates")
			}
		})
	}
}

type observationBody struct {
	io.Reader
	closeErr error
	onClose  func()
	closedAt time.Time
	closes   int
}

func (b *observationBody) Close() error {
	b.closes++
	if b.onClose != nil {
		b.onClose()
	}
	b.closedAt = time.Now().UTC()
	return b.closeErr
}

type observationReadFault struct{ body string }

func (r observationReadFault) Read(p []byte) (int, error) {
	return copy(p, r.body), io.ErrUnexpectedEOF
}

type observationCancelRead struct {
	body   string
	cancel context.CancelFunc
}

func (r observationCancelRead) Read(p []byte) (int, error) {
	r.cancel()
	return copy(p, r.body), io.EOF
}

// These are modeled transport failures, complementing the genuine TLS fixture.
func TestFetchObservationFailureAndCloseSemantics(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		wantErr   error
		wantBytes int64
		imported  int
	}{
		{"network", 0, ErrFetch, 0, 0},
		{"partial", 200, ErrFetch, int64(len(goodURI)), 0},
		{"cancel-read", 200, context.Canceled, int64(len(goodURI)), 0},
		{"oversize-read", 200, ErrSize, MaxBytes + 1, 0},
		{"oversize-header", 200, ErrSize, 0, 0},
		{"close-error", 200, nil, int64(len(goodURI)), 1},
		{"cancel-close", 200, context.Canceled, int64(len(goodURI)), 0},
		{"unsolicited-304", 304, ErrFetch, 0, 0},
		{"rate-limit", 429, ErrRateLimited, 0, 0},
		{"unavailable", 503, ErrFetch, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := testManager(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &observationBody{Reader: strings.NewReader(goodURI)}
			m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if tc.name == "network" {
					return nil, errors.New("private-network-token")
				}
				r := response(tc.status, goodURI, nil)
				r.Body = body
				switch tc.name {
				case "partial":
					body.Reader = observationReadFault{goodURI}
				case "cancel-read":
					body.Reader = observationCancelRead{goodURI, cancel}
				case "oversize-read":
					body.Reader = strings.NewReader(strings.Repeat("x", MaxBytes+2))
					r.ContentLength = -1
				case "oversize-header":
					r.ContentLength = MaxBytes + 1
				case "close-error":
					body.closeErr = errors.New("private-close-token")
				case "cancel-close":
					body.onClose = cancel
				case "rate-limit":
					r.Header.Set("Retry-After", "3600")
				}
				return r, nil
			})}
			before := time.Now().UTC()
			result, err := m.Sync(ctx, Request{URL: "https://feed.example.org/failure-private-token"})
			fetch := requireObservation(t, result, tc.status, before, time.Now().UTC())
			if !errors.Is(err, tc.wantErr) || result.Imported != tc.imported {
				t.Fatal("observation changed original error or import behavior", err)
			}
			if fetch.BodyBytes != tc.wantBytes || fetch.FreshBody || fetch.BodySHA256 != "" {
				t.Fatal("failed, incomplete or cached response received a fresh digest")
			}
			wantClosed := tc.status != 0 && tc.name != "close-error"
			if fetch.BodyClosed != wantClosed || tc.status != 0 && (body.closes != 1 || fetch.ResponseFinishedAt.Before(body.closedAt)) {
				t.Fatal("body closure was duplicated, misreported or happened after finish timestamp")
			}
			if tc.name == "rate-limit" {
				deferred, err := m.Sync(ctx, Request{URL: "https://feed.example.org/failure-private-token"})
				if !errors.Is(err, ErrDeferred) || deferred.Fetch != nil {
					t.Fatal("retry deferral fabricated another fetch")
				}
			}
		})
	}
}

func TestFetchObservationCompleteHTTP200DoesNotImplySuccessfulImport(t *testing.T) {
	for _, mode := range []string{"parse", "history-admission"} {
		t.Run(mode, func(t *testing.T) {
			m, nodes, _ := testManager(t)
			body := "not a supported provider profile"
			if mode == "history-admission" {
				body = historyXHTTPFeedURI()
				m.HistoryWriteAdmission = func(context.Context, int) error { return ErrHistoryAdmission }
			}
			setResponse(m, http.StatusOK, body, nil)
			before := time.Now().UTC()
			result, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/import-refusal"})
			fetch := requireObservation(t, result, http.StatusOK, before, time.Now().UTC())
			if err == nil || result.Imported != 0 || !fetch.FreshBody || !fetch.BodyClosed || fetch.BodySHA256 != snapshotDigest([]byte(body)) {
				t.Fatal("complete HTTP observation was confused with import success")
			}
			if mode == "history-admission" && !errors.Is(err, ErrHistoryAdmission) {
				t.Fatal("original history refusal changed", err)
			}
			snapshot, err := nodes.Snapshot(context.Background(), testTime)
			if err != nil || len(snapshot.Nodes) != 0 {
				t.Fatal("failed import persisted candidates")
			}
		})
	}
}

func TestFetchObservationNotCreatedBeforeDo(t *testing.T) {
	m, _, _ := testManager(t)
	calls := 0
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, goodURI, nil), nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx context.Context
		url string
	}{
		{context.Background(), "http://feed.example.org/invalid"},
		{ctx, "https://feed.example.org/canceled"},
	} {
		result, err := m.Sync(tc.ctx, Request{URL: tc.url})
		if err == nil || result.Fetch != nil || calls != 0 {
			t.Fatal("rejected request fabricated a fetch")
		}
	}
}

func TestFetchObservationCached304PagesRetainOriginalExpiry(t *testing.T) {
	m, nodes, _ := persistentManager(t)
	saved := savePagedFeed(t, m)
	body := pageFeed(70)
	setResponse(m, 200, body, http.Header{"Etag": []string{`"observed-v1"`}})
	first, err := m.SyncSaved(context.Background(), saved.SourceID)
	if err != nil || first.Fetch == nil || first.Fetch.BodySHA256 != snapshotDigest([]byte(body)) || first.Cursor != 32 {
		t.Fatal("first snapshot not imported")
	}
	m.now = func() time.Time { return testTime.Add(time.Hour) }
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != `"observed-v1"` {
			t.Error("original conditional request missing")
		}
		return response(304, "", nil), nil
	})}
	for _, cursor := range []int{64, 70, 70} {
		before := time.Now().UTC()
		result, err := m.SyncSaved(context.Background(), saved.SourceID)
		fetch := requireObservation(t, result, 304, before, time.Now().UTC())
		if err != nil || !result.NotModified || result.Cursor != cursor || !result.OriginExpiresAt.Equal(first.OriginExpiresAt) ||
			!fetch.BodyClosed || fetch.BodyBytes != 0 || fetch.FreshBody || fetch.BodySHA256 != "" {
			t.Fatal("cached page fabricated a fresh body or changed original cursor/expiry", err)
		}
	}
	snapshot, err := nodes.Snapshot(context.Background(), testTime.Add(time.Hour))
	if err != nil || len(snapshot.Nodes) != 70 {
		t.Fatal("cached pages did not retain original imports")
	}
	for _, node := range snapshot.Nodes {
		if node.Health.State != "not_checked" || len(node.Origins) != 1 || !node.Origins[0].ExpiresAt.Equal(first.OriginExpiresAt) {
			t.Fatal("304 conferred health or extended an origin")
		}
	}
}

func TestFetchObservationScheduledJobPublishesDetachedWireDTO(t *testing.T) {
	m, _, _ := persistentManager(t)
	saved := saveFeed(t, m, true)
	m.now = func() time.Time { return saved.NextRefreshAt }
	observationLoopbackTLS(t, m, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, goodURI) })
	ctx, stop := context.WithCancel(context.Background())
	defer func() {
		stop()
		wait, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.Wait(wait); err != nil {
			t.Fatal("original worker did not retire", err)
		}
	}()
	m.StartManaged(ctx, nil)
	m.ScheduleDue(saved.NextRefreshAt)
	m.mu.Lock()
	if len(m.jobs.order) != 1 {
		m.mu.Unlock()
		t.Fatal("original scheduler did not create exactly one job")
	}
	id := m.jobs.order[0]
	m.mu.Unlock()
	job := waitJob(t, m, id)
	if !job.Scheduled || job.Status != "completed" || job.Result == nil || job.Result.Fetch == nil || !job.Result.Fetch.FreshBody {
		t.Fatal("completed original scheduled job lost its actual fetch observation")
	}
	original := *job.Result.Fetch
	job.Result.Fetch.HTTPStatus = 999
	job.Result.Fetch.BodySHA256 = "changed"
	copy, err := m.Job(id)
	if err != nil || copy.Result == nil || copy.Result.Fetch == nil || *copy.Result.Fetch != original {
		t.Fatal("public job view could mutate stored observation")
	}
	encoded, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Result struct {
			Fetch map[string]json.RawMessage `json:"fetch"`
		} `json:"result"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(wire.Result.Fetch))
	for key := range wire.Result.Fetch {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"body_bytes", "body_closed", "body_sha256", "fresh_body", "http_status", "request_started_at", "response_finished_at"}
	if !reflect.DeepEqual(keys, want) || original.HTTPStatus != 200 || original.BodySHA256 != snapshotDigest([]byte(goodURI)) {
		t.Fatal("FETCH-V1 wire shape or actual digest changed")
	}
	empty, err := json.Marshal(Result{})
	if err != nil || strings.Contains(string(empty), `"fetch"`) {
		t.Fatal("absent exchange emitted fetch telemetry")
	}
	noDigest, err := json.Marshal(FetchObservation{HTTPStatus: 304})
	if err != nil || strings.Contains(string(noDigest), `"body_sha256"`) {
		t.Fatal("non-fresh observation emitted a body digest")
	}
}
