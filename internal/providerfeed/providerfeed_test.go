package providerfeed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const goodURI = "vless://11111111-1111-4111-8111-111111111111@node.example.org:443?security=tls&type=tcp#private-label"

var testTime = time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testManager(t *testing.T) (*Manager, *nodestore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m := New(store)
	m.now = func() time.Time { return testTime }
	return m, store, filepath.Join(dir, "nodes.private.json")
}
func response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
func setResponse(m *Manager, status int, body string, headers http.Header) {
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(status, body, headers), nil })}
}
func snapshotBytes(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSyncImportsOnlyQuarantinedCandidatesAndRedactsEverythingPublic(t *testing.T) {
	m, store, _ := testManager(t)
	setResponse(m, 200, goodURI, nil)
	request := Request{URL: "https://feed.example.org/private-token?secret=subscription-token"}
	result, err := m.Sync(context.Background(), request)
	if err != nil || result.Imported != 1 || len(result.NodeIDs) != 1 {
		t.Fatalf("sync result counts: imported=%d ids=%d err=%v", result.Imported, len(result.NodeIDs), err)
	}
	snapshot, err := store.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("node missing")
	}
	node := snapshot.Nodes[0]
	if node.State != "quarantined" || node.Trust != "untrusted" || node.Health.State != "not_checked" || len(snapshot.Groups) != 0 {
		t.Fatal("feed acquired local health/route authority")
	}
	public, _ := json.Marshal(struct {
		Result Result
		States []State
		Nodes  nodestore.Snapshot
	}{result, m.List(), snapshot})
	for _, secret := range []string{"11111111-1111-4111-8111-111111111111", "private-label", "node.example.org", "private-token", "subscription-token"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("public response contains private source/node material")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %+v", request, request, m), "subscription-token") {
		t.Fatal("formatting leaked private request")
	}
	if !result.OriginExpiresAt.Equal(testTime.Add(OriginTTL)) {
		t.Fatal("origin TTL not bounded")
	}
}

func Test304AndFailedFetchPreserveNodeTTLHealthAndPrivateBytes(t *testing.T) {
	m, store, path := testManager(t)
	setResponse(m, 200, goodURI, http.Header{"Etag": []string{`"private-etag"`}})
	req := Request{URL: "https://feed.example.org/token"}
	result, err := m.Sync(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.RecordCheck(context.Background(), result.NodeIDs[0], nodestore.CheckRecord{ProbeID: "probe-feed-check", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + result.NodeIDs[0], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), HTTPStatus: 200}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, path)
	m.now = func() time.Time { return testTime.Add(2 * time.Hour) }
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != `"private-etag"` {
			t.Fatal("missing conditional validator")
		}
		return response(304, "", nil), nil
	})}
	result, err = m.Sync(context.Background(), req)
	if err != nil || !result.NotModified || snapshotBytes(t, path) != before {
		t.Fatal("304 changed persistent evidence")
	}
	snapshot, _ := store.Snapshot(context.Background(), m.now())
	if snapshot.Nodes[0].Health.State != "stale" {
		t.Fatal("304 revived expired health")
	}
	setResponse(m, 503, "server response contains secret", nil)
	if _, err = m.Sync(context.Background(), req); !errors.Is(err, ErrFetch) {
		t.Fatal("HTTP failure accepted")
	}
	if snapshotBytes(t, path) != before || !m.List()[0].LastKnownGood || m.List()[0].Status != "stale" {
		t.Fatal("failed fetch modified LKG")
	}
	m.now = func() time.Time { return testTime.Add(25 * time.Hour) }
	setResponse(m, 304, "", nil)
	result, err = m.Sync(context.Background(), req)
	if !errors.Is(err, ErrFetch) || snapshotBytes(t, path) != before {
		t.Fatal("unsolicited expired 304 renewed origin expiry")
	}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			t.Fatal("expired origin retained conditional request")
		}
		return response(200, goodURI, http.Header{"Etag": []string{`"private-etag"`}}), nil
	})}
	result, err = m.Sync(context.Background(), req)
	if err != nil || result.NotModified || !result.OriginExpiresAt.Equal(m.now().Add(OriginTTL)) {
		t.Fatal("manual full refresh did not renew candidate freshness")
	}
	snapshot, _ = store.Snapshot(context.Background(), m.now())
	if snapshot.Nodes[0].Health.State != "stale" || !snapshot.Nodes[0].Health.ExpiresAt.Equal(testTime.Add(time.Hour)) {
		t.Fatal("full refresh renewed local proof")
	}
}

func Test200RefreshPreservesExactHealthAndRemovedNodes(t *testing.T) {
	m, store, _ := testManager(t)
	setResponse(m, 200, goodURI, nil)
	req := Request{PresetID: "goida-vless"}
	first, err := m.Sync(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.RecordCheck(context.Background(), first.NodeIDs[0], nodestore.CheckRecord{ProbeID: "probe-feed-check", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + first.NodeIDs[0], TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), HTTPStatus: 200}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return testTime.Add(2 * time.Hour) }
	second, err := m.Sync(context.Background(), req)
	if err != nil || second.Imported != 1 {
		t.Fatal(err)
	}
	snapshot, _ := store.Snapshot(context.Background(), m.now())
	if len(snapshot.Nodes) != 1 || !snapshot.Nodes[0].Health.ExpiresAt.Equal(testTime.Add(time.Hour)) || snapshot.Nodes[0].Health.State != "stale" {
		t.Fatal("200 renewed local proof")
	}
	setResponse(m, 200, strings.Replace(goodURI, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1), nil)
	if _, err = m.Sync(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = store.Snapshot(context.Background(), m.now())
	if len(snapshot.Nodes) != 2 {
		t.Fatal("refresh destructively removed prior candidate")
	}
}

func TestPartialImportNeedsExplicitAcceptanceAndNeverStoresRejectedEntries(t *testing.T) {
	m, store, _ := testManager(t)
	bad := strings.Replace(goodURI, "security=tls", "security=tls&allowInsecure=1", 1)
	setResponse(m, 200, bad+"\n"+goodURI, nil)
	req := Request{PresetID: "goida-vless"}
	result, err := m.Sync(context.Background(), req)
	if !errors.Is(err, ErrPartial) || result.Rejected != 1 {
		t.Fatal("partial import was not explicit")
	}
	snapshot, _ := store.Snapshot(context.Background(), testTime)
	if len(snapshot.Nodes) != 0 {
		t.Fatal("partial failure wrote nodes")
	}
	req.AcceptPartial = true
	result, err = m.Sync(context.Background(), req)
	if err != nil || result.Imported != 1 || result.Rejected != 1 {
		t.Fatal("accepted partial import failed")
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != "INSECURE_TLS" {
		t.Fatal("safe rejection reason missing")
	}
}

func TestChangedSelectionDoesNotReuse304AndFirst304IsRejected(t *testing.T) {
	m, _, _ := testManager(t)
	req := Request{URL: "https://feed.example.org/token", Limit: 1}
	setResponse(m, 304, "", nil)
	if _, err := m.Sync(context.Background(), req); !errors.Is(err, ErrFetch) {
		t.Fatal("unsolicited 304 accepted")
	}
	setResponse(m, 200, goodURI, http.Header{"Etag": []string{`"etag"`}})
	if _, err := m.Sync(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != "" {
			t.Fatal("old limited selection reused validators")
		}
		return response(200, goodURI, nil), nil
	})}
	req.Limit = 2
	if _, err := m.Sync(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func TestFetchBoundaryRejectsBadURLsRedirectsAndOversizeWithoutSecrets(t *testing.T) {
	for _, url := range []string{"http://feed.example.org/secret", "https://127.0.0.1/secret", "https://[::1]/secret", "https://feed.local/secret", "https://user:secret@feed.example.org/", "https://feed.example.org:8443/secret"} {
		t.Run(url, func(t *testing.T) {
			m, _, _ := testManager(t)
			m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid URL reached transport"); return nil, nil })}
			if _, err := m.Sync(context.Background(), Request{URL: url}); !errors.Is(err, ErrRequest) {
				t.Fatal("URL accepted")
			}
		})
	}
	m, _, _ := testManager(t)
	for _, target := range []string{"https://127.0.0.1/secret", "https://other.example.org/secret", "https://feed.example.org/redirect-secret"} {
		calls := 0
		m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return response(302, "", http.Header{"Location": []string{target}}), nil
		})}
		_, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/token"})
		if !errors.Is(err, ErrFetch) || calls != 1 || strings.Contains(err.Error(), "secret") {
			t.Fatal("redirect escaped source boundary")
		}
	}
	setResponse(m, 200, strings.Repeat("x", MaxBytes+1), nil)
	if _, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/token"}); !errors.Is(err, ErrSize) {
		t.Fatal("oversize accepted")
	}
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("private-token raw TLS error") })}
	if _, err := m.Sync(context.Background(), Request{URL: "https://feed.example.org/token"}); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("raw error leaked")
	}
}

func TestFeedGateCancellationAndStateCapacity(t *testing.T) {
	m, _, _ := testManager(t)
	m.gate <- struct{}{}
	if _, err := m.Sync(context.Background(), Request{PresetID: "goida-vless"}); !errors.Is(err, ErrBusy) {
		t.Fatal("parallel sync accepted")
	}
	<-m.gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Sync(ctx, Request{PresetID: "goida-vless"}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled sync accepted")
	}
	for i := 0; i < MaxFeeds; i++ {
		m.states[fmt.Sprint(i)] = cache{}
	}
	if _, err := m.Sync(context.Background(), Request{PresetID: "goida-vless"}); !errors.Is(err, ErrSize) {
		t.Fatal("unbounded feed registry")
	}
}

func TestParsersBoundSelectDeduplicateAndIgnoreUpstreamHealth(t *testing.T) {
	second := strings.Replace(goodURI, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1)
	for _, encoded := range []bool{false, true} {
		input := goodURI + "\n" + strings.Replace(goodURI, "private-label", "different-label", 1) + "\n" + second
		if encoded {
			input = base64.StdEncoding.EncodeToString([]byte(input))
		}
		b, err := parse(context.Background(), []byte(input), "uri-lines", 2)
		if err != nil || b.accepted != 2 || b.duplicates != 1 {
			t.Fatal("URI decode/dedup failed")
		}
	}
	key, _ := json.Marshal(goodURI)
	other, _ := json.Marshal(second)
	data := []byte(`{"updated_at":"2999-01-01","germany":{"best":"ignored","top10":[{"key":` + string(key) + `,"latency_ms":1,"host":"lie","port":1}],"total_working":999},"other_countries":{"Nested":{"top10":[{"key":` + string(other) + `}]}}}`)
	b, err := parse(context.Background(), data, "keys-json", 1)
	if err != nil || b.accepted != 1 || b.omitted != 1 || b.rejected != 0 || strings.Contains(b.raw, "2999") {
		t.Fatal("publisher metadata became authority or limit failed")
	}
	for _, bad := range []string{`{"x":{"top10":[{"key":` + string(key) + `,"key":` + string(other) + `}]}}`, `{"x":{"arbitrary":[` + string(key) + `]}}`, `{"x":{"top10":[]}}`, `{"x":null}`, `[]`, strings.Repeat("[", 10) + strings.Repeat("]", 10)} {
		if _, err := parse(context.Background(), []byte(bad), "keys-json", 32); err == nil {
			t.Fatal("invalid keys schema accepted")
		}
	}
	if _, err := parse(context.Background(), []byte(strings.Repeat(goodURI+"\n", MaxEntries+1)), "uri-lines", 1); !errors.Is(err, ErrSize) {
		t.Fatal("entry bound not enforced before truncation")
	}
}

func TestStoreFailureDoesNotAdvertiseSuccessOrRememberValidators(t *testing.T) {
	m, store, _ := testManager(t)
	_ = store.Close()
	setResponse(m, 200, goodURI, http.Header{"Etag": []string{`"etag"`}})
	result, err := m.Sync(context.Background(), Request{PresetID: "goida-vless"})
	if !errors.Is(err, ErrStore) || result.Imported != 0 || m.List()[0].LastKnownGood {
		t.Fatal("failed commit advertised success")
	}
	for _, entry := range m.states {
		if entry.etag != "" {
			t.Fatal("failed import remembered validators")
		}
	}
}
