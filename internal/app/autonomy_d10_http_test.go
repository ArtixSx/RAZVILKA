package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
)

type d10HTTPRequest struct {
	ordinal   int
	validator string
	release   chan struct{}
}

// Real TLS/HTTP bytes; only the transport destination is explicitly pinned to
// this owned listener. The approved public-shaped HTTPS URL, certificate name,
// TLS verification, and providerfetch URL/redirect guards stay enabled.
func d10TLSFeedClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "feed.example.test"}, DNSNames: []string{"feed.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "feed.example.test:443" {
				return nil, fmt.Errorf("unexpected fixture destination")
			}
			return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func d10WaitFeedJob(t *testing.T, feeds *providerfeed.Manager, id string) providerfeed.Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		job, err := feeds.Job(id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == "completed" || job.Status == "failed" || job.Status == "canceled" {
			return job
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("owned source job did not finish")
		}
	}
}

// Actual autonomyRound -> RequestRefillRanked -> StartNodeFeeds/managed queue ->
// real TLS 200/304/failure -> private snapshot/NodeStore -> exact Check/Apply.
// Clock and dial destination are trusted fixtures; OS adapter/checker remain
// controlled, so this is neither public-provider availability nor LAN/HIL proof.
func TestD10WorkerHTTP304ReusesVerifiedSnapshotAndPreservesLKGOnFailure(t *testing.T) {
	a, _, adapter := autonomousIntegrationFixture(t)
	profiles := []string{}
	for i := 0; i < 33; i++ {
		profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@http-page%d.example:443?security=tls", i))
	}
	body := strings.Join(profiles, "\n")
	requests := make(chan d10HTTPRequest, 4)
	var requestCount atomic.Int32
	client := d10TLSFeedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "feed.example.test" || r.URL.Path != "/approved" || r.TLS == nil || r.TLS.ServerName != "feed.example.test" {
			t.Error("wrong HTTP/TLS source identity")
			http.Error(w, "fixture refused", 500)
			return
		}
		ticket := d10HTTPRequest{ordinal: int(requestCount.Add(1)), validator: r.Header.Get("If-None-Match"), release: make(chan struct{})}
		select {
		case requests <- ticket:
		case <-r.Context().Done():
			return
		}
		select {
		case <-ticket.release:
		case <-r.Context().Done():
			return
		}
		switch ticket.ordinal {
		case 1:
			w.Header().Set("ETag", `"verified-d10"`)
			fmt.Fprint(w, body)
		case 2, 4:
			w.WriteHeader(http.StatusNotModified)
		case 3:
			w.Header().Set("ETag", `"unsafe-new"`)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "vless://123e4567-e89b-12d3-a456-426614174000@unsafe-new.example:443?security=tls")
		default:
			t.Error("unexpected extra source request")
			http.Error(w, "fixture refused", 500)
		}
	}))
	feedRoot := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(feedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	base := time.Now().UTC().Add(-3 * time.Hour)
	clock.Store(base.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	var stop context.CancelFunc
	stopFeeds := func() {
		if stop != nil {
			stop()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := a.WaitNodeFeeds(ctx); err != nil {
				t.Error(err)
			}
			stop = nil
		}
		if a.NodeFeeds != nil {
			if err := a.NodeFeeds.Close(); err != nil {
				t.Error(err)
			}
			a.NodeFeeds = nil
		}
	}
	t.Cleanup(stopFeeds)
	openFeeds := func() {
		feeds, err := providerfeed.OpenWithDependencies(a.Nodes, feedRoot, client, now)
		if err != nil {
			t.Fatal(err)
		}
		a.NodeFeeds = feeds
	}
	startFeeds := func() { ctx, cancel := context.WithCancel(context.Background()); stop = cancel; a.StartNodeFeeds(ctx) }
	openFeeds()
	source, err := a.NodeFeeds.Save(context.Background(), "", providerfeed.SaveRequest{Request: providerfeed.Request{URL: "https://feed.example.test/approved", Limit: 32}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy.SourceIDs = []string{source.SourceID}
	a.autonomy.doc.Policy.CandidatesPerRound = 4
	err = a.persistAutonomyLocked(context.Background())
	a.autonomy.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	startFeeds()
	receive := func(ordinal int, validator string) d10HTTPRequest {
		t.Helper()
		select {
		case req := <-requests:
			if req.ordinal != ordinal || req.validator != validator {
				t.Fatal("wrong conditional source request", req.ordinal, req.validator)
			}
			return req
		case <-time.After(10 * time.Second):
			t.Fatal("owned source HTTP request did not arrive")
			return d10HTTPRequest{}
		}
	}
	activeJob := func() string {
		t.Helper()
		for _, state := range a.NodeFeeds.List() {
			if state.SourceID == source.SourceID && state.JobID != "" {
				return state.JobID
			}
		}
		t.Fatal("actual source request lacks managed job")
		return ""
	}
	cacheBytes := func() []byte {
		t.Helper()
		paths, err := filepath.Glob(filepath.Join(feedRoot, "feed-snapshots", "*.private"))
		if err != nil || len(paths) != 1 {
			t.Fatal("verified snapshot file absent", err, len(paths))
		}
		raw, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	checked := []string{}
	usable := ""
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		checked = append(checked, req.NodeID)
		if req.NodeID != usable {
			return dataplane.NodeCheckResult{}, dataplane.ErrExactNodeUnsupported
		}
		return d10Result(req, "sing-box", true), nil
	})
	// Empty cold catalogue requests its approved first page through the app.
	a.autonomyRound(context.Background(), time.Now())
	firstReq := receive(1, "")
	firstJobID := activeJob()
	close(firstReq.release)
	first := d10WaitFeedJob(t, a.NodeFeeds, firstJobID)
	if first.Status != "completed" || first.Result == nil || first.Result.NotModified || first.Result.Cursor != 32 || len(first.Result.NodeIDs) != 32 {
		t.Fatal("first real HTTP page failed", first.Status, first.ErrorCode)
	}
	if !bytes.Equal(cacheBytes(), []byte(body)) {
		t.Fatal("cached source bytes differ from verified 200 body")
	}
	initialExpiry := first.Result.OriginExpiresAt
	for i := 0; i < 8; i++ {
		autonomyTestDue(a, false)
		a.autonomyRound(context.Background(), time.Now())
	}
	r := autonomyTestState(a)
	if len(checked) != 32 || !r.Search.Exhausted || r.Search.Cursor != 32 || len(adapter.calls) != 0 || requestCount.Load() != 1 {
		t.Fatal("cold snapshot not exhausted without Apply", len(checked), r.State)
	}
	before304, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Restart both durable managers; the source validator and both cursors
	// survive. A virtual clock advances only provider cooldown, not proof TTL.
	stopFeeds()
	d10Reopen(t, a)
	clock.Store(base.Add(16 * time.Minute).UnixNano())
	openFeeds()
	startFeeds()
	a.autonomyRound(context.Background(), time.Now())
	secondReq := receive(2, `"verified-d10"`)
	secondJobID := activeJob()
	close(secondReq.release)
	second := d10WaitFeedJob(t, a.NodeFeeds, secondJobID)
	if second.Status != "completed" || second.Result == nil || !second.Result.NotModified || second.Result.Cursor != 33 || len(second.Result.NodeIDs) != 1 || !second.Result.OriginExpiresAt.Equal(initialExpiry) {
		t.Fatal("304 did not resume original page/TTL", second.Status, second.ErrorCode)
	}
	usable = second.Result.NodeIDs[0]
	after304, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before304.Nodes {
		found := false
		for _, latest := range after304.Nodes {
			if latest.ID == old.ID && reflect.DeepEqual(latest, old) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("304 changed existing origin/history", old.ID)
		}
	}
	if len(after304.Nodes) != len(before304.Nodes)+1 || !bytes.Equal(cacheBytes(), []byte(body)) {
		t.Fatal("304 replaced verified contents or candidate membership")
	}
	d10Options(a, append(slices.Clone(first.Result.NodeIDs), usable))
	adapter.after = func(phase string) error {
		if phase == "stage" {
			state := autonomyTestState(a)
			if len(checked) != 33 || state.Search.Cursor != 33 || len(state.Reserves) != 1 {
				t.Fatal("first usable waited for reserve", state.State, len(checked))
			}
		}
		return nil
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Now())
	if r = autonomyTestState(a); r.State != "applied" || len(checked) != 33 || checked[32] != usable || len(r.Reserves) != 1 || requestCount.Load() != 2 || selectedRoute(a.Store.Get().AppliedServices["my-independent-site"]) != "sing-box:"+usable {
		t.Fatal("fresh entry33 did not Apply before refill/reserve", r.State, len(checked))
	}
	verifiedConfig := a.Store.Get()
	verifiedNodes, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Explicit approved refreshes use the same managed source worker. A failed
	// HTTP response with new-looking material/validator must preserve the LKG.
	clock.Store(base.Add(32 * time.Minute).UnixNano())
	failedQueue, err := a.NodeFeeds.QueueSync(source.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	failedReq := receive(3, `"verified-d10"`)
	close(failedReq.release)
	failed := d10WaitFeedJob(t, a.NodeFeeds, failedQueue.ID)
	failedState, err := a.NodeFeeds.Saved(source.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != "failed" || failed.Result == nil || failed.Result.Cursor != 33 || !failedState.LastKnownGood || !failedState.OriginExpiresAt.Equal(initialExpiry) {
		t.Fatal("failed response erased known-good source/cursor", failed.Status, failed.ErrorCode)
	}
	failedNodes, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verifiedNodes, failedNodes) || !reflect.DeepEqual(verifiedConfig, a.Store.Get()) || !bytes.Equal(cacheBytes(), []byte(body)) {
		t.Fatal("failed source mutated trusted membership/history/config/cache")
	}
	clock.Store(base.Add(48 * time.Minute).UnixNano())
	lastQueue, err := a.NodeFeeds.QueueSync(source.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	lastReq := receive(4, `"verified-d10"`)
	close(lastReq.release)
	last := d10WaitFeedJob(t, a.NodeFeeds, lastQueue.ID)
	finalNodes, err := a.Nodes.Snapshot(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if last.Status != "completed" || last.Result == nil || !last.Result.NotModified || last.Result.Cursor != 33 || len(last.Result.NodeIDs) != 0 || !last.Result.OriginExpiresAt.Equal(initialExpiry) || !reflect.DeepEqual(verifiedNodes, finalNodes) || !reflect.DeepEqual(verifiedConfig, a.Store.Get()) || !bytes.Equal(cacheBytes(), []byte(body)) || len(checked) != 33 {
		t.Fatal("failure/exhausted304 changed verified nodes/config/cache or repeated checks", last.Status, last.ErrorCode)
	}
}
