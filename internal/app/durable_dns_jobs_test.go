package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
)

func durableDNSFixture(t *testing.T) (*App, serviceDNSCompareRequest) {
	t.Helper()
	a, _ := awgAPITest(t)
	var err error
	a.DNS, err = dnscontrol.New("")
	if err != nil {
		t.Fatal(err)
	}
	initReconcilerFixture(t, a, time.Now())
	revision := a.Store.Get().Revision
	return a, serviceDNSCompareRequest{ServiceID: "arbitrary-site", ProfileIDs: []string{"private"}, ConfigRevision: &revision, Confirm: "COMPARE_SERVICE_DNS", IdempotencyKey: "dns-durable-test-0001"}
}

func dnsDurableRequest(q serviceDNSCompareRequest) serviceControlJobRequest {
	return serviceControlJobRequest{Kind: "dns-compare", ServiceIDs: []string{q.ServiceID}, ExpectedRevision: q.ConfigRevision, IdempotencyKey: q.IdempotencyKey, DNS: &serviceDNSJobSpec{ProfileIDs: q.ProfileIDs, VerifyService: q.VerifyService}}
}

func fakeDNSComparison(host string) dnscontrol.ServiceDNSComparison {
	return dnscontrol.ServiceDNSComparison{Host: host, CheckedAt: time.Now().UTC().Format(time.RFC3339), Results: []dnscontrol.ServiceDNSAnswer{}}
}

func TestDurableDNSRealHTTPClosesLogoutRetryAndMemoryResult(t *testing.T) {
	a, q := durableDNSFixture(t)
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	token, err := a.Security.Setup("dnsadmin", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	cookieWriter := httptest.NewRecorder()
	security.SetSessionCookie(cookieWriter, httptest.NewRequest("GET", server.URL, nil), token)
	cookie := cookieWriter.Result().Cookies()[0]
	data, _ := json.Marshal(q)
	status, _, raw := serviceDNSHTTPRequest(t, server.Client(), server.URL, data, "", cookie, server.URL)
	var accepted struct{ Job nodeCheckJob }
	if status != 202 || json.Unmarshal(raw, &accepted) != nil || accepted.Job.DNSRequest == nil {
		t.Fatalf("accept: %d %s", status, raw)
	}
	// The accepting HTTP request has ended. Revoking its credential cannot
	// revoke the separate saved intent (explicit job cancellation can).
	logout := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	logout.AddCookie(cookie)
	a.Security.Logout(logout)
	if a.Security.Authenticated(logout) {
		t.Fatal("session not revoked")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, _ []string, host string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		calls.Add(1)
		close(entered)
		<-release
		return fakeDNSComparison(host), guard(ctx)
	})
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(done) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-done:
		default:
			close(release)
			<-done
		}
	}()
	for _, key := range []string{q.IdempotencyKey, "dns-second-window-0001"} {
		r := dnsDurableRequest(q)
		r.IdempotencyKey = key
		job, err := a.enqueueDurableServiceJob(context.Background(), r)
		if err != nil || job.ID != accepted.Job.ID {
			t.Fatal("duplicate/lease", job, err)
		}
	}
	changed := dnsDurableRequest(q)
	changed.DNS.VerifyService = true
	if _, err := a.enqueueDurableServiceJob(context.Background(), changed); !errors.Is(err, errDurableKeyConflict) {
		t.Fatal("changed intent accepted", err)
	}
	view := map[string]any{}
	a.addDurableServiceJobs(view)
	if view["durable_jobs"].([]*nodeCheckJob)[0].State != "running" {
		t.Fatal("memory unavailable while running")
	}
	close(release)
	awaitOperation(t, done)
	a.addDurableServiceJobs(view)
	job := view["durable_jobs"].([]*nodeCheckJob)[0]
	if calls.Load() != 1 || job.State != "completed" || len(job.DNSResult) == 0 {
		t.Fatal("accepted DNS did not finish", job)
	}
	job.DNSResult[0] = 'x'
	job.DNSRequest.ProfileIDs[0] = "mutated"
	a.addDurableServiceJobs(view)
	job = view["durable_jobs"].([]*nodeCheckJob)[0]
	if !json.Valid(job.DNSResult) || job.DNSRequest.ProfileIDs[0] != "private" {
		t.Fatal("public snapshot aliases worker")
	}
	disk, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{q.IdempotencyKey, `"dns_result"`, `"service_verified"`, `"host"`, `"checked_at"`} {
		if strings.Contains(string(disk), forbidden) {
			t.Fatal("journal retained diagnostic/credential", forbidden)
		}
	}
	b := &App{Store: a.Store}
	b.reconciler.started = true
	b.reconciler.path = a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.addDurableServiceJobs(view)
	job = view["durable_jobs"].([]*nodeCheckJob)[0]
	if job.State != "completed" || len(job.DNSResult) != 0 {
		t.Fatal("restart recreated old DNS proof")
	}
}

func TestDurableDNSChangedDefinitionsRefuseBeforeIO(t *testing.T) {
	for _, changed := range []string{"config", "catalog", "provider"} {
		t.Run(changed, func(t *testing.T) {
			a, q := durableDNSFixture(t)
			q.ProfileIDs = []string{"nextdns"}
			if err := a.DNS.SetNextDNSProfileID("abc123"); err != nil {
				t.Fatal(err)
			}
			job, err := a.enqueueDurableServiceJob(context.Background(), dnsDurableRequest(q))
			if err != nil {
				t.Fatal(err)
			}
			switch changed {
			case "config":
				err = a.Store.SetSafeMode(!a.Store.Get().SafeMode)
			case "catalog":
				a.Catalog.Services[0].ProbeURL = "https://changed.example/"
			case "provider":
				err = a.DNS.SetNextDNSProfileID("def456")
			}
			if err != nil {
				t.Fatal(err)
			}
			a.dnsServiceComparer = serviceDNSCompareFunc(func(context.Context, []string, string, func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
				t.Error("stale definition performed DNS IO")
				return dnscontrol.ServiceDNSComparison{}, nil
			})
			a.runDurableServiceJob(context.Background(), time.Now())
			got := durableJobAt(t, a, job.ID)
			if got.State != "failed" || got.DNSCode != "DNS_COMPARE_CHANGED" {
				t.Fatal(got)
			}
		})
	}
}

func TestDurableDNSCancelJoinsBeforeLeaseRelease(t *testing.T) {
	a, q := durableDNSFixture(t)
	job, err := a.enqueueDurableServiceJob(context.Background(), dnsDurableRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	entered, canceled, cleanup, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, _ []string, host string, _ func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-cleanup
		return fakeDNSComparison(host), nil
	})
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(done) }()
	awaitOperation(t, entered)
	defer func() {
		select {
		case <-done:
		default:
			close(cleanup)
			<-done
		}
	}()
	if found, err := a.cancelDurableServiceJob(context.Background(), job.ID); err != nil || !found {
		t.Fatal(found, err)
	}
	awaitOperation(t, canceled)
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("released before cleanup", err)
	}
	close(cleanup)
	awaitOperation(t, done)
	if durableJobAt(t, a, job.ID).State != "canceled" || len(a.reconciler.dnsResults) != 0 || a.Operations.Snapshot().Active != 0 {
		t.Fatal("late result after cancel/lease leak")
	}
}

func TestDurableDNSRestartPerformsFreshCheckAndBoundsMemory(t *testing.T) {
	a, q := durableDNSFixture(t)
	job, err := a.enqueueDurableServiceJob(context.Background(), dnsDurableRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	a.reconciler.doc.Jobs[0].State = "running"
	if err := a.persistReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := &App{Store: a.Store, Catalog: a.Catalog, DNS: a.DNS}
	b.reconciler.started = true
	b.reconciler.path = a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	var calls int
	b.dnsServiceComparer = serviceDNSCompareFunc(func(ctx context.Context, _ []string, host string, guard func(context.Context) error) (dnscontrol.ServiceDNSComparison, error) {
		calls++
		return fakeDNSComparison(host), guard(ctx)
	})
	b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
	if calls != 1 || durableJobAt(t, b, job.ID).State != "completed" {
		t.Fatal("recovery reused old observations")
	}
	for i := range 5 {
		q.IdempotencyKey = fmt.Sprintf("dns-memory-limit-%04d", i)
		if _, err := b.enqueueDurableServiceJob(context.Background(), dnsDurableRequest(q)); err != nil {
			t.Fatal(err)
		}
		b.reconciler.durableBurst = 0
		b.runDurableServiceJob(context.Background(), time.Now())
	}
	if calls != 6 || len(b.reconciler.dnsResults) != 4 || b.reconciler.dnsResults[job.ID] != nil {
		t.Fatal("DNS result retention not bounded")
	}
}

func TestDurableDNSCannotBypassHTTPConsentAndProfileValidation(t *testing.T) {
	a, q := durableDNSFixture(t)
	data, _ := json.Marshal(dnsDurableRequest(q))
	r := httptest.NewRequest("POST", "/api/v1/service-control/jobs", strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+awgAPIToken)
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("generic job endpoint bypasses consent", w.Code)
	}
	for _, profile := range []string{"automatic", "local", "geohide", "not-there"} {
		q.ProfileIDs = []string{profile}
		if _, err := a.enqueueDurableServiceJob(context.Background(), dnsDurableRequest(q)); err == nil {
			t.Fatal("invalid profile queued", profile)
		}
	}
	if len(a.reconciler.doc.Jobs) != 0 {
		t.Fatal("invalid input persisted")
	}
}
