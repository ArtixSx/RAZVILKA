package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
)

func scopedDNSJobFixture(t *testing.T) (*App, serviceControlJobRequest) {
	t.Helper()
	a := dnsRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	if err := a.DNS.SetServiceDraft("telegram", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	spec := scopedDNSApplySpec{Action: "apply", ProfileID: "unfiltered", Client: "192.168.1.40", Listener: "192.168.1.1:10553", Ingress: "br0"}
	revision := a.Store.Get().Revision
	_, review, err := a.reviewScopedDNSApply(context.Background(), "telegram", revision, spec)
	if err != nil {
		previous, _, _ := a.Dataplane.Committed()
		t.Fatalf("preview %v; applied=%+v; routes=%+v", err, a.Store.Get().AppliedServices, previous.Routes)
	}
	spec.Digest = review.review.Digest
	return a, serviceControlJobRequest{Kind: "dns-apply", ServiceIDs: []string{"telegram"}, ExpectedRevision: &revision, DNSApply: &spec, IdempotencyKey: "scoped-dns-job-request-1"}
}

func TestScopedDNSDurableCancelKeepsAdmissionUntilRollbackCompletes(t *testing.T) {
	a, r := scopedDNSJobFixture(t)
	adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
	entered, cleaning, allowCleanup, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.Dataplane.Adapters["dns-scoped"] = &dnsCancelAdapter{dnsReviewAdapter: adapter, entered: entered, cleaning: cleaning, allowCleanup: allowCleanup}
	job, err := a.enqueueDurableServiceJob(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(done) }()
	awaitOperation(t, entered)
	if _, err := a.cancelDurableServiceJob(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	awaitOperation(t, cleaning)
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("DNS cleanup released admission early", err)
	}
	close(allowCleanup)
	awaitOperation(t, done)
	if got := durableJobAt(t, a, job.ID); got.State != "canceled" || got.CleanupOutcome != "joined" || a.DNS.VerifyServiceSelection("telegram", "private") != nil {
		t.Fatal("cancel failed to restore prior DNS", got)
	}
	if release, err := a.Operations.Exclusive(context.Background()); err != nil {
		t.Fatal("cleanup retained admission", err)
	} else {
		release()
	}
}

func TestScopedDNSDurableRejectsMismatchedJobPayloads(t *testing.T) {
	_, r := scopedDNSJobFixture(t)
	for _, kind := range []string{"check", "select", "dns-compare", "stop", "resume", "node-check", "node-apply"} {
		r.Kind = kind
		if validDurableRequest(r) {
			t.Fatalf("DNS intent accepted as %s", kind)
		}
	}
}

func TestScopedDNSDurableApplyPreservesDraftsAndDeduplicatesBusyAcceptance(t *testing.T) {
	a, r := scopedDNSJobFixture(t)
	// A pending unrelated edit must be reviewed but not consumed by DNS apply.
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
		t.Fatal(err)
	}
	*r.ExpectedRevision = a.Store.Get().Revision
	_, review, err := a.reviewScopedDNSApply(context.Background(), "telegram", *r.ExpectedRevision, *r.DNSApply)
	if err != nil {
		t.Fatal(err)
	}
	r.DNSApply.Digest = review.review.Digest
	before := a.Store.Get()
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	job, err := a.enqueueDurableServiceJob(context.Background(), r)
	release()
	if err != nil {
		t.Fatal("busy queue", err)
	}
	for _, key := range []string{r.IdempotencyKey, "scoped-dns-second-window"} {
		r.IdempotencyKey = key
		next, err := a.enqueueDurableServiceJob(context.Background(), r)
		if err != nil || next.ID != job.ID {
			t.Fatal("duplicate", err)
		}
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	if got := durableJobAt(t, a, job.ID); got.State != "completed" || a.DNS.VerifyServiceSelection("telegram", "unfiltered") != nil {
		t.Fatal("DNS apply did not complete", got)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("DNS apply changed main config or device draft")
	}
	if again, err := a.enqueueDurableServiceJob(context.Background(), r); err != nil || again.ID != job.ID {
		t.Fatal("lost response repeats apply", err)
	}
	raw, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{r.IdempotencyKey, "https://", "dns.google", "cloudflare-dns", "private_key"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("job journal retained private material", forbidden)
		}
	}
}

func TestScopedDNSDurableChangedReviewRefusesBeforeRuntime(t *testing.T) {
	for _, change := range []string{"draft", "config", "catalog", "network", "digest"} {
		t.Run(change, func(t *testing.T) {
			a, r := scopedDNSJobFixture(t)
			if change == "digest" {
				r.DNSApply.Digest = strings.Repeat("a", 64)
			}
			job, err := a.enqueueDurableServiceJob(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "draft":
				if err := a.DNS.SetServiceDraft("telegram", "security"); err != nil {
					t.Fatal(err)
				}
			case "config":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "catalog":
				a.Catalog.Services[0].Domains = append(a.Catalog.Services[0].Domains, "new.telegram.org")
			case "network":
				a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
				a.Dataplane.FreshProfile = a.FreshProfile
			}
			adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
			before := len(adapter.calls)
			a.runDurableServiceJob(context.Background(), time.Now())
			if got := durableJobAt(t, a, job.ID); got.State != "failed" || got.DNSApplyCode != "DNS_APPLY_CHANGED" || len(adapter.calls) != before || a.DNS.VerifyServiceSelection("telegram", "private") != nil {
				t.Fatal("stale review reached runtime", got)
			}
		})
	}
}

func TestScopedDNSDurableRestartDoesNotReplayApplyAndCancellationStopsQueuedWork(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprint(cancel), func(t *testing.T) {
			a, r := scopedDNSJobFixture(t)
			job, err := a.enqueueDurableServiceJob(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if cancel {
				if _, err := a.cancelDurableServiceJob(context.Background(), job.ID); err != nil {
					t.Fatal(err)
				}
			}
			b := &App{Store: a.Store}
			b.reconciler.started = true
			b.reconciler.path = a.Store.AutomationStatePath()
			if err := b.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := durableJobAt(t, b, job.ID)
			if cancel {
				if got.State != "canceled" {
					t.Fatal(got)
				}
			} else if got.State != "failed" || got.DNSApplyCode != "DNS_APPLY_CHANGED" {
				t.Fatal("old review remains executable", got)
			}
		})
	}
}

func TestScopedDNSDurableRemovalOfStoppedBindingNeedsNoNetwork(t *testing.T) {
	a := dnsRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	if out := a.executeServiceRuntime(context.Background(), "stop", a.Store.Get().Revision); out.Code != "" {
		t.Fatal(out)
	}
	a.FreshProfile = func(context.Context) (string, error) { return "", errors.New("offline") }
	a.Dataplane.FreshProfile = a.FreshProfile
	before := a.Store.Get()
	spec := scopedDNSApplySpec{Action: "remove"}
	_, binding, err := a.reviewScopedDNSApply(context.Background(), "telegram", before.Revision, spec)
	if err != nil {
		t.Fatal("offline removal", err)
	}
	spec.Digest = binding.review.Digest
	job, err := a.enqueueDurableServiceJob(context.Background(), serviceControlJobRequest{Kind: "dns-apply", ServiceIDs: []string{"telegram"}, ExpectedRevision: &before.Revision, DNSApply: &spec, IdempotencyKey: "discard-stopped-dns-request"})
	if err != nil {
		t.Fatal(err)
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	if got := durableJobAt(t, a, job.ID); got.State != "completed" || a.DNS.VerifyServiceSelection("telegram", "") != nil || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("discard altered stopped routes", got)
	}
}

func TestScopedDNSApplyHTTPRequiresAuthConfirmationAndReturnsDurableJob(t *testing.T) {
	a, r := scopedDNSJobFixture(t)
	a.Security, _ = security.NewGate(panelTestToken)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	q := scopedDNSApplyRequest{ServiceID: r.ServiceIDs[0], ExpectedRevision: r.ExpectedRevision, Spec: r.DNSApply, Confirm: "APPLY_SCOPED_DNS", IdempotencyKey: r.IdempotencyKey}
	data, _ := json.Marshal(q)
	for _, authorized := range []bool{false, true} {
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/dns/scoped/apply", strings.NewReader(string(data)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		if authorized {
			req.Header.Set("Authorization", "Bearer "+panelTestToken)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		wanted := http.StatusUnauthorized
		if authorized {
			wanted = http.StatusAccepted
		}
		if response.StatusCode != wanted {
			t.Fatalf("auth=%v status=%d", authorized, response.StatusCode)
		}
	}
	q.Confirm = ""
	data, _ = json.Marshal(q)
	req := httptest.NewRequest("POST", "/api/v1/dns/scoped/apply", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+panelTestToken)
	w := httptest.NewRecorder()
	a.scopedDNSApplyHTTP(w, req)
	if w.Code != 400 {
		t.Fatal("missing confirmation accepted", w.Code)
	}
}
