package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func durableCatalogRequest(t *testing.T, a *App) nodeCheckJobRequest {
	t.Helper()
	q := allBulkRequest(t, a)
	revision := a.Store.Get().Revision
	q.ExpectedRevision, q.IdempotencyKey = &revision, "durable-full-catalogue-001"
	return q
}

func TestDurableCatalogueFreezesAllPagesAndRetriesAfterHealthMutation(t *testing.T) {
	a, _ := durableNodeFixture(t, 83)
	q := durableCatalogRequest(t, a)
	before := a.Store.Get()
	id := enqueueNodeFixture(t, a, q)
	j := durableJobAt(t, a, id)
	if len(j.Request.NodeIDs) != 83 || j.Request.NodeCatalog.Matched != 83 || j.presentation().Scope != allVLESSScope {
		t.Fatal("catalogue truncated", j.presentation())
	}
	frozen := slices.Clone(j.Request.NodeIDs)
	var calls []string
	a.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		calls = append(calls, r.NodeID)
		return bulkTestResult(r), nil
	})
	a.runDurableServiceJob(context.Background(), time.Now())
	// A health write advances generation. Retrying the accepted selector must
	// still succeed while another operation holds admission.
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if enqueueNodeFixture(t, a, q) != id {
		t.Fatal("health update duplicated catalogue job")
	}
	q.IdempotencyKey = "durable-full-second-window"
	if enqueueNodeFixture(t, a, q) != id {
		t.Fatal("second window duplicated catalogue job")
	}
	release()
	_, err = a.Nodes.Import(context.Background(), nodestore.Source{ID: "later", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@later.example:443?security=tls#later", time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Nodes.SetDisabled(context.Background(), frozen[1], true, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 166 && !durableJobAt(t, a, id).terminal(); i++ {
		if i == 10 {
			// A scheduled service check uses the common activity slot during a
			// yield. It must not discard this batch's process-local aggregates.
			a.nodeChecks.mu.Lock()
			a.nodeChecks.job = &nodeCheckJob{ID: 999, Mode: "service-check", State: "completed", StartedAt: time.Now()}
			a.nodeChecks.mu.Unlock()
		}
		a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
	}
	j = durableJobAt(t, a, id)
	p := a.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.State != "completed" || p.Completed != 83 || p.Total != 83 || p.Passed != 82 || p.Skipped != 1 || len(p.Results) != 64 || len(calls) != 82 {
		t.Fatalf("catalogue summary: state=%s reason=%s blocked=%t worker=%s completed=%d total=%d passed=%d skipped=%d results=%d calls=%d", p.State, j.Reason, a.reconciler.blocked, a.nodeCheckSnapshot()["job"].(*nodeCheckJob).Message, p.Completed, p.Total, p.Passed, p.Skipped, len(p.Results), len(calls))
	}
	for _, called := range calls {
		if !slices.Contains(frozen, called) {
			t.Fatal("new import joined frozen job")
		}
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("catalogue check changed routes")
	}
	if enqueueNodeFixture(t, a, q) != id {
		t.Fatal("completed retry reran catalogue")
	}
	q.ServiceID = "different-service"
	if w := controlRequest(a, "POST", "/api/v1/node-checks", q); w.Code != 409 || !strings.Contains(w.Body.String(), "JOB_KEY_CONFLICT") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestDurableCatalogueRestartRetainsSelectionWithoutOldProof(t *testing.T) {
	a, _ := durableNodeFixture(t, 4)
	q := durableCatalogRequest(t, a)
	id := enqueueNodeFixture(t, a, q)
	a.runDurableServiceJob(context.Background(), time.Now())
	raw, err := os.ReadFile(a.Store.AutomationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), `"results"`) {
		t.Fatal("secret or old proof persisted")
	}
	b := &App{Store: a.Store, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile}
	b.StartNodeChecks(context.Background())
	t.Cleanup(func() { _ = b.WaitNodeChecks(context.Background()) })
	b.reconciler.started, b.reconciler.path = true, a.Store.AutomationStatePath()
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := range b.reconciler.doc.Operations {
		b.reconciler.doc.Operations[i].NextRun = time.Now().Add(time.Hour)
	}
	j := durableJobAt(t, b, id)
	p := b.nodeCheckCurrentView()["job"].(*nodeCheckJob)
	if j.Cursor != 0 || j.CheckNetwork != "" || p.Passed != 0 || len(p.Results) != 0 || p.Scope != allVLESSScope || p.Matched != 4 {
		t.Fatal("replayed prior proof", j, p)
	}
	b.NodeChecker = jobNodeChecker(func(ctx context.Context, r dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		if r.NodeID != j.Request.NodeIDs[0] {
			t.Error("did not restart fresh")
		}
		return bulkTestResult(r), nil
	})
	b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
	if durableJobAt(t, b, id).Cursor != 1 || enqueueNodeFixture(t, b, q) != id {
		t.Fatal("restart lost identity or frozen selector")
	}
	if found, err := b.cancelDurableServiceJob(context.Background(), id); !found || err != nil {
		t.Fatal(found, err)
	}
	if err := b.loadReconcilerLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if durableJobAt(t, b, id).State != "canceled" {
		t.Fatal("canceled catalogue resumed")
	}
}

func TestDurableCatalogueRejectsStaleAndMalformedSelectors(t *testing.T) {
	a, _ := durableNodeFixture(t, 2)
	q := durableCatalogRequest(t, a)
	q.Generation++
	w := controlRequest(a, "POST", "/api/v1/node-checks", q)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "NODE_CATALOG_CHANGED") || len(a.reconciler.doc.Jobs) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	q = durableCatalogRequest(t, a)
	for _, mutate := range []func(*nodeCheckJobRequest){func(q *nodeCheckJobRequest) { q.Mode = "tcp" }, func(q *nodeCheckJobRequest) { q.Confirm = "" }, func(q *nodeCheckJobRequest) { q.ExpectedRevision = nil }, func(q *nodeCheckJobRequest) { q.IdempotencyKey = "" }, func(q *nodeCheckJobRequest) { q.NodeIDs = []string{"node-invalid"} }} {
		bad := q
		mutate(&bad)
		if w := controlRequest(a, "POST", "/api/v1/node-checks", bad); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(a.reconciler.doc.Jobs) != 0 {
		t.Fatal("invalid catalogue persisted")
	}
}

func TestDurableCatalogueMaximumFitsBoundedJournal(t *testing.T) {
	a, _ := durableNodeFixture(t, 128)
	for page := 1; page < 4; page++ {
		profiles := make([]string, 128)
		for i := range profiles {
			profiles[i] = fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@page%d-node%d.example:443?security=tls", page, i)
		}
		if _, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: fmt.Sprintf("page-%d", page), Kind: "manual"}, strings.Join(profiles, "\n"), time.Now(), time.Hour, false); err != nil {
			t.Fatal(err)
		}
	}
	id := enqueueNodeFixture(t, a, durableCatalogRequest(t, a))
	j := durableJobAt(t, a, id)
	if len(j.Request.NodeIDs) != nodestore.MaxNodes {
		t.Fatal("maximum catalogue truncated")
	}
	raw, err := json.Marshal(a.reconciler.doc)
	if err != nil || len(raw) >= maxReconcilerBytes-(32<<10) {
		t.Fatal("catalogue exhausted reserved journal space", len(raw), err)
	}
	if err := validateDurableServiceJobs(a.reconciler.doc.Jobs); err != nil {
		t.Fatal(err)
	}
	// Persisted records must contain the frozen IDs, never an unresolved selector.
	j.Request.NodeIDs = nil
	if validDurableRequest(j.Request) {
		t.Fatal("unresolved catalogue accepted from disk")
	}
}

func TestDurableBatchObservationsBoundedAcrossJobs(t *testing.T) {
	a, q := durableNodeFixture(t, 1)
	var first uint64
	for i := 0; i < 6; i++ {
		q.IdempotencyKey = fmt.Sprintf("bounded-observation-%03d", i)
		id := enqueueNodeFixture(t, a, q)
		if i == 0 {
			first = id
		}
		for round := 0; round < 4 && !durableJobAt(t, a, id).terminal(); round++ {
			a.runDurableServiceJob(context.Background(), time.Now().Add(2*time.Second))
		}
		if durableJobAt(t, a, id).State != "completed" {
			t.Fatal("did not complete")
		}
	}
	observed := a.nodeBatchMemoryResults()
	if len(observed) != 4 {
		t.Fatal("unbounded results", len(observed))
	}
	if _, ok := observed[first]; ok {
		t.Fatal("old details not evicted")
	}
	for _, job := range a.nodeCheckCurrentView()["durable_jobs"].([]*nodeCheckJob) {
		if job.ID == first && (job.Passed != 0 || len(job.Results) != 0 || job.ResultState != "not-retained") {
			t.Fatal("evicted details invented from durable record")
		}
	}
}
