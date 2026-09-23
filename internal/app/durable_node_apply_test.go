package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func durableNodeAccept(t *testing.T, a *App, id string, review nodeRouteReview, key string) durableServiceJob {
	t.Helper()
	body := nodeApplyBody(review)
	body["idempotency_key"] = key
	w := nodeRouteRequest(a, id, "apply", body, "owner-a", context.Background())
	return acceptedNodeJob(t, a, w)
}

func acceptedNodeJob(t *testing.T, a *App, w *httptest.ResponseRecorder) durableServiceJob {
	t.Helper()
	var response struct {
		Job        nodeCheckJob
		Persistent bool
	}
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.Persistent || response.Job.Mode != "service-node-apply" {
		t.Fatalf("not accepted: %d %s", w.Code, w.Body.String())
	}
	return durableJobAt(t, a, response.Job.ID)
}

func TestDurableNodeApplyLostResponseTwoWindowsAndClosedRequest(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	initReconcilerFixture(t, a, time.Now())
	before := a.Store.Get()
	review := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40/32"}})
	secondReview := reviewedNodeScope(t, a, id, &nodeScopeSelection{Mode: "selected", Sources: []string{"192.168.1.40/32"}})
	ctx, cancel := context.WithCancel(context.Background())
	body := nodeApplyBody(review)
	body["idempotency_key"] = "node-request-lost-response"
	job := acceptedNodeJob(t, a, nodeRouteRequest(a, id, "apply", body, "owner-a", ctx))
	cancel() // The accepted transaction no longer belongs to this HTTP request.
	if !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 || len(a.nodeReviews.reviews) != 1 {
		t.Fatal("acceptance applied or lost the other review")
	}
	raw, err := os.ReadFile(a.reconciler.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{review.Token, "owner-a", "private.example", "vless://", "123e4567", "node-request-lost-response"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("durable record leaked a credential/token")
		}
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	adapter.after = func(phase string) error {
		if phase == "activate" {
			close(entered)
			<-release
		}
		return nil
	}
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(finished) }()
	awaitOperation(t, entered)
	for _, pair := range []struct {
		review nodeRouteReview
		key    string
	}{{review, "node-request-lost-response"}, {secondReview, "node-request-second-window"}} {
		if got := durableNodeAccept(t, a, id, pair.review, pair.key); got.ID != job.ID {
			t.Fatal("in-flight retry duplicated transaction")
		}
	}
	if a.reconciler.doc.ManualUntil.After(time.Now()) {
		t.Fatal("retry canceled or delayed its own worker")
	}
	close(release)
	awaitOperation(t, finished)
	got := durableJobAt(t, a, job.ID)
	if got.State != "completed" || got.CleanupOutcome != "joined" || !a.Store.Get().AppliedServices["telegram"].Enabled {
		t.Fatal(got)
	}
	after := a.Store.Get()
	if !reflect.DeepEqual(before.Services["youtube"], after.Services["youtube"]) || !slices.Equal(after.AppliedServices["telegram"].Sources, []string{"192.168.1.40/32"}) {
		t.Fatal("scoped commit consumed unrelated edits")
	}
	calls := len(adapter.calls)
	if retry := durableNodeAccept(t, a, id, review, "node-request-lost-response"); retry.ID != job.ID || retry.State != "completed" || len(adapter.calls) != calls {
		t.Fatal("completed retry replayed")
	}
}

func TestDurableNodeApplyCancelJoinsRollbackAndOldCancelDoesNotAffectNext(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	initReconcilerFixture(t, a, time.Now())
	before := a.Store.Get()
	job := durableNodeAccept(t, a, id, reviewedNode(t, a, id), "node-cancel-joined-request")
	entered, cleanup, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	adapter.after = func(phase string) error {
		if phase == "activate" {
			close(entered)
			<-cleanup
		}
		return nil
	}
	go func() { a.runDurableServiceJob(context.Background(), time.Now()); close(finished) }()
	awaitOperation(t, entered)
	if ok, err := a.cancelDurableServiceJob(context.Background(), job.ID); !ok || err != nil {
		t.Fatal(err)
	}
	if got := durableJobAt(t, a, job.ID); got.State != "canceling" {
		t.Fatal(got)
	}
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cleanup admission released early")
	}
	close(cleanup)
	awaitOperation(t, finished)
	if got := durableJobAt(t, a, job.ID); got.State != "canceled" || got.CleanupOutcome != "joined" || !slices.Contains(adapter.calls, "rollback") || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("cancel did not join rollback", got, adapter.calls)
	}
	adapter.after = nil
	next := durableNodeAccept(t, a, id, reviewedNode(t, a, id), "node-cancel-new-request")
	_, _ = a.cancelDurableServiceJob(context.Background(), job.ID)
	if durableJobAt(t, a, next.ID).CancelRequested {
		t.Fatal("old cancel revoked new action")
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	if durableJobAt(t, a, next.ID).State != "completed" {
		t.Fatal("new action did not finish")
	}
}

func TestDurableNodeApplyRejectsChangedIntentBeforeRuntime(t *testing.T) {
	for _, change := range []string{"config", "definition", "network", "expiry", "scope", "generation"} {
		t.Run(change, func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			initReconcilerFixture(t, a, time.Now())
			job := durableNodeAccept(t, a, id, reviewedNode(t, a, id), "node-changed-intent-1")
			switch change {
			case "config":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "definition":
				a.Catalog.Services[0].Domains = []string{"changed.example"}
			case "network":
				a.FreshProfile = func(context.Context) (string, error) { return "wan-aaaaaaaaaaaa", nil }
			case "expiry":
				a.reconciler.doc.Jobs[0].NodeReview.ExpiresAt = time.Now().Add(-time.Second)
			case "scope":
				a.reconciler.doc.Jobs[0].NodeReview.Sources = []string{"192.168.1.44/32"}
			case "generation":
				a.reconciler.doc.Jobs[0].Request.NodeApply.Generation++
			}
			before := a.Store.Get()
			a.runDurableServiceJob(context.Background(), time.Now())
			if got := durableJobAt(t, a, job.ID); got.State != "failed" || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("stale intent activated", got, adapter.calls)
			}
		})
	}
}

func TestDurableNodeApplyRestartNeverReplaysQueuedOrAmbiguousCommit(t *testing.T) {
	for _, phase := range []string{"queued", "running", "committed"} {
		t.Run(phase, func(t *testing.T) {
			a, id, adapter := nodeApplyFixture(t)
			initReconcilerFixture(t, a, time.Now())
			job := durableNodeAccept(t, a, id, reviewedNode(t, a, id), "node-startup-replay-test")
			if phase != "queued" {
				a.reconciler.doc.Jobs[0].State = "running"
			}
			if phase == "committed" {
				r := job.Request
				r.intentHash = job.IntentHash
				out, err := a.runDurableNodeApply(context.Background(), r, job.NodeReview)
				if err != nil || out.Code != "" {
					t.Fatal(out, err)
				}
			}
			if err := a.persistReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			calls := len(adapter.calls)
			b := &App{Store: a.Store, Dataplane: a.Dataplane, Nodes: a.Nodes, Catalog: a.Catalog, FreshProfile: a.FreshProfile}
			b.reconciler.started, b.reconciler.path = true, a.reconciler.path
			if err := b.loadReconcilerLocked(context.Background()); err != nil {
				t.Fatal(err)
			}
			b.runDurableServiceJob(context.Background(), time.Now().Add(time.Minute))
			if got := durableJobAt(t, b, job.ID); got.State != "failed" || got.NodeCode != "NODE_REVIEW_CHANGED" || len(adapter.calls) != calls {
				t.Fatal("restart replayed review", got)
			}
		})
	}
}

func TestDurableNodeApplyInvalidReviewCannotEnterGenericQueue(t *testing.T) {
	a, id, _ := nodeApplyFixture(t)
	initReconcilerFixture(t, a, time.Now())
	review := reviewedNode(t, a, id)
	body := nodeApplyBody(review)
	body["idempotency_key"] = "node-auth-review-test"
	w := nodeRouteRequest(a, id, "apply", body, "wrong-owner", context.Background())
	if w.Code != 409 || len(a.reconciler.doc.Jobs) != 0 || len(a.nodeReviews.reviews) != 1 {
		t.Fatal("wrong review owner accepted")
	}
	request := serviceControlJobRequest{Kind: "node-apply", ServiceIDs: []string{"telegram"}, NodeIDs: []string{id}, ExpectedRevision: &review.Revision, NodeApply: &nodeApplyJobSpec{Digest: review.Digest, Generation: review.Generation}, IdempotencyKey: "node-unreviewed-generic"}
	w = controlRequest(a, "POST", "/api/v1/service-control/jobs", request)
	if w.Code != 400 || len(a.reconciler.doc.Jobs) != 0 {
		t.Fatalf("generic endpoint accepted application: %d", w.Code)
	}
	request.Kind = "stop"
	request.ServiceIDs = nil
	request.NodeIDs = nil
	if validDurableRequest(request) {
		t.Fatal("runtime action carried hidden node apply")
	}
}

func TestDurableNodeApplyStorageFailureRetainsReviewAndRollbackFailureFences(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	initReconcilerFixture(t, a, time.Now())
	review := reviewedNode(t, a, id)
	path := a.reconciler.path
	a.reconciler.path = path + "/invalid-child"
	body := nodeApplyBody(review)
	body["idempotency_key"] = "node-storage-failure-1"
	w := nodeRouteRequest(a, id, "apply", body, "owner-a", context.Background())
	if w.Code != 503 || len(a.reconciler.doc.Jobs) != 0 || len(a.nodeReviews.reviews) != 1 || len(adapter.calls) != 0 {
		t.Fatal("storage failure accepted work or consumed review", w.Code)
	}
	a.reconciler.path, a.reconciler.blocked = path, false
	job := durableNodeAccept(t, a, id, review, "node-storage-failure-1")
	adapter.after = func(phase string) error {
		if phase == "activate" || phase == "rollback" {
			return errors.New("deliberate runtime failure")
		}
		return nil
	}
	a.runDurableServiceJob(context.Background(), time.Now())
	got := durableJobAt(t, a, job.ID)
	if got.State != "failed" || got.Reason != "cleanup-unverified" || got.CleanupOutcome != "unverified" || !a.Operations.Snapshot().Fenced {
		t.Fatal("failed rollback reported joined or allowed another apply", got)
	}
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrRecovery) {
		if release != nil {
			release()
		}
		t.Fatal("failed rollback did not fence")
	}
}
