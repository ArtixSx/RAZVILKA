package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestManagedXrayReviewBudgetKeepsEarlierCallerAndOriginalAdmission(t *testing.T) {
	a := &App{}
	type marker struct{}
	parent, cancelParent := context.WithTimeout(context.WithValue(context.Background(), marker{}, "original"), 2*time.Minute)
	defer cancelParent()
	owned, release, err := a.Operations.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	started := time.Now()
	review, cancelReview := managedXrayReviewContext(owned)
	defer cancelReview()
	deadline, _ := review.Deadline()
	if horizon := deadline.Sub(started); horizon < 59*time.Second || horizon > 61*time.Second || review.Value(marker{}) != "original" {
		t.Fatal("whole-review cap or original caller values changed", horizon)
	}
	if err := a.Operations.WithExclusiveContext(review, func() error { return nil }); err != nil || a.Operations.Snapshot().Active != 1 {
		t.Fatal("review did not retain the same actual admission", err)
	}
	// Comparison DTOs exercise response completion, never native admission.
	wantPlan, wantReview := dataplane.Plan{PlanID: "comparison-only"}, applyReview{Revision: 7, Digest: "comparison-only"}
	plan, result, err := managedXrayCompleteReview(review, "final-check", wantPlan, wantReview, nil)
	if err != nil || !reflect.DeepEqual(plan, wantPlan) || result != wantReview {
		t.Fatal("live completion changed its original comparison result", err)
	}
	short, cancelShort := context.WithTimeout(owned, 20*time.Millisecond)
	defer cancelShort()
	bounded, end := managedXrayReviewContext(short)
	defer end()
	shortDeadline, _ := short.Deadline()
	actualDeadline, _ := bounded.Deadline()
	if actualDeadline != shortDeadline {
		t.Fatal("60s cap extended an earlier caller deadline")
	}
	<-bounded.Done()
	if err := a.Operations.WithExclusiveContext(bounded, func() error { t.Error("expired review entered"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("earlier deadline did not fence original admission", err)
	}
	plan, result, err = managedXrayCompleteReview(bounded, "final-check", wantPlan, wantReview, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(plan, dataplane.Plan{}) || result != (applyReview{}) {
		t.Fatal("earlier deadline escaped final response completion")
	}
	cancelParent()
	if err := a.Operations.WithExclusiveContext(review, func() error { t.Error("canceled review entered"); return nil }); !errors.Is(err, context.Canceled) || a.Operations.Snapshot().Active != 1 {
		t.Fatal("cancellation revived or released original admission", err)
	}
}

// The shared fixture uses actual Store/control/node/source/registration/Gate;
// physical/WAN and the recorded check are explicit models. No native grant,
// runtime process, packet or router success is claimed by these unit tests.
func TestManagedXrayReviewBudgetCannotReviveExpiredCanceledOrReleasedSource(t *testing.T) {
	for _, failure := range []string{"deadline", "cancel", "released-owner"} {
		t.Run(failure, func(t *testing.T) {
			f := newListXraySourceFixture(t, "xray")
			parent, cancelParent := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelParent()
			owned, release, err := f.a.Operations.ExclusiveContext(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			sourceCaller, end := managedXrayReviewContext(owned)
			defer end()
			if failure == "deadline" {
				var expire context.CancelFunc
				sourceCaller, expire = context.WithTimeout(sourceCaller, 300*time.Millisecond)
				defer expire()
			}
			source := f.review(t, sourceCaller)
			defer source.Close()
			switch failure {
			case "deadline":
				<-sourceCaller.Done()
			case "cancel":
				end()
			case "released-owner":
				release()
				owned, release, err = f.a.Operations.ExclusiveContext(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			fresh, finish := managedXrayReviewContext(owned)
			defer finish()
			if fresh.Err() != nil || source.Current(fresh) == nil || source.Current(fresh) == nil {
				t.Fatal("larger fresh caller revived an expired/revoked original source")
			}
		})
	}
}

func TestManagedXrayReviewBudgetKeepsExactNodeProofExpiry(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(owned context.Context) {
		ctx, cancel := managedXrayReviewContext(owned)
		defer cancel()
		checked := time.Now().UTC()
		check := nodestore.CheckRecord{ProbeID: "budget-expiry", ServiceID: "listed", NetworkProfile: f.physical.network, RoutePathID: "xray:" + f.nodeID,
			TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: checked, ExpiresAt: checked.Add(500 * time.Millisecond)}
		if _, err := f.a.Nodes.RecordCheck(ctx, f.nodeID, check, checked); err != nil {
			t.Fatal(err)
		}
		source := f.review(t, ctx)
		proof, err := dataplane.ReviewNodeServiceProof(ctx, source.node, source.frozen, source.wan)
		if err != nil {
			t.Fatal(err)
		}
		defer proof.Close()
		ref, err := proof.Observation(ctx)
		if err != nil || !ref.ExpiresAt.Equal(check.ExpiresAt) {
			t.Fatal("original check expiry changed", err)
		}
		timer := time.NewTimer(time.Until(ref.ExpiresAt))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("original operation ended before the check expiry")
		}
		fresh, finish := managedXrayReviewContext(owned)
		defer finish()
		if ctx.Err() != nil || !errors.Is(proof.Current(fresh), dataplane.ErrNodeServiceProof) || proof.Current(fresh) == nil {
			t.Fatal("larger caller horizon extended/revived original exact node proof")
		}
	})
}

func TestManagedXrayReviewBudgetCancellationJoinsBeforeAdmissionRelease(t *testing.T) {
	out := captureXrayDiagnosticLog(t)
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(owned context.Context) {
		ctx, cancel := managedXrayReviewContext(owned)
		defer cancel()
		source := f.review(t, ctx)
		e := &managedXraySelectedTCPListExecution{source: source, scope: f.scope}
		e.self = e // Original handles for Close only; no runtime admission.
		entered, canceled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
		original := f.scope.verifyPhysical
		f.scope.verifyPhysical = func(c context.Context) error { close(entered); <-c.Done(); close(canceled); <-finish; return c.Err() }
		defer func() { f.scope.verifyPhysical = original }()
		readDone, closeDone := make(chan error, 1), make(chan error, 1)
		go func() { readDone <- source.Current(ctx) }()
		select {
		case <-entered:
		case <-owned.Done():
			t.Fatal("original read did not enter")
		}
		cancel()
		go func() { closeDone <- e.close() }()
		select {
		case <-canceled:
		case <-owned.Done():
			t.Fatal("caller cancel did not stop original reader")
		}
		select {
		case <-closeDone:
			t.Fatal("Close escaped before original read joined")
		default:
		}
		if f.a.Operations.Snapshot().Active != 1 || f.physical.closes != 0 {
			t.Fatal("cancel released admission or retired physical owner before join")
		}
		if _, release, err := f.a.Operations.ExclusiveContext(owned); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatal("another operation overlapped original cleanup", err)
		}
		close(finish)
		if err := <-readDone; err == nil {
			t.Fatal("canceled original read succeeded")
		}
		if err := <-closeDone; err != nil || f.physical.closes != 1 || f.a.Operations.Snapshot().Active != 1 {
			t.Fatal("original source/scope cleanup did not join under retained admission", err)
		}
		// These are detached comparison DTOs, not issued native permissions.
		plan, review, err := managedXrayCompleteReview(ctx, "final-check", dataplane.Plan{PlanID: "comparison-only", Ready: true}, applyReview{Revision: 7, Digest: "comparison-only"}, nil)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(plan, dataplane.Plan{}) || review != (applyReview{}) {
			t.Fatal("joined exit accepted a post-cancel review")
		}
	})
	text := out.String()
	first := strings.Index(text, "Managed Xray review close stage=source-close cause=none elapsed_ms=")
	second := strings.Index(text, "Managed Xray review close stage=scope-close cause=none elapsed_ms=")
	if first < 0 || second <= first {
		t.Fatal("closed source/scope durations missing or reordered", text)
	}
}

func TestManagedXrayReviewBudgetKeepsStickyRevocationAndPrivateExitErrors(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(owned context.Context) {
		ctx, cancel := managedXrayReviewContext(owned)
		defer cancel()
		source := f.review(t, ctx)
		f.physical.verifyErr = errors.New("private modeled drift")
		if source.Current(ctx) == nil {
			t.Fatal("actual original source accepted physical revocation")
		}
		f.physical.verifyErr = nil
		fresh, finish := managedXrayReviewContext(owned)
		defer finish()
		if source.Current(fresh) == nil {
			t.Fatal("restored physical tuple/larger budget revived sticky source")
		}
	})
	out := captureXrayDiagnosticLog(t)
	logManagedXrayReviewClose("private/path/node", time.Hour, xrayDiagnosticPrivateError{})
	if out.String() != "Managed Xray review close stage=unclassified cause=refused elapsed_ms=120000\n" {
		t.Fatal("cleanup diagnostic leaked or escaped closed fields", out.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	initial, cleanup := errors.New("original refusal"), errors.New("original cleanup refusal")
	_, _, err := managedXrayCompleteReview(ctx, "cleanup", dataplane.Plan{}, applyReview{}, errors.Join(initial, cleanup))
	if !errors.Is(err, initial) || !errors.Is(err, cleanup) || !errors.Is(err, context.Canceled) {
		t.Fatal("exit completion lost joined original failures")
	}
}
