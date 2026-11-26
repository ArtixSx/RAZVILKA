package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This models the metadata boundary after beginHealthCheck; it supplies no
// native process, reader admission, service evidence or cleanup authority.
func mihomoCheckingRotationModel(t *testing.T) (*mihomoLiveResource, context.Context, context.CancelFunc) {
	t.Helper()
	m, _, r, _ := mihomoLiveRecordModel(t)
	if err := m.retainOriginalMihomo(r.scope, false); err != nil {
		t.Fatal(err)
	}
	r.historyAdmission = &updatecheck.ExecutionHistoryAdmission{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	o := &mihomoLiveOperation{owner: r, forward: true}
	o.self = o
	o.open.Store(true)
	ctx = r.scope.contextWith(context.WithValue(ctx, mihomoLiveOperationKey{}, o))
	// The real Check performs this rotation while still committed, before it
	// admits reader9 and creates the original checking cursor.
	if err := r.rotateMihomoTransit(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(r.scope.execution)
	if err != nil {
		t.Fatal(err)
	}
	h := ExecutionMihomoLiveHealthOperation{Schema: 1, ID: strings.Repeat("b", 64), PlanID: r.scope.execution.PlanID, PlanDigest: r.scope.execution.Digest, BeforeSHA256: nodeDefaultSourceMaterialHash(before), Phase: "checking"}
	c := &mihomoLiveHealthCheck{owner: r, open: true, before: before, header: h, cleanup: &operationgate.ExclusiveCleanupReview{}}
	c.self = c
	r.healthCheck = c
	r.scope.execution.State, r.scope.execution.FinishedAt = mihomoActiveCheckingState, ""
	r.scope.execution.MihomoLiveHealthOperation = &h
	return r, ctx, cancel
}

func TestMihomoRetainedCheckDefersRepeatedRotation(t *testing.T) {
	r, ctx, _ := mihomoCheckingRotationModel(t)
	before, _ := json.Marshal(r.scope.execution)
	c := r.healthCheck
	// currentLiveObserved bookends real probes with these two calls while
	// CheckMihomoLive still owns the same active-checking cursor.
	for range 2 {
		if err := r.rotateMihomoTransit(ctx); err != nil {
			t.Fatal("original health check rejected its own repeated rotation", err)
		}
	}
	after, _ := json.Marshal(r.scope.execution)
	if string(before) != string(after) || r.healthCheck != c || r.transitHistory != nil || r.scope.pending {
		t.Fatal("rotation deferral changed the original check or journal")
	}
}

func TestMihomoRetainedCheckRotationRejectsLostCustody(t *testing.T) {
	for _, name := range []string{"missing", "copied", "foreign", "closed", "failed", "stopping", "publishing", "cleanup", "header", "unknown-state", "pending", "canceled"} {
		t.Run(name, func(t *testing.T) {
			r, ctx, cancel := mihomoCheckingRotationModel(t)
			switch name {
			case "missing":
				r.healthCheck = nil
			case "copied":
				copy := *r.healthCheck
				r.healthCheck = &copy
			case "foreign":
				r.healthCheck.owner = &mihomoLiveResource{}
			case "closed":
				r.healthCheck.open = false
			case "failed":
				r.healthCheck.failed = true
			case "stopping":
				r.healthCheck.stopping = true
			case "publishing":
				r.healthCheck.publishing = true
			case "cleanup":
				r.healthCheck.cleanup = nil
			case "header":
				r.scope.execution.MihomoLiveHealthOperation.ID = strings.Repeat("c", 64)
			case "pending":
				r.scope.pending = true
			case "unknown-state":
				r.scope.execution.State = "unknown"
			case "canceled":
				cancel()
			}
			if err := r.rotateMihomoTransit(ctx); err == nil {
				t.Fatal("lost original checking custody accepted")
			}
		})
	}
}

func TestMihomoRetainedCheckFullCohortStillRequiresReaderAdmission(t *testing.T) {
	r, ctx, _ := mihomoCheckingRotationModel(t)
	_, archive, _, _ := mihomoTransitArchiveOwnerFixture(t)
	r.scope.execution.State = "committed"
	r.scope.execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.scope.execution.MihomoLiveHealthOperation = nil
	r.healthCheck = nil
	for _, row := range archive.Resources {
		r.scope.execution.Resources = append(r.scope.execution.Resources, row)
		r.scope.issued[row.ID] = &executionTransitResource{finished: true, admitted: true, spec: *row.NodeTransit, digest: row.Generation, effects: row.EffectsDigest}
	}
	before, _ := json.Marshal(r.scope.execution)
	// The empty modeled admission cannot admit reader8. Deferring rotation
	// inside a check must not bypass this gate before the next check starts.
	if err := r.rotateMihomoTransit(ctx); !errors.Is(err, updatecheck.ErrExecutionHistoryAdmission) {
		t.Fatal("full committed cohort did not reach its existing reader gate", err)
	}
	after, _ := json.Marshal(r.scope.execution)
	if string(before) != string(after) || r.transitHistory != nil || r.scope.pending || r.healthCheck != nil {
		t.Fatal("refused archive admission changed original custody")
	}
}
