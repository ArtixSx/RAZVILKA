package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

type xrayDiagnosticPrivateError struct{}

func (xrayDiagnosticPrivateError) Error() string { panic("private error text must not be read") }

type xrayDiagnosticCycle struct{ visits int }

func (*xrayDiagnosticCycle) Error() string { panic("cycle error text must not be read") }
func (e *xrayDiagnosticCycle) Unwrap() error {
	e.visits++
	return e
}

func TestManagedXrayReviewDiagnosticClosedStagesAndRetainedCauses(t *testing.T) {
	for _, stage := range []string{"target", "admission", "control", "prepare", "final-check", "cleanup"} {
		for _, state := range []string{"live", "canceled", "deadline"} {
			t.Run(stage+"/"+state, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				wantCause := "refused"
				switch state {
				case "canceled":
					cancel()
					wantCause = "canceled"
				case "deadline":
					var end context.CancelFunc
					ctx, end = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer end()
					wantCause = "deadline"
				}
				original := errors.New("private node ID, path, profile and network material")
				err := managedXrayReviewAt(stage, ctx, original)
				gotStage, gotCause := managedXrayReviewDiagnostic(err, "target")
				if gotStage != stage || gotCause != wantCause || !errors.Is(err, original) || ctx.Err() != nil && !errors.Is(err, ctx.Err()) || strings.Contains(err.Error(), "private node") {
					t.Fatal("typed diagnostic changed or leaked retained cause", gotStage, gotCause)
				}
				if managedXrayReviewAt(stage, ctx, nil) != nil {
					t.Fatal("diagnostic turned successful work into a context refusal")
				}
			})
		}
	}
}

func TestManagedXrayReviewDiagnosticJoinedCleanupOverridesStageWithoutLosingCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	initial := managedXrayReviewAt("prepare", ctx, ErrXrayListSource)
	cleanup := managedXrayReviewAt("cleanup", nil, ErrDefaultRouteCapability)
	err := errors.Join(initial, cleanup)
	stage, cause := managedXrayReviewDiagnostic(err, "target")
	if stage != "cleanup" || cause != "canceled" || !errors.Is(err, ErrXrayListSource) || !errors.Is(err, ErrDefaultRouteCapability) || !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup hid original refusal or cancellation", stage, cause)
	}
	stage, cause = managedXrayReviewDiagnostic(errors.Join(err, context.DeadlineExceeded), "target")
	if stage != "cleanup" || cause != "deadline" {
		t.Fatal("joined deadline category changed", stage, cause)
	}
}

func TestManagedXrayReviewDiagnosticUnknownAndCyclicErrorsStayClosed(t *testing.T) {
	var typedNil *managedXrayReviewFailure
	for _, err := range []error{xrayDiagnosticPrivateError{}, typedNil, &managedXrayReviewFailure{stage: "private/path/node-id", cause: xrayDiagnosticPrivateError{}}} {
		stage, cause := managedXrayReviewDiagnostic(err, "target")
		if stage != "target" || cause != "refused" {
			t.Fatal("unknown error manufactured a stage/category", stage, cause)
		}
	}
	stage, cause := managedXrayReviewDiagnostic(managedXrayReviewAt("private-secret", nil, xrayDiagnosticPrivateError{}), "private-secret")
	if stage != "admission" || cause != "refused" {
		t.Fatal("unknown boundary escaped allowlist", stage, cause)
	}
	cycle := &xrayDiagnosticCycle{}
	stage, cause = managedXrayReviewDiagnostic(cycle, "target")
	if stage != "target" || cause != "refused" || cycle.visits > 32 {
		t.Fatal("unknown error traversal was not bounded", stage, cause, cycle.visits)
	}
}

func TestManagedXrayReviewHTTPRetainsCodeAndEmitsOnlyClosedFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		started time.Time
		elapsed int64
	}{
		{"future", time.Now().Add(time.Hour), 0},
		{"past", time.Now().Add(-time.Hour), 120000},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeManagedXrayReviewError(w, managedXrayReviewAt("prepare", nil, xrayDiagnosticPrivateError{}), test.started)
			var body map[string]any
			if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 7 || body["ok"] != false || body["code"] != "XRAY_SELECTED_TCP_REVIEW_REFUSED" || body["service_health"] != "unverified" || body["review_stage"] != "prepare" || body["cause"] != "refused" || body["elapsed_ms"] != float64(test.elapsed) {
				t.Fatal("closed HTTP diagnostic contract changed", w.Body.String())
			}
		})
	}
	// Real target and review entry refusals need no copied runtime or fixture
	// authority. These calls exercise no Apply, process or native traffic.
	a := &App{}
	cfg := config.Config{NetworkPolicy: &config.NetworkPolicy{}, Services: map[string]config.ServiceState{"private-service-id": {Enabled: true, Route: "xray:node-private-id"}}}
	w := httptest.NewRecorder()
	if !a.managedXrayPlanHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/plan?scope=all", nil), cfg, changeScopeAll) {
		t.Fatal("original target refusal was not handled")
	}
	var body map[string]any
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["review_stage"] != "target" || body["cause"] != "refused" || strings.Contains(w.Body.String(), "private-") {
		t.Fatal("target HTTP boundary lost or leaked", w.Body.String())
	}
	var runtime *ManagedXraySelectedTCPListRuntime
	_, _, err := runtime.review(context.Background(), "private-service-id", changeScopeAll)
	stage, cause := managedXrayReviewDiagnostic(err, "target")
	if stage != "admission" || cause != "refused" || !errors.Is(err, ErrXrayListSource) {
		t.Fatal("original review refusal boundary lost", stage, cause)
	}
}
