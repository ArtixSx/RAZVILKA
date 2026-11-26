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

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestServiceRuntimeObservationHasSeparateBoundedContext(t *testing.T) {
	a, _, _, _ := serviceRuntimeFixture(t)
	var freshness context.Context
	a.FreshProfile = func(ctx context.Context) (string, error) {
		freshness = ctx
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second {
			t.Fatal("result freshness lost its short bound")
		}
		return stableNodeProfile(ctx)
	}
	observations := 0
	a.Dataplane.FreshProfile = func(ctx context.Context) (string, error) {
		observations++
		deadline, ok := ctx.Deadline()
		if freshness == nil || freshness.Err() != context.Canceled || ctx.Err() != nil || !ok || time.Until(deadline) < 7*time.Second || time.Until(deadline) > 8*time.Second {
			t.Fatal("runtime inherited result freshness budget or lost its own bound")
		}
		return stableNodeProfile(ctx)
	}
	w := controlRequest(a, "GET", "/api/v1/service-control", nil)
	var view map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != http.StatusOK || observations == 0 {
		t.Fatalf("runtime observation not reached: status=%d error=%v", w.Code, err)
	}
	// The test transaction adapter cannot prove any real process. Extra time
	// must never turn its committed journal into a green running indicator.
	if view["runtime_state"] != "unknown" || view["running"] != false || view["can_stop"] != true || view["runtime_issue"].(map[string]any)["code"] != "UNAVAILABLE" {
		t.Fatal("missing live proof accepted or diagnostic omitted")
	}
}

func TestServiceRuntimeObservationReportsCallerTerminationWithoutSecrets(t *testing.T) {
	for _, code := range []string{"CANCELED", "TIMEOUT"} {
		t.Run(code, func(t *testing.T) {
			a, _, _, _ := serviceRuntimeFixture(t)
			var ctx context.Context
			var cancel context.CancelFunc
			if code == "CANCELED" {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			}
			cancel()
			request := httptest.NewRequest("GET", "/api/v1/service-control", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			// Exercise the handler after admission; the outer HTTP middleware
			// correctly rejects an already-canceled request with 408.
			a.serviceControl(w, request)
			var view map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != http.StatusOK {
				t.Fatalf("status=%d error=%v", w.Code, err)
			}
			if view["running"] != false || view["runtime_state"] != "unknown" || view["runtime_issue"].(map[string]any)["code"] != code {
				t.Fatal("caller termination ignored or falsely displayed running")
			}
		})
	}
	private := "vless://private-fixture@private-endpoint"
	issue, err := json.Marshal(serviceRuntimeIssue(errors.New(private)))
	if err != nil || strings.Contains(string(issue), private) || !strings.Contains(string(issue), "UNAVAILABLE") {
		t.Fatal("raw observation error exposed")
	}
}

func TestServiceRuntimeIssueClassifiesOnlySafeFixedMessages(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{dataplane.ErrNetworkChanged, "NETWORK_CHANGED"},
		{dataplane.ErrReviewChanged, "CONFIGURATION_CHANGED"},
		{errors.New("private command output"), "UNAVAILABLE"},
	} {
		if issue := serviceRuntimeIssue(tc.err); issue["code"] != tc.code || issue["message"] == "" || strings.Contains(issue["message"], tc.err.Error()) {
			t.Fatalf("unsafe or incorrect runtime issue: code=%s", issue["code"])
		}
	}
}
