package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
)

func TestMihomoProbeAttemptTimingPreservesRefusalAndSkippedPhases(t *testing.T) {
	w := httptest.NewRecorder()
	revision := uint64(1)
	(&App{}).probeMihomo(w, httptest.NewRequest("POST", "/", nil), "private://password@server", backendprofile.MihomoOptions{}, "private-review", "private-service", &revision)
	var response struct {
		Code    string                    `json:"code"`
		Timing  *mihomoProbeAttemptTiming `json:"timing"`
		Service bool                      `json:"service_verified"`
		Live    bool                      `json:"live_applied"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 409 || response.Code != "MIHOMO_SERVICE_PROBE_UNCONFIRMED" || response.Service || response.Live || response.Timing == nil {
		t.Fatal("diagnostics changed refusal", w.Code, w.Body.String())
	}
	timing := response.Timing
	if timing.HandlerElapsedMS < timing.PreparationMS || timing.PreparationMS < 0 || timing.AdapterCheckMS != nil || timing.PostcheckMS != nil || timing.FinalizeMS != nil {
		t.Fatal("unattempted phases reported as measured", timing)
	}
	if strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "password") {
		t.Fatal("request material leaked into timing response")
	}
}

func TestMihomoProbeFailureTimingWaitsForFinalizeAndRetainsError(t *testing.T) {
	for _, failedPhase := range []string{"adapter", "finalize"} {
		t.Run(failedPhase, func(t *testing.T) {
			timing := &mihomoProbeAttemptTiming{started: time.Now()}
			timing.finishPreparation()
			primary := errors.New("private endpoint/password")
			calls := 0
			checkErr := measureMihomoProbePhase(&timing.AdapterCheckMS, func() error {
				calls++
				if failedPhase == "adapter" {
					return primary
				}
				return nil
			})
			finalized := false
			closeErr := measureMihomoProbePhase(&timing.FinalizeMS, func() error {
				calls++
				time.Sleep(3 * time.Millisecond)
				finalized = true
				if failedPhase == "finalize" {
					return primary
				}
				return nil
			})
			if calls != 2 || !finalized || failedPhase == "adapter" && checkErr != primary || failedPhase == "finalize" && closeErr != primary {
				t.Fatal("measurement replaced the original operation or its error")
			}
			w := httptest.NewRecorder()
			writeMihomoProbeFailure(w, closeErr != nil, timing)
			var body struct {
				Code     string                    `json:"code"`
				Pending  bool                      `json:"recovery_required"`
				Verified bool                      `json:"service_verified"`
				Timing   *mihomoProbeAttemptTiming `json:"timing"`
			}
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != 409 || body.Verified || body.Pending != (failedPhase == "finalize") {
				t.Fatal("failed phase changed admission", w.Body.String())
			}
			if body.Timing == nil || body.Timing.FinalizeMS == nil || *body.Timing.FinalizeMS < 3 || body.Timing.AdapterCheckMS == nil || body.Timing.PostcheckMS != nil || body.Timing.HandlerElapsedMS < *body.Timing.FinalizeMS {
				t.Fatal("failure lost measured finalization or invented skipped phase", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "password") {
				t.Fatal("error text leaked into timing")
			}
		})
	}
}

func TestMihomoRecoveryResponseDoesNotInventProbeTiming(t *testing.T) {
	w := httptest.NewRecorder()
	writeMihomoProbeFailure(w, true)
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "timing") {
		t.Fatal("separate recovery response acquired an unobserved probe timing", w.Body.String())
	}
}
