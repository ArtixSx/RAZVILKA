package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func admissionRequest(a *App, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader("{}")))
	return w
}

func TestOperatorActionWaitsForBusyGateThenRuns(t *testing.T) {
	a := &App{AdmissionPatience: 5 * time.Second}
	release, err := a.Operations.Exclusive(operationgate.WithLabel(context.Background(), "автопилот: проверка сервисов и подписок"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(300 * time.Millisecond); release() }()
	started := time.Now()
	// Components is nil, so an admitted plan request answers 503 from the
	// handler itself; a refused one would be 409 from admission.
	w := admissionRequest(a, http.MethodGet, "/api/v1/components/xray/plan?action=install")
	if w.Code != http.StatusServiceUnavailable || time.Since(started) < 250*time.Millisecond {
		t.Fatalf("plan was not admitted after the busy operation ended: %d %s", w.Code, w.Body.String())
	}
}

func TestBusyRefusalNamesTheRunningOperation(t *testing.T) {
	a := &App{AdmissionPatience: 400 * time.Millisecond}
	release, err := a.Operations.Exclusive(operationgate.WithLabel(context.Background(), "автопилот: проверка сервисов и подписок"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	started := time.Now()
	w := admissionRequest(a, http.MethodPost, "/api/v1/unknown")
	var body struct {
		Code      string `json:"code"`
		Error     string `json:"error"`
		Operation struct {
			Label string `json:"label"`
		} `json:"operation"`
	}
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != "RESTORE_OPERATION_BUSY" {
		t.Fatalf("busy refusal: %d %s", w.Code, w.Body.String())
	}
	if body.Operation.Label != "автопилот: проверка сервисов и подписок" || !strings.Contains(body.Error, "автопилот: проверка сервисов и подписок") {
		t.Fatalf("refusal does not name the operation: %s", w.Body.String())
	}
	if elapsed := time.Since(started); elapsed < 350*time.Millisecond {
		t.Fatalf("operator action did not wait: %s", elapsed)
	}
}

func TestReadsAndStatusDoNotWaitLong(t *testing.T) {
	a := &App{AdmissionPatience: 20 * time.Second}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	started := time.Now()
	if w := admissionRequest(a, http.MethodGet, "/api/v1/unknown"); w.Code != http.StatusConflict {
		t.Fatalf("read = %d", w.Code)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("read waited %s", elapsed)
	}
	started = time.Now()
	if w := admissionRequest(a, http.MethodGet, "/api/v1/status"); w.Code != http.StatusConflict {
		t.Fatalf("status = %d", w.Code)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("status waited %s", elapsed)
	}
}

func TestPlanPreviewInterruptsBackgroundAutomation(t *testing.T) {
	a := &App{}
	canceled := false
	a.reconciler.started = true
	a.reconciler.cancel = func() { canceled = true }
	a.interruptAutomation(httptest.NewRequest(http.MethodGet, "/api/v1/components/xray/plan?action=install", nil))
	if !canceled {
		t.Fatal("plan preview did not interrupt automation")
	}
	canceled = false
	a.interruptAutomation(httptest.NewRequest(http.MethodGet, "/api/v1/components", nil))
	if canceled {
		t.Fatal("a periodic read interrupted automation")
	}
}
