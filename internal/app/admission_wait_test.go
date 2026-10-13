package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

type statusAdmissionTestKey struct{}

func statusAdmissionProbe(t *testing.T, a *App) (context.Context, <-chan struct{}) {
	t.Helper()
	attempted := make(chan struct{})
	var once sync.Once
	marker := new(int)
	if err := a.Operations.SetGuard(func(ctx context.Context) error {
		if ctx.Value(statusAdmissionTestKey{}) == marker {
			once.Do(func() { close(attempted) })
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), statusAdmissionTestKey{}, marker), attempted
}

func statusAdmissionFailure(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body struct {
		Code        string `json:"code"`
		NotStarted  bool   `json:"not_started"`
		LiveApplied bool   `json:"live_applied"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != code || !body.NotStarted || body.LiveApplied {
		t.Fatalf("status admission refusal: %d %s", w.Code, w.Body.String())
	}
}

// These tests call the actual middleware directly; no HTTP server, browser,
// runtime commands, Store writes or fabricated runtime receipt is involved.
func TestStatusAdmissionGraceJoinsShortReaderAndPublication(t *testing.T) {
	for _, kind := range []string{"shared", "publication"} {
		t.Run(kind, func(t *testing.T) {
			a := &App{AdmissionPatience: 20 * time.Second}
			ctx, attempted := statusAdmissionProbe(t, a)
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			var release func()
			var err error
			if kind == "shared" {
				release, err = a.Operations.Enter(context.Background())
			} else {
				release, err = a.Operations.ObserveExclusive(context.Background(), nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			var calls atomic.Int32
			var retained context.Context
			handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				retained = r.Context()
				if got, ok := retained.Deadline(); !ok || !got.Equal(deadline) {
					t.Error("admission grace replaced the original request lifetime")
				}
				// Once granted, the original owner survives beyond admission grace.
				if kind == "shared" {
					timer := time.NewTimer(150 * time.Millisecond)
					<-timer.C
				}
				borrowed, end, err := a.privateExclusiveOperation(retained)
				if err != nil {
					t.Error("granted status lost its original exclusive owner", err)
					return
				}
				defer end()
				if err := a.Operations.WithExclusiveContext(borrowed, func() error { return nil }); err != nil {
					t.Error("same exclusive context was not retained", err)
				}
				if snapshot := a.Operations.Snapshot(); snapshot.Active != 1 || !snapshot.Exclusive {
					t.Error("status created an additional admission", snapshot)
				}
				w.WriteHeader(http.StatusOK)
			}))
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx))
			}()
			<-attempted
			if calls.Load() != 0 {
				t.Fatal("handler ran before its initial admission was granted")
			}
			release()
			<-done
			if w.Code != http.StatusOK || calls.Load() != 1 {
				t.Fatalf("short %s was not joined: %d, calls=%d", kind, w.Code, calls.Load())
			}
			if a.Operations.Snapshot().Active != 0 {
				t.Fatal("status leaked its request admission")
			}
			if err := a.Operations.WithExclusiveContext(retained, func() error { return nil }); !errors.Is(err, operationgate.ErrBusy) {
				t.Fatal("completed status context revived", err)
			}
		})
	}
}

func TestStatusAdmissionGraceKeepsLongWriterAndDefaultImmediate(t *testing.T) {
	for _, patience := range []time.Duration{0, 25 * time.Millisecond, 20 * time.Second} {
		a := &App{AdmissionPatience: patience}
		release, err := a.Operations.Exclusive(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		handler := a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
		w := httptest.NewRecorder()
		started := time.Now()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
		elapsed := time.Since(started)
		statusAdmissionFailure(t, w, http.StatusConflict, "RESTORE_OPERATION_BUSY")
		if calls != 0 || a.Operations.Snapshot().Active != 1 {
			t.Fatal("status replayed a handler or changed the writer admission")
		}
		release()
		if elapsed >= 200*time.Millisecond || patience <= 25*time.Millisecond && elapsed >= 100*time.Millisecond {
			t.Fatal("status exceeded its bounded refusal", patience, elapsed)
		}
	}
}

func TestStatusAdmissionGraceKeepsRecoveryAndCancellation(t *testing.T) {
	for _, when := range []string{"before", "waiting"} {
		for _, refusal := range []string{"recovery", "journal", "cancel"} {
			t.Run(when+"/"+refusal, func(t *testing.T) {
				a := &App{AdmissionPatience: 20 * time.Second}
				ctx, attempted := statusAdmissionProbe(t, a)
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				release, err := a.Operations.Enter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				refuse := func() {
					if refusal == "recovery" {
						a.Operations.Fence()
					} else if refusal == "journal" {
						a.Operations.FenceJournal()
					} else {
						cancel()
					}
				}
				if when == "before" {
					refuse()
				}
				var calls atomic.Int32
				handler := a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
				w, done := httptest.NewRecorder(), make(chan struct{})
				go func() {
					defer close(done)
					handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx))
				}()
				if when == "waiting" {
					<-attempted
					refuse()
				}
				<-done
				status, code := http.StatusRequestTimeout, "OPERATION_CANCELED"
				if refusal == "recovery" {
					status, code = http.StatusServiceUnavailable, "PRIVATE_BACKUP_RECOVERY_REQUIRED"
				} else if refusal == "journal" {
					status, code = http.StatusServiceUnavailable, "DATAPLANE_RECOVERY_REQUIRED"
				}
				statusAdmissionFailure(t, w, status, code)
				if calls.Load() != 0 || a.Operations.Snapshot().Active != 1 {
					t.Fatal("refused status executed or leaked admission")
				}
			})
		}
	}
}

func TestStatusAdmissionGraceReleasesLateGrant(t *testing.T) {
	for _, refusal := range []string{"expired", "canceled", "guard-refusal"} {
		t.Run(refusal, func(t *testing.T) {
			a := &App{AdmissionPatience: 20 * time.Second}
			first, retry, allowGuard := make(chan struct{}), make(chan struct{}), make(chan struct{})
			marker := new(int)
			attempts := 0
			if err := a.Operations.SetGuard(func(ctx context.Context) error {
				if ctx.Value(statusAdmissionTestKey{}) != marker {
					return nil
				}
				attempts++
				if attempts == 1 {
					close(first)
				} else if attempts == 2 {
					close(retry)
					<-allowGuard // Deliberately slow guard after a busy first attempt.
					if refusal == "guard-refusal" {
						return operationgate.ErrRecovery
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			release, err := a.Operations.Enter(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), statusAdmissionTestKey{}, marker))
			defer cancel()
			var calls atomic.Int32
			handler := a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			w, done := httptest.NewRecorder(), make(chan struct{})
			go func() {
				defer close(done)
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx))
			}()
			<-first
			release()
			select {
			case <-retry:
			case <-done:
				t.Fatal("status refused without attempting its admission grace")
			}
			if refusal == "expired" {
				timer := time.NewTimer(150 * time.Millisecond)
				<-timer.C
			} else if refusal == "canceled" {
				cancel()
			}
			close(allowGuard)
			<-done
			status, code := http.StatusConflict, "RESTORE_OPERATION_BUSY"
			if refusal == "canceled" {
				status, code = http.StatusRequestTimeout, "OPERATION_CANCELED"
			} else if refusal == "guard-refusal" {
				status, code = http.StatusServiceUnavailable, "PRIVATE_BACKUP_RECOVERY_REQUIRED"
			}
			statusAdmissionFailure(t, w, status, code)
			if calls.Load() != 0 || a.Operations.Snapshot().Active != 0 {
				t.Fatal("late grant ran its handler or leaked admission")
			}
			if next, err := a.Operations.Exclusive(context.Background()); err != nil {
				t.Fatal("late admission was not released", err)
			} else {
				next()
			}
		})
	}
}

func TestStatusAdmissionGracePatienceBounds(t *testing.T) {
	for _, test := range []struct {
		patience, want time.Duration
	}{{0, 0}, {-time.Second, 0}, {25 * time.Millisecond, 25 * time.Millisecond}, {20 * time.Second, 125 * time.Millisecond}} {
		a := &App{AdmissionPatience: test.patience}
		if got := a.admissionPatience(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)); got != test.want {
			t.Fatalf("status patience %s: got %s, want %s", test.patience, got, test.want)
		}
	}
	a := &App{AdmissionPatience: 20 * time.Second}
	if a.admissionPatience(httptest.NewRequest(http.MethodGet, "/api/v1/services", nil)) != 2*time.Second ||
		a.admissionPatience(httptest.NewRequest(http.MethodPost, "/api/v1/apply", nil)) != 20*time.Second ||
		a.admissionPatience(httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)) != 0 {
		t.Fatal("status grace changed another method or endpoint")
	}
}
