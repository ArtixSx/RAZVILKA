package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/smartroute"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

type pausedBody struct {
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
	reader  io.Reader
}

func (b *pausedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.resume })
	return b.reader.Read(p)
}
func (b *pausedBody) Close() error { return nil }
func awaitOperation(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	// The full race suite instruments password hashing and every concurrent
	// package. A three-second wall-clock deadline was flaky on shared CI even
	// though the request had not failed; keep this bounded but allow race-mode
	// scheduling overhead before declaring the checkpoint unreachable.
	case <-time.After(15 * time.Second):
		t.Fatal("operation did not reach checkpoint")
	}
}
func newPausedBody(reader io.Reader) *pausedBody {
	return &pausedBody{entered: make(chan struct{}), resume: make(chan struct{}), reader: reader}
}

func TestPrivateImportExcludesHTTPReadsAndWritesUntilCompletion(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	envelope, err := privatebackup.Encrypt(privateRestoreFixture(t), "synthetic backup password")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"envelope": envelope, "password": "synthetic backup password", "confirm": "IMPORT_PRIVATE_BACKUP"})
	body := newPausedBody(bytes.NewReader(raw))
	var resume sync.Once
	defer resume.Do(func() { close(body.resume) })
	r := httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/import", body)
	handler := a.Handler(http.NotFoundHandler())
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(w, r) }()
	awaitOperation(t, body.entered)
	before := a.Store.Get()
	for _, request := range []struct{ method, path string }{
		{"PUT", "/api/v1/services/youtube"}, {"GET", "/api/v1/devices"},
		{"GET", "/api/v1/status"}, {"POST", "/api/v1/apply"},
		{"POST", "/api/v1/warp/generate"}, {"POST", "/api/v1/private-backups/import"},
		{"POST", "/api/v1/cloudflare/backups/restore"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(request.method, request.path, strings.NewReader(`{}`)))
		if response.Code != 409 || !strings.Contains(response.Body.String(), `"not_started":true`) || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("request bypassed exclusive import", request.path, response.Body.String())
		}
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("blocked request mutated config")
	}
	if _, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("background admission not excluded")
	}
	resume.Do(func() { close(body.resume) })
	awaitOperation(t, done)
	if w.Code != 200 || a.Store.Get().Services["youtube"].Route != "usque" {
		t.Fatal("import failed", w.Code, w.Body.String())
	}
	last, err := a.Operations.Enter(context.Background())
	if err != nil {
		t.Fatal("HTTP import leaked ownership", err)
	}
	last()
}

func TestUncertainOnlineJournalFencesAPIWithoutFallback(t *testing.T) {
	a, base := privateRestoreTestApp(t)
	before := a.Store.Get()
	if err := os.WriteFile(filepath.Join(base, "journal", "restore.private.json"), []byte("corrupt-private-journal-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	err := a.restorePrivateDraft(context.Background(), privateRestoreFixture(t))
	var failed *privateRestoreFailure
	if !errors.As(err, &failed) || !failed.recoveryRequired {
		t.Fatal("uncertain journal not fenced", err)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) || len(a.CustomServices.List()) != 0 {
		t.Fatal("fell back to unjournaled writes")
	}
	handler := a.Handler(http.NotFoundHandler())
	for _, call := range []struct{ method, path string }{{"GET", "/api/v1/status"}, {"GET", "/api/v1/devices"}, {"POST", "/api/v1/apply"}, {"POST", "/api/v1/private-backups/import"}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(call.method, call.path, strings.NewReader("{}")))
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"recovery_required":true`) || w.Header().Get("Retry-After") != "" {
			t.Fatal("fenced API result", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), base) || strings.Contains(w.Body.String(), "corrupt-private-journal-marker") {
			t.Fatal("private journal leaked")
		}
	}
	a.backgroundRound(context.Background(), 1)
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("fenced worker wrote configuration")
	}
}

func TestPrivateImportNeedsStartupCoordinator(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.PrivateRestore = nil
	before := a.Store.Get()
	err := a.restorePrivateDraft(context.Background(), privateRestoreFixture(t))
	var failure *privateRestoreFailure
	if !errors.As(err, &failure) || !failure.notStarted || failure.recoveryRequired {
		t.Fatal("missing coordinator result", err)
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("missing coordinator fell back")
	}
}

type pausedRouteProber struct {
	once            sync.Once
	entered, resume chan struct{}
}

func (p *pausedRouteProber) Probe(_ context.Context, service catalog.Service, route string) testlab.Result {
	p.once.Do(func() { close(p.entered) })
	<-p.resume
	return testlab.Result{ServiceID: service.ID, Route: route, Status: "unknown"}
}

func TestBackgroundRoundPausesForRestoreAndRetainsAdmissionUntilJoined(t *testing.T) {
	a, base := privateRestoreTestApp(t)
	var err error
	a.SmartRoute, err = smartroute.New(filepath.Join(base, "smart-route.json"))
	if err != nil {
		t.Fatal(err)
	}
	a.TestLab = testlab.NewRunner()
	prober := &pausedRouteProber{entered: make(chan struct{}), resume: make(chan struct{})}
	a.RouteProber = prober
	if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exclusive, _ := a.Operations.Exclusive(ctx)
	a.backgroundRound(ctx, 1)
	select {
	case <-prober.entered:
		t.Fatal("background started during restore")
	default:
	}
	exclusive()
	done := make(chan struct{})
	var resume sync.Once
	defer resume.Do(func() { close(prober.resume) })
	go func() { defer close(done); a.backgroundRound(ctx, 1) }()
	awaitOperation(t, prober.entered)
	cancel()
	if _, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("unjoined background probes lost admission")
	}
	resume.Do(func() { close(prober.resume) })
	awaitOperation(t, done)
	last, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("background round leaked admission", err)
	}
	last()
}

func TestRequestCancellationDoesNotExposeUnfinishedHandler(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	body := newPausedBody(strings.NewReader(`{"enabled":true,"route":"direct"}`))
	var resume sync.Once
	defer resume.Do(func() { close(body.resume) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/services/youtube", body).WithContext(ctx)
	handler := a.Handler(http.NotFoundHandler())
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), r) }()
	awaitOperation(t, body.entered)
	cancel()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/import", strings.NewReader("not-json")))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "RESTORE_OPERATION_BUSY") {
		t.Fatal("canceled handler lost ownership before return", w.Body.String())
	}
	resume.Do(func() { close(body.resume) })
	awaitOperation(t, done)
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("ordinary handler leaked ownership", err)
	}
	release()
}

func TestOperationMiddlewareSecurityExemptionsAndPanicCleanup(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	const token = "0123456789abcdefghijklmnopqrstuvwxyz-ADMIN"
	var err error
	a.Security, err = security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	handler := a.Handler(http.NotFoundHandler())
	r := httptest.NewRequest(http.MethodPut, "http://router.local/api/v1/services/youtube", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://router.local")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("admission ran before authentication", w.Code)
	}
	for _, path := range []string{"/", "/api/v1/auth/status", "/api/v1/connections/stream"} {
		called := false
		a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if !called {
			t.Fatal("restore would block login or an endless stream", path)
		}
	}
	release()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("test panic missing")
			}
		}()
		a.operationMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("synthetic failure") })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/devices", nil))
	}()
	last, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("panic leaked admission", err)
	}
	last()
}

func TestInternalRestoreCannotBypassAdmissionOrReuseExpiredContext(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	before := a.Store.Get()
	release, _ := a.Operations.Enter(context.Background())
	err := a.restorePrivateDraft(context.Background(), privateRestoreFixture(t))
	if !errors.Is(err, operationgate.ErrBusy) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("internal restore bypassed ordinary operation")
	}
	release()
	var expired context.Context
	a.operationMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		expired = r.Context()
		first, err := a.privateRestoreAdmission(expired)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.privateRestoreAdmission(expired); !errors.Is(err, operationgate.ErrBusy) {
			t.Fatal("same context admitted concurrent restores")
		}
		first()
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/private-backups/import", nil))
	if _, err := a.privateRestoreAdmission(expired); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("expired HTTP context bypassed gate")
	}
}

func TestAdmittedRestoreRetainsOwnershipPastRequestReturn(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	var finish func()
	var expired context.Context
	a.operationMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		expired = r.Context()
		var err error
		finish, err = a.privateRestoreAdmission(expired)
		if err != nil {
			t.Fatal(err)
		}
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/private-backups/import", nil))
	if _, err := a.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("unfinished restore lost ownership at handler return")
	}
	if _, err := a.privateRestoreAdmission(expired); !errors.Is(err, operationgate.ErrBusy) {
		t.Fatal("expired context admitted more work")
	}
	finish()
	finish()
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("completed restore leaked ownership", err)
	}
	release()
}
