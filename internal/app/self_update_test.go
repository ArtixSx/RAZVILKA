package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func TestSelfUpdateCandidateRefusalPreservesConfiguration(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.SelfUpdate = updatecheck.NewUpdater("0.18.1-dev", t.TempDir(), updatecheck.Deployment{Executable: "/opt/var/lib/candidate/razvilka", Port: "8788", Paths: updatecheck.ProductionPaths()})
	before := a.Store.Get()
	handler := a.Handler(http.NotFoundHandler())
	for _, body := range []string{`{"confirm":"PREPARE_APP_UPDATE","url":"https://example.org/package"}`, `{"confirm":"WRONG"}`} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/self-update/prepare", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("unreviewed prepare accepted", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/self-update/prepare", strings.NewReader(`{"confirm":"PREPARE_APP_UPDATE"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"blocked"`) {
		t.Fatal("candidate crossed production boundary", w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("prepare changed configuration")
	}
}

func TestSelfUpdateStatusCancellationRemainAuthenticatedAndAvailable(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.SelfUpdate = updatecheck.NewUpdater("0.18.1-dev", t.TempDir(), updatecheck.Deployment{})
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
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		request := httptest.NewRequest(method, "http://router.local/api/v1/self-update/current", nil)
		request.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		if w.Code != 401 {
			t.Fatal("status/cancel bypassed auth", w.Code)
		}
		request = httptest.NewRequest(method, "http://router.local/api/v1/self-update/current", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Origin", "http://router.local")
		request.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		expected := 200
		if method == http.MethodDelete {
			expected = 409
		}
		if w.Code != expected || strings.Contains(w.Body.String(), "RESTORE_OPERATION_BUSY") {
			t.Fatal("update status/cancel blocked by gate", w.Code, w.Body.String())
		}
	}
}

func TestSelfUpdateApplyExclusiveAdmissionRetainedUntilHandoff(t *testing.T) {
	a := &App{}
	var handoffRelease func()
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		handoffRelease, err = a.privateRestoreAdmission(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(202)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/self-update/apply", nil))
	if handoffRelease == nil {
		t.Fatal("handoff lacked admission")
	}
	if release, err := a.Operations.Enter(context.Background()); err != operationgate.ErrBusy {
		if release != nil {
			release()
		}
		t.Fatal("HTTP completion released active installer gate", err)
	}
	handoffRelease()
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("completed handoff leaked admission", err)
	}
	release()
}

func TestSelfUpdateNewDaemonBlocksWritersButAllowsInstallerHealth(t *testing.T) {
	dir := t.TempDir()
	u := updatecheck.NewUpdater("0.19.0", dir, updatecheck.Deployment{})
	if err := os.MkdirAll(u.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	record := map[string]any{"owner": "razvilka-self-update-v1", "job": map[string]any{"id": strings.Repeat("a", 32), "state": "restarting", "helper_pid": 0, "updated_at": time.Now().UTC()}}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(u.Directory, "current.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{SelfUpdate: u}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartSelfUpdate(ctx)
	if !u.InstallationLocked() {
		t.Fatal("new process did not retain installer admission")
	}
	called := false
	handler := a.operationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	for _, path := range []string{"/api/v1/services/youtube", "/api/v1/auth/password"} {
		called = false
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("PUT", path, nil))
		if called || w.Code != 409 {
			t.Fatal("new daemon accepted writes before installer health committed", path, w.Code)
		}
	}
	called = false
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/status", nil))
	if !called || w.Code != 200 {
		t.Fatal("startup fence made installer healthcheck impossible")
	}
	if release, err := a.Operations.Enter(ctx); err != operationgate.ErrBusy {
		if release != nil {
			release()
		}
		t.Fatal("startup fence admitted background writer")
	}
	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := a.WaitSelfUpdate(waitCtx); err != nil {
		t.Fatal(err)
	}
}
