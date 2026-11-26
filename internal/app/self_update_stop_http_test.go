package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelfUpdateStoppedHTTPRepairAllowsOnlyMatchingKnownRollback(t *testing.T) {
	a, proof := fileUpdateHTTPFixture(t)
	fileUpdateEnableControl(t, a)
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", selfUpdateStopBody(a), componentRecoveryToken, s.URL); code != 202 {
		t.Fatal(code, string(data))
	}
	stop, _, err := operationgate.ReadSelfUpdateStop(context.Background(), a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"restore", "restore-private-state"} {
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, action), componentRecoveryToken, s.URL); code != 200 {
			t.Fatal(action, code, string(data))
		}
	}
	runs := len(proof.runs)
	for _, action := range []string{"install", "start-candidate-panel", "start-rollback-panel", "accept-live", "accept-rollback", "prepare"} {
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, action), componentRecoveryToken, s.URL); code < 400 {
			t.Fatal("Stop admitted Start/live", action, code, string(data))
		}
	}
	if len(proof.runs) != runs || len(proof.lives) != 0 || len(proof.finishes) != 0 {
		t.Fatal("repair borrowed live authority", proof.runs)
	}
	current, _, err := operationgate.ReadSelfUpdateStop(context.Background(), a.SelfUpdateFiles.ControlRoot)
	if err != nil || current != stop {
		t.Fatal("repair changed Stop authority", current, err)
	}
	for _, field := range []string{"transaction_id", "expected_revision"} {
		body := fileUpdateBody(a, "resolve-unknown")
		if field == "transaction_id" {
			body[field] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		} else {
			body[field] = a.Store.Get().Revision + 1
		}
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", body, componentRecoveryToken, s.URL); code < 400 {
			t.Fatal("unmatched repair admitted", field, code, string(data))
		}
	}
}

func TestSelfUpdateStoppedHTTPUnknownCommandCannotReplayOrRestore(t *testing.T) {
	a, proof := fileUpdateHTTPFixture(t)
	fileUpdateEnableControl(t, a)
	for _, action := range []string{"prepare", "stop-old-panel", "prepare-private-state"} {
		if err := fileUpdateAction(t, a, action); err != nil {
			t.Fatal(action, err)
		}
	}
	proof.runError = errors.New("unknown supervised runtime command")
	if err := fileUpdateAction(t, a, "quiesce-old-runtime"); err == nil {
		t.Fatal("unknown outcome accepted")
	}
	proof.observeError = errors.New("ECHILD is unavailable")
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", selfUpdateStopBody(a), componentRecoveryToken, s.URL); code != 202 {
		t.Fatal(code, string(data))
	}
	runs := len(proof.runs)
	for _, action := range []string{"quiesce-old-runtime", "restore", "restore-private-state", "resolve-unknown"} {
		if code, data := componentHTTP(t, s, "POST", "/api/v1/self-update/recovery", fileUpdateBody(a, action), componentRecoveryToken, s.URL); code < 400 {
			t.Fatal("unknown command replayed/accepted", action, code, string(data))
		}
	}
	if len(proof.runs) != runs {
		t.Fatal("unknown command replayed", proof.runs)
	}
}

func fileUpdateEnableControl(t *testing.T, a *App) {
	t.Helper()
	a.SelfUpdateFiles.ControlRoot = filepath.Join(filepath.Dir(a.SelfUpdateFiles.Directory), "authority")
}

func selfUpdateStopBody(a *App) map[string]any {
	return map[string]any{"action": "stop", "confirm": "STOP_OWNED_ROUTES", "expected_revision": a.Store.Get().Revision, "idempotency_key": "stop-reviewed-update"}
}

func TestSelfUpdateDurableStopHTTPWhileInstallerOwnsLeasePreservesAllImages(t *testing.T) {
	a, proof := fileUpdateHTTPFixture(t)
	fileUpdateEnableControl(t, a)
	if err := fileUpdateAction(t, a, "prepare"); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), selfUpdateFileAdmissionKey{}, selfUpdateFileAdmission{id: fileUpdateID})
	release, err := a.Operations.Exclusive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// Independent private/network uncertainty still prevents cleanup. It does
	// not wait for the installer or prohibit a global durable revocation.
	a.Operations.FenceJournal()
	configPath := filepath.Join(filepath.Dir(filepath.Dir(a.SelfUpdateFiles.Directory)), "config.json")
	beforeConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	images := map[string][]byte{}
	for _, file := range proof.files {
		path := filepath.Join(a.SelfUpdateFiles.Installation, file.Target)
		images[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	code, data := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", selfUpdateStopBody(a), componentRecoveryToken, s.URL)
	var reply map[string]any
	if json.Unmarshal(data, &reply) != nil || code != 202 || reply["authority_revoked"] != true || reply["stop_requested"] != true || reply["stopped_confirmed"] != false || reply["cleanup_pending"] != true {
		t.Fatalf("Stop did not durably revoke while installer held lease: %d %s", code, data)
	}
	if !a.Operations.Snapshot().Exclusive || len(proof.runs) != 0 || len(proof.lives) != 0 || len(proof.finishes) != 0 {
		t.Fatal("Stop borrowed installer admission or pretended cleanup", proof.runs)
	}
	stop, present, err := operationgate.ReadSelfUpdateStop(context.Background(), a.SelfUpdateFiles.ControlRoot)
	if err != nil || !present || !stop.Stopped || stop.State != "requested" || stop.ConfigRevision != a.Store.Get().Revision {
		t.Fatal(stop, present, err)
	}
	for _, key := range []string{"stop-reviewed-update", "different-browser-request"} {
		body := selfUpdateStopBody(a)
		body["idempotency_key"] = key
		if code, data = componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", body, componentRecoveryToken, s.URL); code != 202 {
			t.Fatal(code, string(data))
		}
	}
	again, _, err := operationgate.ReadSelfUpdateStop(context.Background(), a.SelfUpdateFiles.ControlRoot)
	if err != nil || again != stop {
		t.Fatal("repeat changed global revocation", again, err)
	}
	resume := selfUpdateStopBody(a)
	resume["action"], resume["confirm"] = "resume", "RESUME_OWNED_ROUTES"
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", resume, componentRecoveryToken, s.URL); code != 503 {
		t.Fatal("ordinary Resume cleared durable authority", code)
	}
	if err := a.SelfUpdateFiles.StartupAllowed(context.Background(), fileUpdateID, 2); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("matching startup bypassed Stop", err)
	}
	if err := fileUpdateAction(t, a, "install"); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("late file replacement bypassed Stop", err)
	}
	if code, data := componentHTTP(t, s, "GET", "/api/v1/self-update/recovery", nil, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"authority_revoked":true`)) || !bytes.Contains(data, []byte(`"stopped_confirmed":false`)) {
		t.Fatalf("Stop receipt absent from inspection: %d %s", code, data)
	}
	afterConfig, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(beforeConfig, afterConfig) {
		t.Fatal("Stop created third config image", err)
	}
	for path, before := range images {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("Stop replaced an application image", path, err)
		}
	}
}

func TestSelfUpdateDurableStopSecurityValidationAndDamagedAuthority(t *testing.T) {
	for _, test := range []string{"unauthenticated", "origin", "revision", "missing-revision", "confirm", "callback", "damaged-control"} {
		t.Run(test, func(t *testing.T) {
			a, _ := fileUpdateHTTPFixture(t)
			if err := fileUpdateAction(t, a, "prepare"); err != nil {
				t.Fatal(err)
			}
			fileUpdateEnableControl(t, a)
			body := selfUpdateStopBody(a)
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			token, origin, want := componentRecoveryToken, s.URL, 400
			switch test {
			case "unauthenticated":
				token, want = "", 401
			case "origin":
				origin, want = "https://foreign.example", 403
			case "revision":
				body["expected_revision"], want = a.Store.Get().Revision+1, 409
			case "missing-revision":
				delete(body, "expected_revision")
			case "confirm":
				body["confirm"] = "wrong"
			case "callback":
				body["stopped_confirmed"] = true
			case "damaged-control":
				want = 503
				if err := os.Mkdir(a.SelfUpdateFiles.ControlRoot, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if code, data := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", body, token, origin); code != want || bytes.Contains(data, []byte(`"authority_revoked":true`)) {
				t.Fatal(code, string(data), want)
			}
			if test != "damaged-control" {
				if _, err := os.Stat(a.SelfUpdateFiles.ControlRoot); !os.IsNotExist(err) {
					t.Fatal("refused request created Stop authority", err)
				}
			}
		})
	}
}

func TestSelfUpdateGlobalStopDoesNotNeedReadableFileTransaction(t *testing.T) {
	a, proof := fileUpdateHTTPFixture(t)
	fileUpdateEnableControl(t, a)
	if err := os.Mkdir(a.SelfUpdateFiles.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.SelfUpdateFiles.Directory, "current.json")
	protected := []byte("corrupt retained file transaction")
	if err := os.WriteFile(path, protected, 0600); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "POST", "/api/v1/service-control/runtime", selfUpdateStopBody(a), componentRecoveryToken, s.URL); code != 202 || !bytes.Contains(data, []byte(`"authority_revoked":true`)) {
		t.Fatalf("global revocation depended on damaged transaction: %d %s", code, data)
	}
	if code, data := componentHTTP(t, s, "GET", "/api/v1/self-update/recovery", nil, componentRecoveryToken, s.URL); code != 503 || !bytes.Contains(data, []byte(`"authority_revoked":true`)) {
		t.Fatal(code, string(data))
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, protected) || len(proof.runs) != 0 {
		t.Fatal("revocation repaired or replayed damaged transaction", err)
	}
}
