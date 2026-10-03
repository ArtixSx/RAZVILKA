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
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/security"
)

// Real HTTP/auth/gate/Store/Manager/journal; package commands and native
// observations are simulated. These tests do not claim native D11 acceptance.
type recoveryPackageRunner struct {
	installed, available string
	calls                []string
	unknown              bool
	rollbackUnknown      bool
}

func (r *recoveryPackageRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	switch args[0] {
	case "list-installed":
		return []byte("nfqws2-keenetic - " + r.installed + "\n"), nil
	case "list":
		return []byte("nfqws2-keenetic - " + r.available + "\n"), nil
	case "update":
		return []byte("ok"), nil
	case "upgrade":
		r.installed = r.available
		if r.unknown {
			return nil, errors.New("unknown command exit")
		}
		return []byte("upgraded"), nil
	case "install":
		r.installed = strings.Split(filepath.Base(args[len(args)-1]), "_")[1]
		if r.rollbackUnknown {
			return nil, errors.New("rollback command exit unknown")
		}
		return []byte("rollback"), nil
	}
	return nil, errors.New("unexpected command")
}

func TestComponentScheduledUpdateAndRestartKeepRecoveryFence(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal(err)
	}
	m := a.Components
	fresh := &App{Store: a.Store, Security: a.Security, Components: &components.Manager{StateDir: m.StateDir, InfoDir: m.InfoDir, RepoDir: m.RepoDir, BinDir: m.BinDir, InitDir: m.InitDir, Opkg: m.Opkg, Runner: runner, Client: m.Client}}
	if err := fresh.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	if release, err := fresh.Operations.Enter(context.Background()); release != nil || !errors.Is(err, errComponentRecovery) {
		t.Fatal("restart admitted worker", err)
	}
	s := httptest.NewServer(fresh.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte("awaiting-live-acceptance")) {
		t.Fatalf("restart state %d %s", code, data)
	}
	if err := os.WriteFile(filepath.Join(m.StateDir, "update-journal", "current.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _ := componentHTTP(t, s, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, s.URL); code != 503 {
		t.Fatal("corrupt journal hidden", code)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", map[string]any{"transaction_id": strings.Repeat("a", 32), "component": "nfqws2", "action": "accept-live", "expected_revision": a.Store.Get().Revision, "confirm": "REPAIR_COMPONENT_TRANSACTION"}, componentRecoveryToken, s.URL); code != 503 {
		t.Fatal("corrupt journal repair bypassed", code)
	}
}

func TestComponentInterruptedRollbackHTTPRequiresTrustedInspection(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	runner.rollbackUnknown = true
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", recoveryBody(a, "rollback"), componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	body := recoveryBody(a, "verify-rollback")
	body["external_repair_confirmed"] = true
	// A JSON boolean cannot create a trusted completion receipt.
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	body["quiescence_check"] = true
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 400 {
		t.Fatal("HTTP supplied callback accepted", code)
	}
	delete(body, "quiescence_check")
	a.componentRecoveryChecks.quiescence = func(context.Context) error { return nil }
	body["external_repair_confirmed"] = false
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	body["external_repair_confirmed"] = true
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 {
		t.Fatalf("verified repaired rollback %d %s", code, data)
	}
	rollbacks := 0
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "install ") {
			rollbacks++
		}
	}
	if rollbacks != 1 {
		t.Fatal("unknown rollback command replayed", rollbacks)
	}
}

func TestComponentRecoveryGuardRejectsStopAndSafeMode(t *testing.T) {
	a, _ := componentHTTPFixture(t)
	guard, err := a.componentUpdateGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.SetSafeMode(true); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(guard(context.Background()), components.ErrRecoveryAuthority) {
		t.Fatal("SafeMode did not revoke guard")
	}
	if err := a.Store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("test", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	guard, err = a.componentUpdateGuard(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"test": "direct"}, a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(guard(context.Background()), components.ErrRecoveryAuthority) {
		t.Fatal("Stop did not revoke guard")
	}
	if _, err := a.componentUpdateGuard(context.Background()); !errors.Is(err, components.ErrRecoveryAuthority) {
		t.Fatal("Stopped update admitted", err)
	}
}
func (r *recoveryPackageRunner) RunIn(_ context.Context, dir, _ string, args ...string) ([]byte, error) {
	return nil, os.WriteFile(filepath.Join(dir, args[1]+"_"+r.available+"_all.ipk"), []byte("simulated package"), 0600)
}

const componentRecoveryToken = "component-recovery-real-http-admin-token-123"

func componentHTTPFixture(t *testing.T) (*App, *recoveryPackageRunner) {
	t.Helper()
	root := t.TempDir()
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	gate, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	runner := &recoveryPackageRunner{installed: "1.0", available: "1.0"}
	m := &components.Manager{StateDir: filepath.Join(root, "state"), InfoDir: filepath.Join(root, "info"), RepoDir: filepath.Join(root, "repo"), BinDir: filepath.Join(root, "bin"), InitDir: filepath.Join(root, "init"), Opkg: "simulated-opkg", Runner: runner, Client: &http.Client{Transport: sourceFixtureTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline releases") })}}
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CacheRollbackPackage(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	runner.available = "2.0"
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, Components: m, Security: gate}
	a.componentRecoveryChecks.inactive = func(context.Context, string) error { return nil }
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	return a, runner
}

func componentHTTP(t *testing.T, server *httptest.Server, method, path string, body any, token, origin string) (int, []byte) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data
}
func recoveryBody(a *App, action string) map[string]any {
	state, _, _ := a.Components.PendingManagedUpdate()
	return map[string]any{"transaction_id": state.TransactionID, "component": state.Component, "action": action, "expected_revision": a.Store.Get().Revision, "confirm": "REPAIR_COMPONENT_TRANSACTION"}
}

func TestComponentRecoveryRealHTTPMatchingAuthorityAndAcceptance(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	code, data := componentHTTP(t, s, "POST", "/api/v1/components/nfqws2/update", nil, componentRecoveryToken, s.URL)
	if code != 202 || !a.PendingComponentRecovery() {
		t.Fatalf("dormant journaled update: %d %s", code, data)
	}
	before := len(runner.calls)
	body := recoveryBody(a, "accept-live")
	for _, scenario := range []struct {
		token, origin string
		status        int
	}{{"", s.URL, 401}, {componentRecoveryToken, "https://foreign.invalid", 403}} {
		if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, scenario.token, scenario.origin); code != scenario.status {
			t.Fatalf("security: %d %s", code, data)
		}
	}
	for _, field := range []string{"transaction_id", "component", "expected_revision"} {
		copy := recoveryBody(a, "accept-live")
		if field == "expected_revision" {
			copy[field] = a.Store.Get().Revision + 1
		} else {
			copy[field] = "xray"
		}
		code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", copy, componentRecoveryToken, s.URL)
		if code < 400 {
			t.Fatal("mismatch admitted", field, code)
		}
	}
	if len(runner.calls) != before {
		t.Fatal("denied recovery touched package runner")
	}
	if code, _ := componentHTTP(t, s, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, s.URL); code != 200 {
		t.Fatal(code)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/nfqws2/update", nil, componentRecoveryToken, s.URL); code != 503 {
		t.Fatal("ordinary update escaped pending", code)
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("candidate accepted live", code)
	}
	a.componentRecoveryChecks.live = func(context.Context, string) error { return a.Store.SetSafeMode(true) }
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 || !a.PendingComponentRecovery() {
		t.Fatal("authority changed during live check", code)
	}
	if err := a.Store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	body = recoveryBody(a, "accept-live")
	a.componentRecoveryChecks.live = func(context.Context, string) error { return nil }
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 || a.PendingComponentRecovery() {
		t.Fatalf("matching acceptance %d %s", code, data)
	}
	data, err := os.ReadFile(filepath.Join(a.Components.StateDir, "operations", "nfqws2.json"))
	var operation componentRecoveryOperation
	if err != nil || json.Unmarshal(data, &operation) != nil || operation.Status != "succeeded" || operation.TransactionID != body["transaction_id"] {
		t.Fatalf("matching acceptance did not settle durable operation receipt: %v %s", err, data)
	}
	// Re-open the manager as a fresh reader: a reload must release UI actions.
	m := a.Components
	fresh := &components.Manager{StateDir: m.StateDir, InfoDir: m.InfoDir, RepoDir: m.RepoDir, BinDir: m.BinDir, InitDir: m.InitDir, Opkg: m.Opkg, Runner: runner, Client: m.Client}
	views, err := fresh.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.ID == "nfqws2" && view.OperationStatus == "running" {
			t.Fatal("settled operation still blocks UI after restart")
		}
	}
	commands := len(runner.calls)
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code < 400 || len(runner.calls) != commands {
		t.Fatal("repeat replayed settled transaction", code)
	}
}

func TestComponentTerminalHTTPFinishesOperationWithoutReplay(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal(err)
	}
	body := recoveryBody(a, "accept-live")
	// Simulate a process exit between package-journal acceptance and the
	// independent operation/checkpoint write, leaving the real running receipt.
	_, err := a.Components.RecoverManagedUpdate(context.Background(), components.ManagedRecoveryRequest{TransactionID: body["transaction_id"].(string), Component: "nfqws2", Action: "accept-live"}, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	before := len(runner.calls)
	a.componentRecoveryChecks.live = func(context.Context, string) error {
		t.Error("terminal acceptance callback replayed")
		return errors.New("must not replay")
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"checkpoint_settled":true`)) {
		t.Fatalf("terminal follow-up: %d %s", code, data)
	}
	if len(runner.calls) != before {
		t.Fatal("terminal follow-up ran package commands")
	}
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 || len(runner.calls) != before {
		t.Fatal("finished receipt permitted replay", code)
	}
}

func TestComponentInstalledIdleHTTPRequiresTrustedProofAndSettlesReceipt(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	body := recoveryBody(a, "accept-installed-idle")
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("HTTP inferred quiescence", code)
	}
	a.componentRecoveryChecks.quiescence = func(context.Context) error { return nil }
	a.componentRecoveryChecks.inactive = func(context.Context, string) error { return errors.New("working routes still use component") }
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("active package accepted idle", code)
	}
	a.componentRecoveryChecks.inactive = func(context.Context, string) error { return nil }
	if code, data := componentHTTP(t, s, "GET", "/api/v1/components/recovery", nil, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"inactivity_confirmed":true`)) {
		t.Fatalf("idle capability: %d %s", code, data)
	}
	a.componentRecoveryChecks.live = func(context.Context, string) error {
		t.Error("idle acceptance invoked live proof")
		return errors.New("not live")
	}
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"installed_idle_accepted":true`)) || !bytes.Contains(data, []byte(`"live_accepted":false`)) {
		t.Fatalf("idle acceptance: %d %s", code, data)
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err != nil || pending || state.Phase != components.UpdateAcceptedIdle {
		t.Fatal(state, pending, err)
	}
	data, err := os.ReadFile(filepath.Join(a.Components.StateDir, "operations", "nfqws2.json"))
	if err != nil || !bytes.Contains(data, []byte(`"status":"succeeded"`)) {
		t.Fatalf("idle receipt left running: %v %s", err, data)
	}
	before := len(runner.calls)
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 || len(runner.calls) != before {
		t.Fatal("idle settlement replay", code)
	}
}

func TestComponentIdleAuthorityRecheckedAfterSecondObservation(t *testing.T) {
	a, _ := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal(err)
	}
	a.componentRecoveryChecks.quiescence = func(context.Context) error { return nil }
	observations := 0
	a.componentRecoveryChecks.inactive = func(context.Context, string) error {
		observations++
		if observations == 2 {
			return a.Store.SetSafeMode(true)
		}
		return nil
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", recoveryBody(a, "accept-installed-idle"), componentRecoveryToken, s.URL); code != 409 || !a.PendingComponentRecovery() || observations != 2 {
		t.Fatal("SafeMode did not revoke idle acceptance", code, observations)
	}
}

func TestComponentKnownRollbackHTTPKeepsSeparateAcceptance(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	a.componentRecoveryChecks.inactive = func(context.Context, string) error {
		if runner.installed == "2.0" {
			return errors.New("candidate failed")
		}
		return nil
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/nfqws2/update", nil, componentRecoveryToken, s.URL); code != 202 || !bytes.Contains(data, []byte(`"pending_rollback_acceptance":true`)) {
		t.Fatalf("known rollback was prematurely accepted: %d %s", code, data)
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err != nil || !pending || state.Phase != components.UpdateAwaitingRollback {
		t.Fatal(state, pending, err)
	}
	before := len(runner.calls)
	a.componentRecoveryChecks.inactive = func(context.Context, string) error { return errors.New("old runtime unconfirmed") }
	body := recoveryBody(a, "verify-rollback")
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 || !a.PendingComponentRecovery() {
		t.Fatal("failed old runtime accepted", code)
	}
	a.componentRecoveryChecks.inactive = func(context.Context, string) error { return nil }
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 {
		t.Fatalf("independent old acceptance: %d %s", code, data)
	}
	for _, call := range runner.calls[before:] {
		if strings.HasPrefix(call, "install ") || strings.HasPrefix(call, "upgrade ") {
			t.Fatal("acceptance replayed package command", call)
		}
	}
}

func TestComponentTerminalHTTPCheckpointPreservesLaterOperation(t *testing.T) {
	for _, binding := range []string{"legacy-newer", "different-transaction", "same-transaction-newer"} {
		t.Run(binding, func(t *testing.T) {
			a, runner := componentHTTPFixture(t)
			if err := a.loadAutonomy(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
				t.Fatal(err)
			}
			body := recoveryBody(a, "accept-live")
			_, err := a.Components.RecoverManagedUpdate(context.Background(), components.ManagedRecoveryRequest{TransactionID: body["transaction_id"].(string), Component: "nfqws2", Action: "accept-live"}, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			state, _, err := a.Components.PendingManagedUpdate()
			if err != nil {
				t.Fatal(err)
			}
			terminalAt, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
			if err != nil {
				t.Fatal(err)
			}
			operation := componentRecoveryOperation{SchemaVersion: 1, Component: "nfqws2", Action: "update", Status: "running", Message: "new operation must remain intact", UpdatedAt: terminalAt.Add(time.Second).Format(time.RFC3339Nano)}
			if binding == "different-transaction" {
				operation.TransactionID = strings.Repeat("b", 32)
				operation.UpdatedAt = terminalAt.Add(-time.Second).Format(time.RFC3339Nano)
			}
			if binding == "same-transaction-newer" {
				operation.TransactionID = state.TransactionID
			}
			protected, _ := json.Marshal(operation)
			path := filepath.Join(a.Components.StateDir, "operations", "nfqws2.json")
			if err := os.WriteFile(path, protected, 0600); err != nil {
				t.Fatal(err)
			}
			a.autonomy.mu.Lock()
			a.autonomy.doc.Maintenance["components"] = componentPendingPrefix + "nfqws2"
			err = a.persistAutonomyLocked(context.Background())
			a.autonomy.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			before := len(runner.calls)
			a.componentRecoveryChecks.live = func(context.Context, string) error {
				t.Error("terminal observation replayed")
				return errors.New("no replay")
			}
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 || !bytes.Contains(data, []byte(`"checkpoint_settled":true`)) {
				t.Fatalf("checkpoint-only settlement: %d %s", code, data)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, protected) || len(runner.calls) != before {
				t.Fatalf("protected receipt changed: %v %s", err, after)
			}
			if a.componentMaintenancePending() {
				t.Fatal("old scheduler checkpoint not settled")
			}
			if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
				t.Fatal("settled checkpoint accepted repeat", code)
			}
		})
	}
}

func TestComponentUnknownHTTPRecoveryNeverReplaysUpgrade(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	runner.unknown = true
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	code, _ := componentHTTP(t, s, "POST", "/api/v1/components/nfqws2/update", nil, componentRecoveryToken, s.URL)
	if code < 400 || !a.PendingComponentRecovery() {
		t.Fatal("unknown update lost fence", code)
	}
	body := recoveryBody(a, "rollback")
	body["allow_unknown_rollback"] = true
	a.componentRecoveryChecks.quiescence = func(context.Context) error { return errors.New("orphan package script still active") }
	if code, _ := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal(code)
	}
	a.componentRecoveryChecks.quiescence = func(context.Context) error { return nil }
	if code, data := componentHTTP(t, s, "POST", "/api/v1/components/recovery", body, componentRecoveryToken, s.URL); code != 200 {
		t.Fatalf("rollback: %d %s", code, data)
	}
	upgrades, rollbacks := 0, 0
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "upgrade ") {
			upgrades++
		}
		if strings.HasPrefix(call, "install ") {
			rollbacks++
		}
	}
	if upgrades != 1 || rollbacks != 1 || runner.installed != "1.0" || a.PendingComponentRecovery() {
		t.Fatal("unknown replay or unconfirmed rollback", upgrades, rollbacks)
	}
}
