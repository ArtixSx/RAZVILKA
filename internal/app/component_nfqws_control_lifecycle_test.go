package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func managedNFQInitialControlFixture(t *testing.T) *App {
	t.Helper()
	base := t.TempDir()
	store, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := strategylab.New(filepath.Join(base, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.Validator, manager.Executor = strategylab.CompatibleValidator{}, nil
	control := filepath.Join(base, "control")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	owner := components.New()
	owner.StateDir = filepath.Join(base, "components")
	helper := updatecheck.NewUpdater(Version, base, updatecheck.Deployment{})
	helper.Directory = filepath.Join(base, "self-update")
	sec, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, StrategyLab: manager, Components: owner, Security: sec, ComponentHistory: updatecheck.NewComponentHistoryAdmission(ManagedComponentReadVersion), SelfUpdate: helper,
		SelfUpdateFiles: &SelfUpdateFiles{Installation: base, Directory: filepath.Join(base, "self-update-files"), ControlRoot: control, Helper: helper}}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseManagedNFQControl() })
	return a
}

func TestManagedNFQFailedInitialFactoryClosesUnusedControlAcrossServiceStopResume(t *testing.T) {
	initial := managedNFQInitialControlFixture(t)
	a, _, _, _ := serviceRuntimeFixture(t)
	// Existing runtime adapters are explicit models. Config CAS, control files,
	// original operation ownership and the failed NFQ factory are actual; this
	// test makes no native runtime or quiescence claim.
	a.StrategyLab, a.Components = initial.StrategyLab, initial.Components
	a.SelfUpdateFiles, a.SelfUpdate, a.ComponentHistory = initial.SelfUpdateFiles, initial.SelfUpdate, initial.ComponentHistory
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if control, err := a.ConfigureManagedNFQCompatibility(owned); err == nil || control != nil {
		release()
		t.Fatal("missing receipt enabled a provider", err)
	}
	release()
	if a.managedNFQBundle.control != nil {
		t.Fatal("failed initial factory pinned an unused control epoch")
	}
	before, _, err := operationgate.ReadSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"stop", "resume"} {
		if response := runtimeRequest(a, action); response.Code != 200 {
			t.Fatal("actual runtime HTTP/CAS", action, response.Code, response.Body.String())
		}
		owned, release, err := a.Operations.ExclusiveContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		control, err := a.managedNFQControl(owned)
		if err != nil || control.Reference().Sequence != before.Sequence || control.Current(owned) != nil {
			release()
			t.Fatal("service state invented or blocked a control epoch", action, err)
		}
		a.closeUnretainedManagedNFQControl(control)
		if control.Current(owned) == nil || a.managedNFQBundle.control != nil {
			release()
			t.Fatal("unused descriptor survived an initial-only operation")
		}
		release()
	}
	after, _, err := operationgate.ReadSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil || after.Stopped || after.Sequence != before.Sequence || after.InstallationID != before.InstallationID {
		t.Fatal("service resume changed durable control", err)
	}
	if _, err := os.Stat(a.StrategyLab.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("construction or service state created source history", err)
	}
	if a.StrategyLab.Executor != nil || len(a.StrategyLab.Snapshot().Candidates) != 0 {
		t.Fatal("initial lifecycle created a native or candidate capability")
	}
}

func TestManagedNFQDurableStopBlocksPlanInstallAndRepairWithoutImplicitResume(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	owned, release, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if control, err := a.ConfigureManagedNFQCompatibility(owned); err == nil || control != nil {
		release()
		t.Fatal("missing receipt configured a provider", err)
	}
	// An already admitted read cannot promote a stopped record to forward
	// permission. Availability uses the protected owner, never this DTO.
	stopped, err := operationgate.RequestSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot, strings.Repeat("c", 32), a.Store.Get().Revision)
	if err != nil {
		release()
		t.Fatal(err)
	}
	a.Components.StateDir = managedComponentsState
	caps := a.componentRecoveryCapabilities(owned, components.ManagedUpdateState{SchemaVersion: 3, Component: "nfqws2", Phase: components.UpdatePrepared}, true)
	if actions := caps["available_actions"].([]string); len(actions) != 0 {
		release()
		t.Fatal("durable Stop advertised repair", actions)
	}
	release()
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, a.SelfUpdateFiles.ControlRoot); !errors.Is(err, operationgate.ErrSelfUpdateStopped) {
		t.Fatal("repeated startup implicitly resumed durable Stop", err)
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{"GET", managedNFQBundlePlanPath, nil},
		{"POST", managedNFQBundleInstallPath, map[string]any{"expected_revision": a.Store.Get().Revision}},
	} {
		status, _ := componentHTTP(t, server, request.method, request.path, request.body, componentRecoveryToken, server.URL)
		if status != http.StatusServiceUnavailable {
			t.Fatal("durable Stop admitted a plan/install", request.path, status)
		}
	}
	current, _, err := operationgate.ReadSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot)
	if err != nil || !current.Stopped || current.Sequence != stopped.Sequence || current.Digest != stopped.Digest {
		t.Fatal("read or rejected install rewrote durable Stop", err)
	}
	if _, err := os.Stat(a.StrategyLab.Path); !errors.Is(err, os.ErrNotExist) || a.managedNFQBundle.control != nil {
		t.Fatal("durable Stop initialized source or retained a false epoch", err)
	}
}

func TestManagedNFQFailureStageDoesNotExposeUnderlyingDiagnostic(t *testing.T) {
	const sensitive = "/private/controller?token=not-for-response"
	for _, test := range []struct {
		stage, reason string
		err           error
	}{
		{"bundle_preflight", "MANAGED_NFQWS_AUTHORITY_UNAVAILABLE", errors.New(sensitive)},
		{"history", "MANAGED_NFQWS_RETAINED_CONTROLLER_BLOCKED", errors.Join(updatecheck.ErrComponentHistoryAdmission, errors.New(sensitive))},
		{"source_inactive", "MANAGED_NFQWS_SOURCE_NOT_INACTIVE", errors.Join(strategylab.ErrCompatibilityQuiescenceUnknown, errors.New(sensitive))},
	} {
		response := httptest.NewRecorder()
		(&App{}).writeManagedNFQBundleFailure(response, test.err, test.stage)
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusConflict || body["stage"] != test.stage || body["reason_code"] != test.reason || body["installed_idle"] != false || body["working_routes_changed"] != false {
			t.Fatal("failure lost its safe stage or claimed installation", response.Body.String())
		}
		if strings.Contains(response.Body.String(), sensitive) || strings.Contains(response.Body.String(), "not-for-response") {
			t.Fatal("underlying diagnostic escaped into the response")
		}
	}
}

func TestManagedNFQInstallRequiresPresentRevisionAndAcceptsExplicitZeroInput(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	if a.Store.Get().Revision != 0 {
		t.Fatal("fresh fixture is not the actual default configuration")
	}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, _ := componentHTTP(t, server, "POST", managedNFQBundleInstallPath, map[string]any{"expected_revision": nil}, componentRecoveryToken, server.URL)
	if status != http.StatusBadRequest {
		t.Fatal("null revision was treated as an explicit CAS revision", status)
	}
	status, data := componentHTTP(t, server, "POST", managedNFQBundleInstallPath, map[string]any{"expected_revision": uint64(0)}, componentRecoveryToken, server.URL)
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	// The test has no reviewed native platform/canonical component state. The
	// genuine HTTP decoder must reach that refusal without inventing revision1.
	if status != http.StatusConflict || body["stage"] == nil || a.Store.Get().Revision != 0 || a.managedNFQBundle.control != nil {
		t.Fatal("explicit zero input changed configuration or failed decoding", status, string(data))
	}
	if _, err := os.Stat(a.StrategyLab.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused first install created source state", err)
	}
}
