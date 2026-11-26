//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/onboarding"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

const nfqAutopilotPinnedURL = "https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_all_entware.ipk"
const nfqAutopilotPinnedDigest = "28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054"

// HTTPS acquisition returns the exact pinned offline archive. The isolated
// launcher creates the fixture WAN and seeds its dependency database. The
// worker, component manager, supervisor, opkg, kernel inventory, and first
// Apply preflight run against the original checks and the actual tool images.
func TestNFQWSAutoInitialNativeStockScopeRefusal(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQ_AUTOPILOT_NATIVE") != "1" {
		t.Skip("requires the disposable native NFQWS autopilot launcher")
	}
	root := os.Getenv("TMPDIR")
	requireNFQAutopilotFixture(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), 145*time.Second)
	defer cancel()
	archive := readNFQAutopilotFixtureFile(t, os.Getenv("RAZVILKA_NFQWS_INITIAL_IPK"))
	if h := sha256.Sum256(archive); hex.EncodeToString(h[:]) != nfqAutopilotPinnedDigest || len(archive) != 2382102 {
		t.Fatal("wrong upstream package image")
	}
	profile, err := systemprobe.FreshWANProfile(ctx)
	if err != nil || profile.WANInterface != "eth3" {
		t.Fatal("real isolated WAN inventory unavailable", profile.WANInterface, err, systemprobe.NetworkEpochStatus())
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil || store.SetSafeMode(false) != nil {
		t.Fatal("private user store", err)
	}
	dns, err := dnscontrol.New(filepath.Join(root, "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := strategylab.New(filepath.Join(root, "strategies.json"))
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(root, "control")
	if _, err = operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal("actual control epoch", err)
	}
	native := components.New()
	if native.Opkg != "/opt/bin/opkg" || !filepath.IsAbs(native.StateDir) {
		t.Fatal("production component manager did not discover private Entware opkg")
	}
	var downloads atomic.Int32
	native.Client = &http.Client{Transport: nfqAutopilotNativeArchive(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != nfqAutopilotPinnedURL || downloads.Add(1) != 1 {
			return nil, errors.New("unexpected package fetch")
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(archive)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(archive))}, nil
	})}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	manager, err := newDataplaneManagerWithNodes(filepath.Join(root, "dataplane"), configs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(registerScopedDNS(manager, dns), manager.ConfigureNFQWSStockNative(native)); err != nil {
		t.Fatal("production installer and scoped DNS owner binding", err)
	}
	binding, cancelBinding := context.WithTimeout(ctx, 20*time.Second)
	_, closeSources, err := runtimeManagerSourcesBoundLifetime(binding, ctx, func() (*dataplane.Manager, error) { return manager, nil }, dns.Path)
	cancelBinding()
	if err != nil {
		t.Fatalf("native stock preparation source refused before any worker or package operation: %s: %v", selfUpdateRuntimeManagerFailureStage(err), err)
	}
	defer func() {
		if err := closeSources(); err != nil {
			t.Error("native tool lease closure", err)
		}
	}()
	adapter, ok := manager.Adapters["nfqws2"].(*dataplane.NFQWS2Adapter)
	if !ok {
		t.Fatal("original NFQWS2 adapter missing")
	}
	if err := adapter.VerifyRuntimeInactive(ctx); err != nil {
		t.Fatal("fresh pre-worker inventory cannot prove inactivity", dataplane.NFQWSRuntimeInactiveStage(err), err)
	}
	token := strings.Repeat("N", 40)
	securityGate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Store: store, Catalog: catalog.NFQWS2Starter(), DNS: dns, EngineConfigs: configs, StrategyLab: strategy,
		Components: native, Dataplane: manager, Security: securityGate,
		ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion),
		SelfUpdateFiles:  &app.SelfUpdateFiles{Directory: filepath.Join(root, "self-update"), ControlRoot: control},
	}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	handler := a.Handler(http.NotFoundHandler())
	var initial struct {
		Policy  autonomy.Policy          `json:"policy"`
		Starter onboarding.StarterReview `json:"starter"`
	}
	readNFQAutopilotAPI(t, ctx, handler, token, http.MethodGet, nil, &initial)
	const service = "discord"
	if !initial.Starter.Eligible || initial.Policy.SetupComplete || store.Get().NetworkPolicy != nil {
		t.Fatal("fresh reviewed starter setup unavailable")
	}
	p := initial.Policy
	allow := true
	p.SetupComplete, p.Enabled, p.AllLAN = true, true, true
	p.InstallMissingComponents, p.SourceIDs, p.DefaultSources = &allow, nil, nil
	p.PreferredRoutes = []string{"nfqws2"}
	p.Application.Mode, p.Components.Mode = "off", "off"
	readNFQAutopilotAPI(t, ctx, handler, token, http.MethodPut, map[string]any{
		"expected_revision": initial.Policy.Revision, "policy": p, "confirm": "SAVE_AUTONOMY",
		"starter_sha256": initial.Starter.SHA256, "starter_service_ids": []string{service},
	}, nil)
	if _, err := os.Lstat("/opt/usr/bin/nfqws2"); !errors.Is(err, os.ErrNotExist) || downloads.Load() != 0 {
		t.Fatal("package unexpectedly present before background worker", err)
	}

	started := time.Now()
	a.StartServiceReconciler(ctx)
	defer func() {
		join, cancelJoin := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancelJoin()
		if err := a.WaitServiceReconciler(join); err != nil {
			t.Error("worker failed to join", err)
		}
	}()
	status := waitNFQAutopilotApply(t, ctx, manager, native, store.AutomationStatePath()+".autonomy.json", service)
	join, cancelJoin := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancelJoin()
	if err := a.WaitServiceReconciler(join); err != nil {
		t.Fatal("worker did not join after the terminal outcome", err)
	}
	final := store.Get()
	if status.CommittedPlan != nil || final.AppliedServices[service].Enabled || !final.Services[service].Enabled || final.Services[service].Route != "nfqws2" {
		t.Fatal("first Apply changed applied routes or lost the selected service")
	}
	if status.Execution.State != "canary-failed" || !strings.Contains(status.Execution.Error, dataplane.ErrNFQWSFirstStartScope.Error()) {
		t.Fatalf("first Apply ended at a different boundary: %s %s %+v", status.Execution.State, status.Execution.Error, status.Execution.Steps)
	}
	for _, step := range status.Execution.Steps {
		if step.Phase == "activate" || step.Phase == "health" || strings.HasPrefix(step.Phase, "commit") {
			t.Fatalf("refused Apply reached effect phase: %+v", step)
		}
	}
	state, pending, err := native.PendingManagedUpdate()
	if err != nil || pending || downloads.Load() != 1 || !state.InstalledIdleAccepted() {
		t.Fatal("native package idle acceptance missing", state, pending, err)
	}
	var supervisor struct {
		State      string `json:"state"`
		ExitCode   int    `json:"exit_code"`
		WaitECHILD bool   `json:"wait_echild"`
	}
	journal := filepath.Join(native.StateDir, "update-journal", state.TransactionID, "install.supervision.json")
	if err := json.Unmarshal(readNFQAutopilotFixtureFile(t, journal), &supervisor); err != nil || supervisor.State != "reaped" || supervisor.ExitCode != 0 || !supervisor.WaitECHILD {
		t.Fatal("verified native package supervisor did not reap its descendants", supervisor, err)
	}
	if err := adapter.VerifyRuntimeInactive(ctx); err != nil {
		t.Fatal("native queue/process/firewall proof after refused Apply", dataplane.NFQWSRuntimeInactiveStage(err), err)
	}
	if !manager.NFQWS2FirstStartAvailable() || a.Operations.Snapshot().Active != 0 {
		t.Fatal("accepted idle package or original operation closure lost")
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if err != nil || acceptedAt.Before(started) || acceptedAt.After(time.Now()) {
		t.Fatalf("native idle receipt has an invalid elapsed time: %v %v", acceptedAt, err)
	}
	t.Logf("authenticated wizard -> router worker -> exact native IPK accepted idle -> first Apply refused by original stock policy scope; idle_elapsed=%s total_elapsed=%s package=%s execution=%s", acceptedAt.Sub(started), time.Since(started), state.Phase, status.Execution.State)
}

type nfqAutopilotNativeArchive func(*http.Request) (*http.Response, error)

func (f nfqAutopilotNativeArchive) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func requireNFQAutopilotFixture(t *testing.T, root string) {
	t.Helper()
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(root, "/tmp/razvilka-nfq-autopilot.") {
		t.Fatal("private launcher, root and canonical TMPDIR required")
	}
	for mount, fd := range map[string]int{"net": 3, "mnt": 4} {
		outer, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		inner, ownErr := os.Readlink("/proc/self/ns/" + mount)
		if err != nil || ownErr != nil || !strings.HasPrefix(outer, mount+":") || !strings.HasPrefix(inner, mount+":") || outer == inner {
			t.Fatal("fixture isolation not established", mount, err, ownErr)
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("launcher private directory is unavailable", err)
	}
	mounts := readNFQAutopilotFixtureFile(t, "/proc/self/mountinfo")
	var privateOpt bool
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 9 && fields[4] == "/opt" && strings.Contains(line, " - tmpfs ") {
			privateOpt = true
		}
	}
	if !privateOpt {
		t.Fatal("/opt is not a private tmpfs")
	}
}

func readNFQAutopilotFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(path, err)
	}
	return data
}

func readNFQAutopilotAPI(t *testing.T, ctx context.Context, handler http.Handler, token, method string, input, output any) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "/api/v1/autonomy", bytes.NewReader(data)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal(method, response.Code, response.Body.String())
	}
	if output != nil {
		if err := json.Unmarshal(response.Body.Bytes(), output); err != nil {
			t.Fatal(err)
		}
	}
}

func waitNFQAutopilotApply(t *testing.T, ctx context.Context, manager *dataplane.Manager, native *components.Manager, runtimePath, service string) dataplane.RuntimeStatus {
	t.Helper()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		var doc struct {
			Runtime map[string]autonomy.Runtime `json:"runtime"`
		}
		if err := json.Unmarshal(readNFQAutopilotFixtureFile(t, runtimePath), &doc); err != nil {
			t.Fatal("read persisted worker outcome", err)
		}
		status, err := manager.Status()
		if err != nil {
			t.Fatal("dataplane readback", err)
		}
		switch runtime := doc.Runtime[service]; runtime.State {
		case "pending", "checking", "applying":
		case "apply-refused":
			if status.Execution != nil && status.Execution.FinishedAt != "" && status.Execution.Error != "" {
				return status
			}
			fallthrough
		default:
			state, pending, err := native.PendingManagedUpdate()
			t.Fatalf("worker stopped before stock scope refusal: state=%s message=%s component=%+v pending=%v err=%v execution=%+v", runtime.State, runtime.Message, state, pending, err, status.Execution)
		}
		if status.CommittedPlan != nil {
			t.Fatal("unexpected committed plan")
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			state, pending, e := native.PendingManagedUpdate()
			t.Fatalf("worker did not reach first Apply: component=%+v pending=%v err=%v dataplane=%+v deadline=%v", state, pending, e, status, ctx.Err())
		}
	}
}
