//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// The native compiled test binary is its own protected helper, using the SAME
// production early CLI dispatch. No provider test prefix or asset approval is
// introduced; all other invocations use the ordinary Go test runner.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "-node-history-read-version" {
		os.Exit(mainWithSelfUpdateJournalRoots(productionSelfUpdateJournalRoots()))
	}
	if handled, code := runComponentReadCommand(os.Args[1:], productionComponentStateDirectory); handled {
		os.Exit(code)
	}
	if len(os.Args) > 1 && os.Args[1] == "nfqws-compatibility-supervisor" {
		handled, code := runCommand(os.Args[1:])
		if !handled {
			code = 2
		}
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestNativeTestBinaryNodeHistoryMetadataDispatch(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal("actual test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, self, "-node-history-read-version").Output()
	if err != nil || ctx.Err() != nil || len(output) > 32 || string(output) != strconv.Itoa(nodestore.ExactHistoryReadVersion)+"\n" {
		t.Fatal("actual test binary did not dispatch the production node history metadata reader")
	}
}

// Root opts in only with an existing genuine installer-produced Components
// state and a new private root in its owned ARM64 environment. The test never
// installs an archive, invents a receipt, runs main networking or grants scope.
func TestManagedNFQCompatibilityInstalledAppHTTP(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_MANAGED_APP") != "1" {
		t.Skip("coordinator-owned ARM64 genuine installed bundle required")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("genuine reviewed bundle requires root ARM64 environment")
	}
	root := os.Getenv("RAZVILKA_NATIVE_MANAGED_APP_ROOT")
	stateRoot := os.Getenv("RAZVILKA_COMPONENT_STATE")
	for _, path := range []string{root, stateRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatal("explicit canonical owned root required")
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		t.Fatal("new test root must be a private real directory", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("new empty owned test root required", err)
	}
	owner := components.New()
	owner.StateDir = stateRoot
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	installed, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("genuine current installed source required", err)
	}
	descriptor := installed.Descriptor()
	if err := installed.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := config.Load(filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := strategylab.New(filepath.Join(root, "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager.Validator, manager.Executor = strategylab.CompatibleValidator{}, nil
	candidate, err := manager.AddCandidate("tcp-tls", "installed compatibility", "--filter-tcp=443 --lua-desync=fake:blob=tls_clienthello", "expert")
	if err != nil {
		t.Fatal(err)
	}
	files, err := productionSelfUpdateFiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, files.ControlRoot); err != nil {
		t.Fatal(err)
	}
	const token = "native-managed-compatibility-owned-token-0123456789"
	securityGate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Store: store, StrategyLab: manager, Components: owner, Security: securityGate, SelfUpdate: files.Helper, SelfUpdateFiles: files, ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	control, err := configureManagedNFQCompatibility(ctx, a)
	if err != nil {
		t.Fatal("actual managed startup constructor", err)
	}
	defer control.Close()
	before := store.Get()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/strategy-lab/candidates/"+candidate.ID+"/validate", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Origin", server.URL)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var checked strategylab.Candidate
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&checked) != nil {
		t.Fatal("actual managed HTTP compatibility did not complete", response.StatusCode)
	}
	if !checked.Validation.OK || !checked.Validation.Native || !checked.Validation.LuaChecked || checked.Validation.QuiescenceUnknown || checked.Validation.Code != "COMPATIBLE" || manager.Snapshot().QuiescenceUnknown || a.Operations.Snapshot().Active != 0 {
		t.Fatal("genuine compatibility/retirement was not confirmed", checked.Validation.Code)
	}
	if !reflect.DeepEqual(store.Get(), before) || before.NetworkPolicy != nil || before.DefaultRouteConsent != nil || manager.Executor != nil || manager.Snapshot().Safety["temporary_scoped_firewall_probe"] != false {
		t.Fatal("compatibility changed configuration, scope or probe availability")
	}
	saved, err := os.ReadFile(manager.Path)
	if err != nil || !bytes.Contains(saved, []byte(`"wait_echild": true`)) || !bytes.Contains(saved, []byte(`"acknowledged": true`)) {
		t.Fatal("real ECHILD and parent ACK were not saved", err)
	}
	current, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		t.Fatal("exact runtime lease was not retired after HTTP completion", err)
	}
	defer current.Close()
	if !reflect.DeepEqual(current.Descriptor(), descriptor) {
		t.Fatal("compatibility changed installed generation")
	}
	t.Log("actual installed ARM64 bundle: main constructor, authenticated HTTP, dry-run+Lua and original completion retirement passed; no route or client health claim")
}
