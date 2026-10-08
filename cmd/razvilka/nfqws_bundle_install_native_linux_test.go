//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// This opt-in actually installs the fixed reviewed payload through the panel.
// Root supplies its owned ARM64 deployment, actual /opt/bin/razvilka identity,
// readable retained fleet and a new private empty source root. No fixture
// archive, receipt, trusted-assets flag or substituted admission is accepted.
func TestManagedNFQBundleFirstInstallAppHTTP(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_MANAGED_INSTALL_APP") != "1" {
		t.Skip("coordinator-owned genuine ARM64 first installation required")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" {
		t.Fatal("actual root ARM64 installation required")
	}
	root := os.Getenv("RAZVILKA_NATIVE_MANAGED_INSTALL_APP_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("canonical owned source root required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		t.Fatal("new private real directory required", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("new empty source directory required", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	owner := components.New()
	if floor, err := components.RequiredRetainedManagedUpdateReadVersion(ctx, owner.StateDir); err != nil || floor != components.ComponentUpdateSchema {
		t.Fatal("first managed installation requires readable pre-schema3 component state", floor, err)
	}
	if installed, err := owner.AcquireCurrentManagedNFQWSRuntime(ctx); err == nil {
		_ = installed.Close()
		t.Fatal("genuine managed bundle already installed; do not erase its history to repeat this test")
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
	controlRoot := filepath.Join(root, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	const token = "native-managed-install-owned-token-0123456789"
	sec, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Store: store, StrategyLab: manager, Components: owner, Security: sec, SelfUpdateFiles: &app.SelfUpdateFiles{ControlRoot: controlRoot}, ComponentHistory: updatecheck.NewComponentHistoryAdmission(app.ManagedComponentReadVersion)}
	defer a.CloseManagedNFQControl()
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	if control, err := configureManagedNFQCompatibility(ctx, a); err == nil || control != nil {
		t.Fatal("missing receipt configured startup compatibility", err)
	}
	before := store.Get()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	request := func(method, path, body string, out any) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			t.Fatal("actual API response", response.StatusCode, err)
		}
		return response.StatusCode
	}
	var plan struct {
		Ready    bool   `json:"ready"`
		Revision uint64 `json:"revision"`
		Code     string `json:"code"`
		Reason   string `json:"reason"`
	}
	if status := request("GET", "/api/v1/components/nfqws2/managed-bundle/plan", "", &plan); status != 200 || !plan.Ready || plan.Revision != before.Revision {
		t.Fatal("actual retained fleet/control/config did not admit the installation plan", status, plan)
	}
	if _, err := os.Stat(manager.Path); !os.IsNotExist(err) {
		t.Fatal("plan initialized source", err)
	}
	body, _ := json.Marshal(map[string]uint64{"expected_revision": plan.Revision})
	var result struct {
		OK         bool                                 `json:"ok"`
		Receipt    components.ManagedNFQWSBundleReceipt `json:"receipt"`
		Installed  bool                                 `json:"installed_idle"`
		Compatible bool                                 `json:"compatibility_ready"`
	}
	if status := request("POST", "/api/v1/components/nfqws2/managed-bundle/install", string(body), &result); status != 200 || !result.OK || !result.Installed || !result.Compatible {
		t.Fatal("actual first install or original source handover refused", status, result)
	}
	manifest, err := components.ReviewedManagedNFQWSManifest(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := manifest.Digest()
	if err != nil || result.Receipt.ManifestSHA256 != digest || result.Receipt.ProviderID != manifest.ProviderID || result.Receipt.Flavor != manifest.Flavor || result.Receipt.State != "ready-idle" {
		t.Fatal("installed receipt does not match reviewed payload", err)
	}
	var readback struct {
		Installed bool   `json:"installed_idle"`
		ID        string `json:"receipt_id"`
		Hash      string `json:"manifest_sha256"`
	}
	if status := request("GET", "/api/v1/components/nfqws2/managed-bundle/installed", "", &readback); status != 200 || !readback.Installed || readback.ID != result.Receipt.TransactionID || readback.Hash != digest {
		t.Fatal("independent current lease readback does not match install", status, readback)
	}
	snapshot := manager.Snapshot()
	saved, err := os.ReadFile(manager.Path)
	if err != nil || len(snapshot.Candidates) != 0 || len(snapshot.Evidence) != 0 || len(snapshot.Selections) != 0 || snapshot.QuiescenceUnknown || bytes.Contains(saved, []byte(`"wait_echild": true`)) || bytes.Contains(saved, []byte(`"acknowledged": true`)) {
		t.Fatal("first installation invented history or candidates", err)
	}
	if !reflect.DeepEqual(before, store.Get()) || !before.SafeMode || before.NetworkPolicy != nil || before.DefaultRouteConsent != nil || manager.Executor != nil || snapshot.Safety["temporary_scoped_firewall_probe"] != false || a.Operations.Snapshot().Active != 0 {
		t.Fatal("idle installation changed routes, scope or native probing")
	}
	t.Log("actual ARM64 first panel install: original closed source initialized, reviewed payload installed, fresh runtime readback and locked provider handover passed; no native compatibility, route or client-health claim")
}
