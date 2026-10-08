package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func TestManagedNFQBundleHTTPReadAuthCSRFCASAndTrustInputsNeverInitializeSource(t *testing.T) {
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
	owner := components.New()
	owner.StateDir = filepath.Join(base, "components")
	if err := os.Mkdir(owner.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	sec, err := security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, StrategyLab: manager, Components: owner, Security: sec, ComponentHistory: updatecheck.NewComponentHistoryAdmission(ManagedComponentReadVersion)}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	before := store.Get()
	image, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		method, path, token, origin string
		body                        any
		want                        int
	}{
		{"GET", managedNFQBundlePlanPath, "", server.URL, nil, 401},
		{"GET", managedNFQBundlePlanPath, componentRecoveryToken, server.URL, nil, 200},
		{"GET", managedNFQBundleInstalledPath, componentRecoveryToken, server.URL, nil, 503},
		{"POST", managedNFQBundleInstallPath, "", server.URL, map[string]any{"expected_revision": before.Revision}, 401},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, "https://foreign.example", map[string]any{"expected_revision": before.Revision}, 403},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, map[string]any{}, 400},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, map[string]any{"expected_revision": before.Revision, "trusted_assets": true}, 400},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, map[string]any{"expected_revision": before.Revision, "receipt": "request supplied"}, 400},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, map[string]any{"expected_revision": before.Revision, "manifest": map[string]any{"architecture": "arm64"}}, 400},
		{"POST", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, map[string]any{"expected_revision": before.Revision}, 409},
		{"GET", managedNFQBundleInstallPath, componentRecoveryToken, server.URL, nil, 405},
	} {
		status, data := componentHTTP(t, server, request.method, request.path, request.body, request.token, request.origin)
		if status != request.want {
			t.Fatal(request.method, request.path, status, string(data))
		}
		if !reflect.DeepEqual(before, store.Get()) || manager.Executor != nil || manager.Snapshot().QuiescenceUnknown {
			t.Fatal("read or refused request changed actual configuration/source")
		}
		if _, err := os.Stat(manager.Path); !os.IsNotExist(err) {
			t.Fatal("read or refused request initialized missing source", err)
		}
		entries, err := os.ReadDir(owner.StateDir)
		if err != nil || len(entries) != 0 {
			t.Fatal("read or refusal created component state", err)
		}
	}
	after, err := os.ReadFile(filepath.Join(base, "config.json"))
	afterInfo, statErr := os.Stat(filepath.Join(base, "config.json"))
	if err != nil || statErr != nil || !bytes.Equal(image, after) || !os.SameFile(info, afterInfo) || a.Operations.Snapshot().Active != 0 {
		t.Fatal("request changed persisted config or retained operation", err, statErr)
	}
}

func TestManagedNFQResumeCannotReplayLegacyPackageRecovery(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); err != components.ErrUpdatePending {
		t.Fatal(err)
	}
	beforeCalls := append([]string(nil), runner.calls...)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	status, data := componentHTTP(t, server, "POST", "/api/v1/components/recovery", recoveryBody(a, "resume"), componentRecoveryToken, server.URL)
	if status != 400 || !reflect.DeepEqual(beforeCalls, runner.calls) {
		t.Fatal("managed resume reached legacy package execution", status, string(data), runner.calls)
	}
}
