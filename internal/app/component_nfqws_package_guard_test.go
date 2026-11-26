package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func installOwnedNFQWSInitFixture(t *testing.T, a *App) {
	t.Helper()
	stock, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	inert, err := engineconfig.NFQWSFirstStartInit(stock, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.Components.InitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.Components.InitDir, "S51nfqws2"), inert, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWSOwnedPackageAppMutationsRefuseBeforeEffects(t *testing.T) {
	for _, action := range []string{"install", "update", "remove"} {
		t.Run(action, func(t *testing.T) {
			a, runner := componentHTTPFixture(t)
			installOwnedNFQWSInitFixture(t, a)
			before := len(runner.calls)
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			code, body := componentHTTP(t, s, http.MethodPost, "/api/v1/components/nfqws2/"+action, nil, componentRecoveryToken, s.URL)
			if code != http.StatusConflict || !strings.Contains(string(body), "NFQWS_OWNED_PROFILE_PACKAGE_UNSUPPORTED") {
				t.Fatalf("%d %s", code, body)
			}
			if len(runner.calls) != before {
				t.Fatal("blocked request reached package runner", runner.calls[before:])
			}
			if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrNFQWSOwnedPackageMutation) {
				t.Fatal("scheduled update wrong refusal", err)
			}
			if len(runner.calls) != before {
				t.Fatal("scheduled refusal reached package runner", runner.calls[before:])
			}
		})
	}
}

func TestNFQWSPackageAdvisoryCannotAuthorizeLaterMutation(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.nfqwsPackageMutationGuard("nfqws2"); err != nil {
		t.Fatal(err)
	}
	guard := a.nfqwsPackageUpdateGuard("nfqws2", func(context.Context) error { return nil })
	views := []components.View{{Spec: components.Spec{ID: "nfqws2"}, CanInstall: true, CanUpdate: true, CanRemove: true}}
	a.enrichNFQWSPackageInventory(views)
	if !views[0].CanUpdate {
		t.Fatal("unowned package hidden")
	}
	installOwnedNFQWSInitFixture(t, a)
	before := len(runner.calls)
	if err := guard(context.Background()); !errors.Is(err, components.ErrNFQWSOwnedPackageMutation) {
		t.Fatal("stale advisory accepted", err)
	}
	a.enrichNFQWSPackageInventory(views)
	if views[0].CanInstall || views[0].CanUpdate || views[0].CanRemove || views[0].LifecycleBlockReason == "" {
		t.Fatal("owned capabilities advertised", views)
	}
	a.Dataplane = nil
	if err := a.nfqwsPackageMutationGuard("nfqws2"); !errors.Is(err, components.ErrNFQWSPackageOwnershipUnknown) {
		t.Fatal("missing actual DP allowed mutation", err)
	}
	if len(runner.calls) != before {
		t.Fatal("advisory executed package command")
	}
}

func TestNFQWSPackageHTTPFailsClosedOnMissingOrCorruptOwner(t *testing.T) {
	for _, state := range []string{"missing-dataplane", "corrupt-lease", "malformed-init"} {
		t.Run(state, func(t *testing.T) {
			a, runner := componentHTTPFixture(t)
			switch state {
			case "missing-dataplane":
				a.Dataplane = nil
			case "corrupt-lease":
				dir := filepath.Join(a.Dataplane.StateRoot, "runtime", "nfqws2")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "ownership.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed-init":
				installOwnedNFQWSInitFixture(t, a)
				f, err := os.OpenFile(filepath.Join(a.Components.InitDir, "S51nfqws2"), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.WriteString("echo foreign\n"); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := len(runner.calls)
			s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
			defer s.Close()
			code, body := componentHTTP(t, s, http.MethodPost, "/api/v1/components/nfqws2/remove", nil, componentRecoveryToken, s.URL)
			if code != http.StatusConflict || !strings.Contains(string(body), "NFQWS_PACKAGE_OWNERSHIP_UNKNOWN") {
				t.Fatalf("%d %s", code, body)
			}
			if len(runner.calls) != before {
				t.Fatal("unknown ownership reached package runner", runner.calls[before:])
			}
		})
	}
}

func TestNFQWSMatchingPackageRollbackRechecksOwnership(t *testing.T) {
	a, runner := componentHTTPFixture(t)
	if err := a.updateComponent(context.Background(), "nfqws2"); !errors.Is(err, components.ErrUpdatePending) {
		t.Fatal("create actual pending package transaction", err)
	}
	installOwnedNFQWSInitFixture(t, a)
	before := len(runner.calls)
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	code, body := componentHTTP(t, s, http.MethodPost, "/api/v1/components/recovery", recoveryBody(a, "rollback"), componentRecoveryToken, s.URL)
	if code != http.StatusConflict || !strings.Contains(string(body), "NFQWS_OWNED_PROFILE_PACKAGE_UNSUPPORTED") {
		t.Fatalf("%d %s", code, body)
	}
	if len(runner.calls) != before || !a.PendingComponentRecovery() {
		t.Fatal("blocked rollback changed package or cleared recovery", runner.calls[before:])
	}
	state, pending, err := a.Components.PendingManagedUpdate()
	if err != nil {
		t.Fatal(err)
	}
	caps := a.componentRecoveryCapabilities(context.Background(), state, pending)
	for _, action := range caps["available_actions"].([]string) {
		if action == "rollback" {
			t.Fatal("blocked rollback advertised", caps)
		}
	}
}
