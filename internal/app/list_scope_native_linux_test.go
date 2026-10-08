//go:build linux

package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This opt-in observes the real router through the ordinary App binding.
// Only private test config/control files are written. No path proof, executor,
// native command, firewall or DNS mutation is supplied by the test.
func TestListScopeNativeOriginalApplicationBinding(t *testing.T) {
	if os.Getenv("RAZVILKA_LIST_SCOPE_NATIVE") != "stock-nc1812" {
		t.Skip("coordinator-owned read-only stock router observation required")
	}
	root, home := os.Getenv("RAZVILKA_LIST_SCOPE_NATIVE_ROOT"), os.Getenv("RAZVILKA_LIST_SCOPE_NATIVE_HOME")
	if os.Geteuid() != 0 || runtime.GOARCH != "arm64" || !filepath.IsAbs(root) || filepath.Clean(root) != root || home == "" {
		t.Fatal("actual root ARM64, private canonical root and explicit Home required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&077 != 0 {
		t.Fatal("private real root required", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("new empty test directory required", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatal("actual reviewed platform", err)
	}
	path, control := filepath.Join(root, "config.json"), filepath.Join(root, "control")
	store, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: control}}
	if err := a.ConfigureDefaultConsent(path, ""); err != nil {
		t.Fatal(err)
	}
	defer a.CloseDefaultConsent()
	var binding *ListScopeBinding
	defer func() {
		if binding != nil {
			_ = binding.Close()
		}
	}()
	operation := func(use func(context.Context)) {
		t.Helper()
		current, release, err := a.Operations.ExclusiveContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		use(current)
	}
	operation(func(current context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(current, control)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		ref := epoch.Reference()
		policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{home}, NewDevices: "inherit"}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
		if _, err := store.ApproveDefaultRouteConsent(current, store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		binding, err = NewReviewedStockNC1812ListScopeBinding(current, a, provider)
		if err != nil {
			t.Fatal("original App physical binding", err)
		}
	})
	before := store.Get()
	operation(func(current context.Context) {
		snapshot, err := binding.Observe(current)
		if err != nil {
			t.Fatal("fresh original operation", err)
		}
		if len(snapshot.Scope.Segments) != 1 || snapshot.Scope.Segments[0].ID != home || snapshot.DNSMode != "baseline" || len(snapshot.Paths) != 0 || snapshot.ProfileGeneration != 0 || snapshot.NodeGeneration != 0 || !reflect.DeepEqual(before, store.Get()) {
			t.Fatal("observation changed configuration or invented path proof")
		}
		t.Logf("actual App scope: segments=%d devices=%d no_paths=true no_network_mutation=true", len(snapshot.Scope.Segments), len(snapshot.Scope.Devices))
	})
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	operation(func(current context.Context) {
		if _, err := binding.Observe(current); err == nil {
			t.Fatal("closed original handle admitted observation")
		}
	})
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("original operation not released")
	}
}
