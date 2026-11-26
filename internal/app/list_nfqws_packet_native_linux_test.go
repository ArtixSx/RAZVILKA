//go:build linux

package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Real router observation and private App/Store/control only. The selected
// candidate is explicitly modeled comparison data, not a native source lease.
// No executor, adapter, queue, process, firewall or DNS mutation is supplied.
func TestNFQWSPacketNativeOriginalApplicationBinding(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQ_PACKET_NATIVE") != "stock-nc1812" {
		t.Skip("coordinator-owned read-only stock router observation required")
	}
	root, home := os.Getenv("RAZVILKA_NFQ_PACKET_NATIVE_ROOT"), os.Getenv("RAZVILKA_NFQ_PACKET_NATIVE_HOME")
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	if err = store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if _, err = operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	a := &App{Store: store, SelfUpdateFiles: &SelfUpdateFiles{ControlRoot: control}}
	if err = a.ConfigureDefaultConsent(path, ""); err != nil {
		t.Fatal(err)
	}
	defer a.CloseDefaultConsent()
	var binding *NFQWSPacketScopeBinding
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
	const excludedMAC = "02:00:00:00:00:55"
	operation(func(current context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(current, control)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		ref := epoch.Reference()
		policy := &config.NetworkPolicy{Schema: 2, Revision: 1, Clients: config.ClientScope{Mode: "lan_except", SegmentIDs: []string{home}, NewDevices: "inherit", ExcludedDeviceIDs: []string{"mac-02-00-00-00-00-55"}}, Traffic: config.TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
		if _, err = store.ApproveDefaultRouteConsent(current, store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		binding, err = NewReviewedStockNC1812NFQWSPacketScopeBinding(current, a, provider)
		if err != nil {
			t.Fatal("original App packet binding", err)
		}
	})
	before := store.Get()
	operation(func(current context.Context) {
		snapshot, err := binding.Observe(current)
		if err != nil {
			t.Fatal("original packet observation", err)
		}
		if snapshot.Facts.Home.ID != home || len(snapshot.Facts.IPv4Prefixes) != 1 || snapshot.DNSMode != "baseline" || !slices.Contains(snapshot.Facts.ExcludedMACs, excludedMAC) || !reflect.DeepEqual(before, store.Get()) {
			t.Fatal("observation changed private intent or lost offline exclusion")
		}
		_, comparison, routes, _ := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
		routes[0].CIDRs = []string{"1.1.1.1/32"}
		compiled, err := CompileNFQWSIPv4LANPacketPolicy(before, snapshot, routes, map[string]DefaultRoutePath{"listed": comparison.Paths["listed"]}, time.Now())
		if err != nil || compiled == nil || compiled.LAN() == nil || len(compiled.Rules()) == 0 {
			t.Fatal("comparison-only compiler", err)
		}
		if err = binding.BindCompilation(current, compiled); err != nil {
			t.Fatal("original comparison binding", err)
		}
		if err = binding.ScopeCheck(current, compiled.LAN()); err != nil {
			t.Fatal("original scope before private CAS", err)
		}
		cleanup, err := a.Operations.ReviewExclusiveCleanup(current)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, err = store.CommitNetworkPolicyWithRollback(before, compiled.Policy(), before.Services)
		finished := time.Now()
		if err != nil {
			t.Fatal("private Store CAS", err)
		}
		if err = binding.AcceptCommitted(current, store.Get(), started, finished); err != nil {
			t.Fatal("same original owner after private CAS", err)
		}
		if err = binding.ScopeCheck(current, compiled.LAN()); err != nil {
			t.Fatal("original packet owner after private CAS", err)
		}
		if store.Get().DefaultRouteConsent.ApprovalRevision != before.DefaultRouteConsent.ApprovalRevision {
			t.Fatal("private commit replaced the original approval")
		}
		if err = cleanup.WithCurrent(current, func() error { return binding.cleanupScopeCheck(current, compiled.LAN()) }); err != nil {
			t.Fatal("original retained cleanup observation", err)
		}
		t.Logf("actual Home packet reader + App/Store/control/CAS + retained observation; rules=%d; selected_source=modeled; network_mutations=0; native_NFQ_proof=false", len(compiled.Rules()))
	})
	if err = binding.Close(); err != nil {
		t.Fatal("original reader close/join", err)
	}
	operation(func(current context.Context) {
		if _, err := binding.Observe(current); err == nil {
			t.Fatal("closed original packet owner admitted use")
		}
	})
	if a.Operations.Snapshot().Active != 0 {
		t.Fatal("original operation not released")
	}
}
