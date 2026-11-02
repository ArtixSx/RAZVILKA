//go:build linux && amd64 && razvilka_native_fixture

package dataplane_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/startuptools"
)

// Historical intent is modeled. EVERY current process/socket/kernel/source
// observation is the real public offline implementation. This is a disposable
// Linux acceptance test, not evidence of a hardware reboot or CLI lease setup.
func TestMihomoLiveColdPublicNativeHistoricalIntent(t *testing.T) {
	if os.Getenv("RAZVILKA_MANAGED_PROBE_NATIVE") != "1" {
		t.Skip("disposable native fixture only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		host, hostErr := os.Readlink("/proc/1/ns/" + kind)
		if os.Geteuid() != 0 || err != nil || hostErr != nil || self == host {
			t.Fatal("separate actual root namespace required", kind)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	l, err := startuptools.AcquireNativeFixturePolicy(ctx, provider, os.Getenv("RAZVILKA_MANAGED_PROBE_TOOLS_REVIEW"))
	if err != nil {
		t.Fatal("original tool lease", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	}()
	identity, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, historical := dataplane.MihomoColdHistoricalFixtureForExternalTest(t)
	if historical.Resources[0].MihomoLive.NetworkIdentity.BootID == identity.BootID {
		t.Fatal("fixture requires different historical boot")
	}
	original, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	tools, err := l.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := dataplane.NewBackendInventory(provider, tools)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := dataplane.NewProxyTunnelAdapter("sing-box", nil, m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	proxy.SidecarKind, proxy.SidecarBin = "hev", "/opt/bin/hev-socks5-tunnel"
	for _, a := range []dataplane.Adapter{dataplane.NewNFQWS2Adapter(), dataplane.NewScopedDNSAdapter(ctx, nil, m.StateRoot), proxy} {
		if err := m.Register(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.BindRuntimeInactivitySources(ctx, provider, inventory, filepath.Join(m.StateRoot, "dns.json")); err != nil {
		t.Fatal("actual source binding", err)
	}
	current := func(c context.Context) error { return l.Check(c, identity) }
	after, err := m.RetireMihomoLiveAfterBoot(ctx, historical.PlanID, historical.Digest, current)
	if err != nil {
		t.Fatal("public retirement with real negative observations", err)
	}
	if after.State != "rolled-back" || after.RollbackVerified || len(after.Resources) != len(historical.Resources) {
		t.Fatal("incorrect terminal history", after.State)
	}
	for _, r := range after.Resources {
		if r.State != "removed" {
			t.Fatal("nonterminal resource", r.Kind)
		}
	}
	latest, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := os.ReadFile(filepath.Join(m.StateRoot, "transactions", historical.PlanID, "execution.json"))
	if err != nil || !bytes.Equal(latest, transaction) {
		t.Fatal("two terminal writers diverged", err)
	}
	archive, err := os.ReadFile(filepath.Join(m.StateRoot, "mihomo-live-retirements", historical.PlanID, "retirement.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Before, After []byte }
	if json.Unmarshal(archive, &manifest) != nil || !bytes.Equal(manifest.Before, original) || !bytes.Equal(manifest.After, latest) {
		t.Fatal("original history not retained")
	}
	if _, err := m.RetireMihomoLiveAfterBoot(ctx, historical.PlanID, historical.Digest, current); err != nil {
		t.Fatal("idempotent public retry", err)
	}
	t.Log("public offline retirement and repeat passed with actual current process/socket/kernel/source observations; historical old boot is modeled")
}
