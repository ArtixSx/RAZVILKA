//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// ROOT-only actual dependency QA: real held thread task/net, PID/exe/argv/stat
// census and TCP/UDP socket presence/closure. No fake kernel callback is used;
// this does not claim full observer/backend/platform acceptance.
func TestScopedDNSInactiveNativeProcDependency(t *testing.T) {
	if os.Getenv("RAZVILKA_SCOPED_DNS_INACTIVE_NATIVE") != "1" {
		t.Skip("ROOT actual Linux dependency opt-in")
	}
	scopedDNSInactiveNativeDependency(t, netidentity.NewProcProvider())
}

func TestScopedDNSInactiveNativeReviewedStockDependency(t *testing.T) {
	if os.Getenv("RAZVILKA_SCOPED_DNS_INACTIVE_NATIVE") != "1" {
		t.Skip("ROOT actual stock dependency opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	provider, err := netidentity.NewReviewedStockNC1812Provider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scopedDNSInactiveNativeDependency(t, provider)
}

func scopedDNSInactiveNativeDependency(t *testing.T, provider *netidentity.Provider) {
	t.Helper()
	proof, err := scopedDNSInactivePlatformProof()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), scopedDNSAdapterID)
	settings := filepath.Join(filepath.Dir(root), "settings.json")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := provider.WithCurrent(ctx, func(held context.Context, _ netidentity.Identity) error {
		want := fmt.Sprintf("/proc/%d/task/%d/net", os.Getpid(), syscall.Gettid())
		if proof.threadNetRoot == nil || proof.threadNetRoot() != want {
			t.Fatal("socket census was not bound to held TID")
		}
		if err := scopedDNSInactiveProc(held, proof, root, settings, nil); err != nil {
			return err
		}
		udp, tcp, err := listenScopedDNS(netip.MustParseAddrPort("127.0.0.1:0"))
		if err != nil {
			return err
		}
		defer udp.Close()
		defer tcp.Close()
		ports := map[uint16]bool{udp.LocalAddr().(*net.UDPAddr).AddrPort().Port(): true}
		if err := scopedDNSInactiveProc(held, proof, root, settings, ports); err == nil {
			t.Fatal("real TCP/UDP listener accepted as absent")
		}
		if err := udp.Close(); err != nil {
			return err
		}
		if err := tcp.Close(); err != nil {
			return err
		}
		return scopedDNSInactiveProc(held, proof, root, settings, ports)
	}); err != nil {
		t.Fatal(err)
	}
}
