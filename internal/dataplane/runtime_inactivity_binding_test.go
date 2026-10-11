package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestRuntimeInactivityStartupBindingRefusesMissingOrReplacedOriginalParticipants(t *testing.T) {
	for _, change := range []string{"missing-nfq", "missing-dns", "foreign-nfq-root", "foreign-dns-root", "existing-dns-provider", "existing-dns-check", "foreign-settings", "relative-settings", "unbounded", "cancelled", "foreign-provider"} {
		t.Run(change, func(t *testing.T) {
			m := New(filepath.Join(t.TempDir(), "dataplane"))
			nfq := NewNFQWS2Adapter()
			if err := m.Register(nfq); err != nil {
				t.Fatal(err)
			}
			dns := NewScopedDNSAdapter(context.Background(), nil, m.StateRoot)
			if err := m.Register(dns); err != nil {
				t.Fatal(err)
			}
			provider := netidentity.NewProcProvider()
			inventory := &BackendInventory{}
			inventory.reader.Provider = provider
			settings := filepath.Join(filepath.Dir(m.StateRoot), "dns", "state.json")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			switch change {
			case "missing-nfq":
				delete(m.Adapters, "nfqws2")
			case "missing-dns":
				delete(m.Adapters, scopedDNSAdapterID)
			case "foreign-nfq-root":
				nfq.StateRoot = filepath.Join(m.StateRoot, "foreign")
			case "foreign-dns-root":
				dns.StateRoot = filepath.Join(m.StateRoot, "foreign")
			case "existing-dns-provider":
				dns.InactivityIdentity = netidentity.NewProcProvider()
			case "existing-dns-check":
				dns.InactivityKernelCheck = func(context.Context, netidentity.Identity) error { return nil }
			case "foreign-settings":
				dns.InactivitySettingsPath = filepath.Join(filepath.Dir(settings), "other.json")
			case "relative-settings":
				settings = "dns/state.json"
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "foreign-provider":
				inventory.reader.Provider = netidentity.NewProcProvider()
			}
			oldProvider, oldSettings, hadKernel := dns.InactivityIdentity, dns.InactivitySettingsPath, dns.InactivityKernelCheck != nil
			if err := m.BindRuntimeInactivitySources(ctx, provider, inventory, settings); !errors.Is(err, ErrRuntimeInactivity) {
				t.Fatal("startup accepted missing/replaced owner", err)
			}
			if nfq.inactivity != nil || dns.InactivityIdentity != oldProvider || dns.InactivitySettingsPath != oldSettings || (dns.InactivityKernelCheck != nil) != hadKernel {
				t.Fatal("refused startup installed or replaced a source")
			}
		})
	}
}
