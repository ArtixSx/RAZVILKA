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
	for _, change := range []string{"missing-nfq", "missing-dns", "foreign-nfq-root", "foreign-dns-root", "existing-dns-provider", "existing-dns-check", "foreign-settings", "relative-settings", "root-settings", "unbounded", "cancelled", "deadline", "nil-context", "foreign-provider", "nil-provider", "nil-inventory", "nil-manager"} {
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
			case "root-settings":
				settings = filepath.VolumeName(settings) + string(filepath.Separator)
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "deadline":
				var end context.CancelFunc
				ctx, end = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer end()
			case "nil-context":
				ctx = nil
			case "foreign-provider":
				inventory.reader.Provider = netidentity.NewProcProvider()
			case "nil-provider":
				provider = nil
			case "nil-inventory":
				inventory = nil
			case "nil-manager":
				m = nil
			}
			oldProvider, oldSettings, hadKernel := dns.InactivityIdentity, dns.InactivitySettingsPath, dns.InactivityKernelCheck != nil
			err := m.BindRuntimeInactivitySources(ctx, provider, inventory, settings)
			if !errors.Is(err, ErrRuntimeInactivity) {
				t.Fatal("startup accepted missing/replaced owner", err)
			}
			wantStage := map[string]string{
				"missing-nfq": "binding-participants", "missing-dns": "binding-participants",
				"foreign-nfq-root": "binding-roots", "foreign-dns-root": "binding-roots",
				"existing-dns-provider": "binding-already-bound", "existing-dns-check": "binding-already-bound",
				"foreign-settings": "binding-dns-settings", "relative-settings": "binding-settings", "root-settings": "binding-settings",
				"unbounded": "binding-context", "cancelled": "binding-context", "deadline": "binding-context", "nil-context": "binding-context",
				"foreign-provider": "binding-inputs", "nil-provider": "binding-inputs", "nil-inventory": "binding-inputs", "nil-manager": "binding-inputs",
			}[change]
			if RuntimeInactivityBindingStage(err) != wantStage || errors.Is(err, context.Canceled) != (change == "cancelled") || errors.Is(err, context.DeadlineExceeded) != (change == "deadline") {
				t.Fatal("original startup branch/context cause was hidden or changed", RuntimeInactivityBindingStage(err))
			}
			if nfq.inactivity != nil || dns.InactivityIdentity != oldProvider || dns.InactivitySettingsPath != oldSettings || (dns.InactivityKernelCheck != nil) != hadKernel {
				t.Fatal("refused startup installed or replaced a source")
			}
		})
	}
}

type runtimeInactivityBindingOpaqueError struct{ cause error }

func (*runtimeInactivityBindingOpaqueError) Error() string {
	panic("private error text must not be read")
}
func (e *runtimeInactivityBindingOpaqueError) Unwrap() error { return e.cause }

func TestRuntimeInactivityStartupBindingDiagnosticIsClosedAndBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original := New(t.TempDir()).BindRuntimeInactivitySources(ctx, nil, nil, "")
	if RuntimeInactivityBindingStage(&runtimeInactivityBindingOpaqueError{cause: original}) != "binding-context" {
		t.Fatal("opaque joined cause hid the original typed coordinate")
	}
	if RuntimeInactivityBindingStage(errors.New("runtime inactivity binding refused at binding-context")) != "" ||
		RuntimeInactivityBindingStage(&runtimeInactivityBindingFailure{stage: "private-path", cause: ErrRuntimeInactivity}) != "" {
		t.Fatal("error text or an unknown coordinate supplied a closed stage")
	}
	cycle := &runtimeInactivityBindingOpaqueError{}
	cycle.cause = cycle
	if RuntimeInactivityBindingStage(cycle) != "" {
		t.Fatal("opaque cycle supplied a diagnostic stage")
	}
}
