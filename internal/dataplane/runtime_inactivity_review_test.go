package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This is a private complete-source model: real binding/association and DNS
// dispatch run; only provider facts and protected tool currentness are modeled.
func runtimeSourceReviewFixture(t *testing.T) (*Manager, *RuntimeInactivitySourceReview, *bool) {
	t.Helper()
	f := newNFQWS2InactiveFixture(t)
	m := New(filepath.Dir(filepath.Dir(f.a.StateRoot)))
	m.Adapters["nfqws2"] = f.a
	dns := NewScopedDNSAdapter(context.Background(), nil, m.StateRoot)
	if err := m.Register(dns); err != nil {
		t.Fatal(err)
	}
	f.a.inactivity = nil
	f.source.bound = false
	closed := false
	f.source.inventory.reader.CheckTools = func(context.Context, backendInventoryScope) error {
		if closed {
			return errors.New("original tool owner closed")
		}
		return nil
	}
	f.source.frozen = *f.source.inventory
	ctx := nfqws2InactiveTestContext(t)
	settings := filepath.Join(filepath.Dir(m.StateRoot), "dns", "state.json")
	if _, err := m.ReviewRuntimeInactivitySources(ctx, settings); !errors.Is(err, ErrRuntimeInactivitySourcesMissing) {
		t.Fatal("pristine absence did not remain typed", err)
	}
	if err := m.bindRuntimeInactivitySources(ctx, f.source.provider, f.source.inventory, settings, func(context.Context, *NFQWS2Adapter, *BackendInventory) (*NFQWSRuntimeInactiveSource, error) {
		return f.source, nil
	}); err != nil {
		t.Fatal(err)
	}
	return m, m.runtimeSources, &closed
}

func sourceReviewModelCheck(ctx context.Context, r *RuntimeInactivitySourceReview) error {
	return r.checkCurrentWith(ctx, func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		return use(c, r.source.identity)
	})
}

func TestRuntimeInactivitySourceReviewRetainsSingleStartupOwner(t *testing.T) {
	m, r, closed := runtimeSourceReviewFixture(t)
	ctx := nfqws2InactiveTestContext(t)
	if err := sourceReviewModelCheck(ctx, r); err != nil {
		t.Fatal("original source unavailable", err)
	}
	before := r.source
	if err := m.BindRuntimeInactivitySources(ctx, r.source.provider, r.source.inventory, r.settings); RuntimeInactivityBindingStage(err) != "binding-already-bound" {
		t.Fatal("ordinary binding silently accepted second source", err)
	}
	if m.runtimeSources != r || r.nfq.inactivity != before {
		t.Fatal("second binding replaced original owner")
	}
	if r.dns.InactivityKernelCheck != nil || r.dns.runtimeInactivityKernel() == nil {
		t.Fatal("production DNS reader was not retained privately")
	}
	*closed = true
	if err := sourceReviewModelCheck(ctx, r); err == nil {
		t.Fatal("closed original owner could be reused")
	}
	if _, err := m.ReviewRuntimeInactivitySources(ctx, r.settings); errors.Is(err, ErrRuntimeInactivitySourcesMissing) {
		t.Fatal("closed source permitted replacement fallback")
	}
}

func TestRuntimeInactivitySourceReviewRejectsReplacedOrCopiedAssociations(t *testing.T) {
	for _, change := range []string{"copy", "manager", "registry", "source", "provider", "collector", "dns-provider", "dns-reader", "dns-settings", "dns-manager", "context"} {
		t.Run(change, func(t *testing.T) {
			m, r, _ := runtimeSourceReviewFixture(t)
			ctx := nfqws2InactiveTestContext(t)
			switch change {
			case "copy":
				copy := *r
				r = &copy
			case "manager":
				m.runtimeSources = nil
			case "registry":
				m.Adapters["nfqws2"] = NewNFQWS2Adapter()
			case "source":
				r.nfq.inactivity = nil
			case "provider":
				r.source.inventory.reader.Provider = netidentity.NewProcProvider()
			case "collector":
				r.source.inventory.review = "changed"
			case "dns-provider":
				r.dns.InactivityIdentity = netidentity.NewProcProvider()
			case "dns-reader":
				r.dns.InactivityKernelCheck = func(context.Context, netidentity.Identity) error { return nil }
			case "dns-settings":
				r.dns.InactivitySettingsPath += "changed"
			case "dns-manager":
				r.dns.inactivitySources = nil
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := sourceReviewModelCheck(ctx, r); err == nil {
				t.Fatal("changed source association accepted")
			}
			if _, err := m.ReviewRuntimeInactivitySources(ctx, r.settings); errors.Is(err, ErrRuntimeInactivitySourcesMissing) {
				t.Fatal("changed original owner became absent")
			}
		})
	}
}

func TestRuntimeInactivitySourceReviewChecksOriginalOwnerAtClosingBookend(t *testing.T) {
	m, r, _ := runtimeSourceReviewFixture(t)
	r.source.frozen.reader.CheckTools = func(context.Context, backendInventoryScope) error { m.runtimeSources = nil; return nil }
	if err := sourceReviewModelCheck(nfqws2InactiveTestContext(t), r); err == nil {
		t.Fatal("owner changed during protected tool check was accepted")
	}
	for _, calls := range []int{0, 2} {
		_, r, _ := runtimeSourceReviewFixture(t)
		err := r.checkCurrentWith(nfqws2InactiveTestContext(t), func(ctx context.Context, use func(context.Context, netidentity.Identity) error) error {
			for n := 0; n < calls; n++ {
				if err := use(ctx, r.source.identity); err != nil {
					return err
				}
			}
			return nil
		})
		if err == nil {
			t.Fatal("missing/repeated original observation callback accepted", calls)
		}
	}
}
