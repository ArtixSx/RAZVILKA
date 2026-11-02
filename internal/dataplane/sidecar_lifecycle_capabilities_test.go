package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/components"
	"path/filepath"
	"reflect"
	"testing"
)

func TestManagedSidecarRegistrationRequiresOriginalBoundParent(t *testing.T) {
	m := New(t.TempDir())
	lab, err := NewProxyTunnelAdapterWithHev("xray", nil, m.StateRoot, filepath.Join(t.TempDir(), "hev-socks5-tunnel"))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Register(lab); err != nil {
		t.Fatal(err)
	}
	if got := m.ManagedSidecarLifecycleRegistration("hev"); len(got.Parents) != 0 || got.RuntimePreflight || got.Recovery {
		t.Fatal("lab constructor invented managed owner", got)
	}
	m = New(t.TempDir())
	owner := components.New()
	owner.BinDir = t.TempDir()
	for _, id := range []string{"xray", "usque"} {
		adapter, err := NewProxyTunnelAdapter(id, nil, m.StateRoot)
		if err != nil {
			t.Fatal(err)
		}
		// Actual recovery constructor binds the original future asset checker;
		// deliberately absent assets must not be observed by this projection.
		if err = BindHEVSidecarForRecovery(context.Background(), adapter, owner); err != nil {
			t.Fatal(err)
		}
		adapter.Runner = handshakeBudgetRunner(func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("registration executed native preflight")
			return nil, nil
		})
		if err = m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	got := m.ManagedSidecarLifecycleRegistration("hev")
	if !reflect.DeepEqual(got.Parents, []string{"usque", "xray"}) || !got.RuntimePreflight || !got.Recovery {
		t.Fatal("actual bound dependency lost", got)
	}
	got.Parents[0] = "edited"
	if m.ManagedSidecarLifecycleRegistration("hev").Parents[0] != "usque" {
		t.Fatal("caller changed registration")
	}
	if len(m.ManagedSidecarLifecycleRegistration("mihomo").Parents) != 0 {
		t.Fatal("invented unsupported sidecar")
	}
}
