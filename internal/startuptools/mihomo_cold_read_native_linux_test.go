//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Exercises the real retained startup source, not a replacement runner or a
// journal supplied tool descriptor. Missing history is intentional: reaching
// that read proves admission only, never successful retirement or a real reboot.
func TestStaticVersionFactNativeMihomoColdRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	original, first, ip6, err := l.MihomoColdReadTools()
	if err != nil || original != l || first.Provider != l.provider || first.Identity != l.identity || ip6 == "" {
		t.Fatal("original cold descriptor", nativeStages(err), err)
	}
	other, second, secondIP6, err := l.MihomoColdReadTools()
	if err != nil || other != l || second.Provider != first.Provider || second.Identity != first.Identity || second.ReviewSHA256 != first.ReviewSHA256 || second.IP != first.IP || second.IPTables != first.IPTables || secondIP6 != ip6 {
		t.Fatal("fresh comparison projection changed original source", err)
	}
	before, err := l.RunMihomoColdRead(ctx, first.IP, "-4", "-N", "rule", "show")
	if err != nil || len(before) == 0 {
		t.Fatal("actual bounded read", nativeStages(err), err)
	}
	if _, err := l.RunMihomoColdRead(ctx, first.IP, "-4", "rule", "add", "priority", "32123", "lookup", "123"); err == nil {
		t.Fatal("cold source accepted a mutation")
	}
	after, err := l.RunMihomoColdRead(ctx, first.IP, "-4", "-N", "rule", "show")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused command changed actual kernel rules", err)
	}
	tools, err := l.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := dataplane.NewBackendInventory(first.Provider, tools)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	m := dataplane.New(root)
	proxy, err := dataplane.NewProxyTunnelAdapter("sing-box", nil, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range []dataplane.Adapter{dataplane.NewNFQWS2Adapter(), dataplane.NewScopedDNSAdapter(ctx, nil, root), proxy} {
		if err := m.Register(adapter); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.BindRuntimeInactivitySources(ctx, first.Provider, inventory, filepath.Join(root, "dns.json")); err != nil {
		t.Fatal("actual original inactivity source", nativeStages(err), err)
	}
	id, digest := "dp-"+strings.Repeat("a", 32), strings.Repeat("b", 64)
	current := func(c context.Context) error { return l.Check(c, first.Identity) }
	_, err = m.RetireMihomoLiveAfterBoot(ctx, id, digest, current)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cold factory failed before intentionally absent history", nativeStages(err), err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := l.MihomoColdReadTools(); err == nil {
		t.Fatal("closed descriptor accepted")
	}
	if _, err := l.RunMihomoColdRead(ctx, first.IP, "-4", "-N", "rule", "show"); err == nil {
		t.Fatal("closed source ran command")
	}
	if _, err := m.RetireMihomoLiveAfterBoot(ctx, id, digest, current); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("revoked original source reached history", err)
	}
	t.Log("actual original source/read-only ABI/revocation passed; no retirement or reboot claim")
}
