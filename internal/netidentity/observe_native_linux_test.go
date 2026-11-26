//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// Execution belongs to Root's native window. Portable model tests never read
// a production router or run NDMC; no namespace/kernel mutation is performed.
func TestNativeNetworkIdentityProcThreadAndClosing(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_NATIVE") != "1" {
		t.Skip("Root native opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p := NewProcProvider()
	if err := p.WithCurrent(ctx, func(c context.Context, original Identity) error {
		tid := syscall.Gettid()
		fresh, err := p.Observe(c)
		if err != nil || fresh != original || fresh.Kind != ProcNetInode || syscall.Gettid() != tid {
			t.Fatal(fresh, original, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeReviewedStockNC1812FactoryAndScope(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_STOCK_NATIVE") != "1" {
		t.Skip("Root exact stock router opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	p, err := NewReviewedStockNC1812Provider(ctx)
	cancel()
	if err != nil {
		t.Fatal("fresh stock factory", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.WithCurrent(ctx, func(_ context.Context, v Identity) error {
		if v.Kind != ReviewedSingleInitNet || v.Inode != 0 || v.PlatformReviewSHA256 != nc1812Profile().hash() {
			t.Fatal("exact stock singleton", v)
		}
		raw, err := Encode(v)
		if err != nil {
			return err
		}
		decoded, err := Decode(raw)
		if err != nil || decoded != v {
			t.Fatal("native canonical wire", err)
		}
		return nil
	}); err != nil {
		t.Fatal("fresh locked scope and closing verification", err)
	}
}
