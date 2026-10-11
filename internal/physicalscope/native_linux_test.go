//go:build linux

package physicalscope

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func nativeProvider(t *testing.T, ctx context.Context) (*netidentity.Provider, bool) {
	t.Helper()
	switch os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") {
	case "linux":
		return netidentity.NewProcProvider(), false
	case "stock-nc1812":
		p, err := netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p, true
	default:
		t.Skip("Root-only opt-in read-only physical observation")
		return nil, false
	}
}

// This exercises the actual socket ABI without pretending loopback is Home.
func TestPhysicalScopeNativeWireDependency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	provider, _ := nativeProvider(t, ctx)
	err := provider.WithCurrent(ctx, func(c context.Context, _ netidentity.Identity) error {
		f, err := openFence(c)
		if err != nil {
			return err
		}
		defer f.close()
		frames, err := dump(c, 18, 0)
		if err != nil {
			return at("native.links", err)
		}
		if len(frames) == 0 {
			return ErrUnknown
		}
		for _, m := range frames {
			if _, err := decodeLink(m); err != nil {
				return at("native.link-decode", err)
			}
		}
		for _, family := range []byte{2, 10} {
			for _, kind := range []uint16{22, 26, 30} {
				if _, err := dump(c, kind, family); err != nil {
					return at("native.dump", err)
				}
			}
		}
		return f.check(c, Snapshot{})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The selection must be explicitly supplied by Root. No WAN/default route or
// automatic bridge discovery can choose Home for this native acceptance test.
func TestPhysicalScopeNativeSelectedObservation(t *testing.T) {
	retained := nativeRetainedIncarnationOptIn(t)
	limit := 25 * time.Second
	if retained {
		limit = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	provider, stock := nativeProvider(t, ctx)
	home := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_HOME")
	if home == "" {
		t.Skip("requires explicit Root-selected Home native ID or Linux bridge name")
	}
	selection := Selection{HomeSegmentID: home, GuestSegmentIDs: []string{}}
	if guests := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_GUESTS"); guests != "" {
		selection.GuestSegmentIDs = strings.Split(guests, ",")
	}
	if stock {
		selection.SegmentIDs = append([]string{selection.HomeSegmentID}, selection.GuestSegmentIDs...)
		selection.HomeSegmentID = ""
		selection.GuestSegmentIDs = nil
	}
	selectionReads := 0
	read := func(c context.Context) (Selection, error) { selectionReads++; return selection, c.Err() }
	o := NewLinux(provider, read)
	if stock {
		o = NewReviewedStockNC1812(provider, read)
	}
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal("observe", err)
	}
	defer r.Close()
	if retained {
		nativeRetainedIncarnationSequence(t, ctx, provider, o, r, &selection, &selectionReads)
		return
	}
	if err := o.Verify(ctx, r); err != nil {
		t.Fatal("verify", err)
	}
	s := r.Snapshot()
	t.Logf("typed_scope=%s segments=%d devices=%d original_fence_open=true", s.Identity.Kind, len(s.Segments), len(s.Devices))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if o.Verify(ctx, r) == nil {
		t.Fatal("closed native fence admitted forward")
	}
}
