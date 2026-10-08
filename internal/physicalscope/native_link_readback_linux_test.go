//go:build linux

package physicalscope

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"golang.org/x/sys/unix"
)

// Root-only forensics for a tracked LINK refusal. The one socket opens before
// the first facts, and every notification is compared with that first dump.
// A PASS closes the diagnostic only: no Observe, physical Review or effect.
func TestPhysicalScopeNativeLinkRefreshReadback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	provider, stock := nativeProvider(t, ctx)
	home := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_HOME")
	if home == "" {
		t.Skip("requires explicit Root-selected Home")
	}
	selection := Selection{HomeSegmentID: home}
	if guests := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_GUESTS"); guests != "" {
		selection.GuestSegmentIDs = strings.Split(guests, ",")
	}
	if stock {
		selection.SegmentIDs = append([]string{home}, selection.GuestSegmentIDs...)
		selection.HomeSegmentID, selection.GuestSegmentIDs = "", nil
	}
	selection, err := canonicalSelection(selection)
	if err != nil {
		t.Fatal(err)
	}
	source := platformSource(provider, stock)
	var fence *kernelFence
	var identity netidentity.Identity
	err = source.current(ctx, func(c context.Context, id netidentity.Identity) error {
		identity = id
		opened, err := openFence(c)
		if err == nil {
			fence = opened.(*kernelFence)
		}
		return err
	})
	if fence != nil {
		defer fence.close()
	}
	if err != nil || fence == nil {
		t.Fatal(boundary("native.link-readback.open", err))
	}
	counts := map[linkReadbackClass]int{}
	kindCounts := map[string]int{}
	totalBytes, totalFrames := 0, 0
	var original Snapshot
	var baseline map[int]message
	comparison := "unavailable"
	drain := func(c context.Context, phase string) error {
		if err := fence.currentError(); err != nil {
			return boundary("native.link-readback.descriptor", err)
		}
		buf := make([]byte, 1<<20)
		for {
			if err := c.Err(); err != nil {
				return err
			}
			n, err := receive(fence.fd, buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return fence.currentError()
			}
			if err != nil {
				return boundary("native.link-readback.receive", err)
			}
			totalBytes += n
			if totalBytes > maxNetBytes {
				return at("native.link-readback.byte-limit", nil)
			}
			frames, err := messages(buf[:n])
			if err != nil {
				return boundary("native.link-readback.datagram", err)
			}
			for _, m := range frames {
				totalFrames++
				if totalFrames > 8192 {
					return at("native.link-readback.frame-limit", nil)
				}
				if m.kind == 4 {
					return at("native.link-readback.overrun", nil)
				}
				kindCounts[phase+":"+strconv.Itoa(int(m.kind))]++
				if len(kindCounts) > 128 {
					return at("native.link-readback.kind-limit", nil)
				}
				if m.kind != 16 && m.kind != 17 {
					continue
				}
				class := classifyLinkReadback(phase, m, baseline, original.Segments)
				if class.Role == "unrelated" && class.RuntimeDecision == "accepted" {
					continue // Count unrelated traffic above; retain owned/refused LINK classes.
				}
				if _, exists := counts[class]; !exists && len(counts) >= 64 {
					return at("native.link-readback.class-limit", nil)
				}
				counts[class]++
			}
		}
	}
	for pass := 0; pass < 2; pass++ {
		phase := [2]string{"initial", "pass"}[pass]
		err := source.current(ctx, func(c context.Context, id netidentity.Identity) error {
			if id != identity || id.Validate() != nil {
				return at("native.link-readback.identity", nil)
			}
			if pass > 0 {
				if err := drain(c, phase+".before"); err != nil {
					return err
				}
			}
			facts, links, err := captureNativeLinkReadback(c, selection, provider, stock)
			if err != nil {
				return boundary("native.link-readback.facts", err)
			}
			facts.Identity = id
			if pass == 0 {
				original, baseline = facts, links
			} else if reflect.DeepEqual(original, facts) {
				comparison = "same"
			} else {
				comparison = snapshotDifference(original, facts)
			}
			return drain(c, phase+".after")
		})
		if err != nil {
			t.Fatal(boundary("native.link-readback."+phase, err))
		}
	}
	err = source.current(ctx, func(c context.Context, id netidentity.Identity) error {
		if id != identity {
			return at("native.link-readback.closing.identity", nil)
		}
		return drain(c, "closing")
	})
	if err != nil {
		t.Fatal(boundary("native.link-readback.closing", err))
	}
	if err := fence.close(); err != nil {
		t.Fatal(boundary("native.link-readback.close", err))
	}
	raw, err := json.Marshal(struct {
		ObservationOnly        bool                `json:"observation_only"`
		Capability             string              `json:"capability"`
		OriginalPhysicalReview bool                `json:"original_physical_review"`
		SelectedSegments       int                 `json:"selected_segments"`
		SnapshotComparison     string              `json:"snapshot_comparison"`
		TotalFrames            int                 `json:"total_frames"`
		KindCounts             map[string]int      `json:"kind_counts"`
		Classes                []linkReadbackCount `json:"classes"`
	}{true, "ungranted", false, len(original.Segments), comparison, totalFrames, kindCounts, summarizeLinkReadback(counts)})
	if err != nil || len(raw) > 64<<10 {
		t.Fatal(at("native.link-readback.output", err))
	}
	t.Log(string(raw))
}

// The same actual NDM/link/address/route/neighbor assembly as captureKernel,
// with the first GETLINK frames retained privately for diagnostic comparison.
func captureNativeLinkReadback(ctx context.Context, selection Selection, provider *netidentity.Provider, stock bool) (Snapshot, map[int]message, error) {
	var native []nativeSegment
	if stock {
		raw, err := provider.ReadReviewedStockInterfaces(ctx)
		if err != nil {
			return Snapshot{}, nil, boundary("native.link-readback.ndm", err)
		}
		native, err = parseNDM(raw)
		if err != nil {
			return Snapshot{}, nil, err
		}
	}
	links, err := dump(ctx, 18, 0)
	if err != nil {
		return Snapshot{}, nil, boundary("native.link-readback.links", err)
	}
	addresses, err := dump(ctx, 22, 0)
	if err != nil {
		return Snapshot{}, nil, boundary("native.link-readback.addresses", err)
	}
	var routes []message
	for _, family := range []byte{2, 10} {
		frames, err := dump(ctx, 26, family)
		if err != nil {
			return Snapshot{}, nil, boundary("native.link-readback.routes", err)
		}
		routes = append(routes, frames...)
	}
	segments, err := assembleSegments(selection, native, stock, links, addresses, routes)
	if err != nil {
		return Snapshot{}, nil, err
	}
	devices, err := observeKernelBindings(ctx, segments)
	if err != nil {
		return Snapshot{}, nil, err
	}
	baseline := map[int]message{}
	for _, m := range links {
		link, err := decodeLink(m)
		if err != nil {
			return Snapshot{}, nil, err
		}
		baseline[link.IfIndex] = m
	}
	return Snapshot{Selection: selection, Segments: segments, Devices: devices}, baseline, nil
}
