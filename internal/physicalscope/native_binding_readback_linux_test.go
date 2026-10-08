//go:build linux

package physicalscope

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Root-only bounded GET observation. A successful diagnostic test says only
// that the readback closed; rejected rows remain rejected by the real decoder.
// It never calls Observe, creates a physical Review or authorizes any effect.
func TestPhysicalScopeNativeNeighborClassReadback(t *testing.T) {
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
		selection.HomeSegmentID = ""
		selection.GuestSegmentIDs = nil
	}
	counts := map[neighborReadbackClass]int{}
	selectedFrames, totalFrames, selectedSegments := 0, 0, 0
	err := provider.WithCurrent(ctx, func(c context.Context, _ netidentity.Identity) error {
		var native []nativeSegment
		if stock {
			raw, err := provider.ReadReviewedStockInterfaces(c)
			if err != nil {
				return at("native.readback.ndm", err)
			}
			native, err = parseNDM(raw)
			if err != nil {
				return err
			}
		}
		links, err := dump(c, 18, 0)
		if err != nil {
			return at("native.readback.links", err)
		}
		addresses, err := dump(c, 22, 0)
		if err != nil {
			return at("native.readback.addresses", err)
		}
		var routes []message
		for _, family := range []byte{2, 10} {
			frames, err := dump(c, 26, family)
			if err != nil {
				return at("native.readback.routes", err)
			}
			routes = append(routes, frames...)
		}
		segments, err := assembleSegments(selection, native, stock, links, addresses, routes)
		if err != nil {
			return err
		}
		selectedSegments = len(segments)
		indices := map[int]bool{}
		for _, segment := range segments {
			indices[segment.IfIndex] = true
		}
		for _, family := range []byte{2, 10} {
			frames, err := dump(c, 30, family)
			if err != nil {
				return at("native.readback.neighbors", err)
			}
			totalFrames += len(frames)
			if totalFrames > 8192 {
				return at("native.readback.row-limit", nil)
			}
			for _, m := range frames {
				if err := c.Err(); err != nil {
					return err
				}
				if len(m.data) < 12 {
					return at("native.readback.neighbor-header", nil)
				}
				if !indices[int(binary.NativeEndian.Uint32(m.data[4:8]))] {
					continue
				}
				selectedFrames++
				class := classifyNeighborReadback(family, m)
				if _, exists := counts[class]; !exists && len(counts) >= 128 {
					return at("native.readback.class-limit", nil)
				}
				counts[class]++
			}
		}
		return c.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		ObservationOnly        bool                    `json:"observation_only"`
		Capability             string                  `json:"capability"`
		OriginalPhysicalReview bool                    `json:"original_physical_review"`
		SelectedSegments       int                     `json:"selected_segments"`
		TotalFrames            int                     `json:"total_frames"`
		SelectedFrames         int                     `json:"selected_frames"`
		Classes                []neighborReadbackCount `json:"classes"`
	}{true, "ungranted", false, selectedSegments, totalFrames, selectedFrames, summarizeNeighborReadback(counts)})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 64<<10 {
		t.Fatal(at("native.readback.output-limit", nil))
	}
	t.Log(string(raw))
}
