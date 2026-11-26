//go:build linux

package physicalscope

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Opt-in coordinator-owned diagnostics only. The original Provider brackets
// existing complete RTM_GETROUTE dumps on one OS thread. No interface/route,
// source lease, ownership, service proof, receipt or runtime grant is created.
// Output contains only numeric header/attribute shapes, never address bytes,
// names, keys, argv, proc contents or the actual namespace identity.
func TestNativeWGKernelRouteShapes(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_KERNEL_ROUTE_SHAPES") != "1" {
		t.Skip("coordinator-owned read-only route shape observation")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	provider := netidentity.NewProcProvider()
	if os.Getenv("RAZVILKA_WG_KERNEL_ROUTE_STOCK") == "1" {
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		if err != nil {
			t.Fatal("actual reviewed stock namespace unavailable")
		}
	}
	id, err := provider.Observe(ctx)
	if err != nil {
		t.Fatal("actual original namespace unavailable")
	}
	counts := map[string]int{}
	rows, shapeBytes, uses := 0, 0, 0
	err = provider.WithCurrent(ctx, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != id {
			return ErrUnknown
		}
		for _, family := range []byte{2, 10} {
			leaf, stop := context.WithTimeout(held, 2*time.Second)
			frames, err := dump(leaf, 26, family)
			leafErr := leaf.Err()
			stop()
			if err != nil || leafErr != nil {
				return ErrUnknown
			}
			for _, m := range frames {
				if held.Err() != nil || rows >= 8192 {
					return ErrUnknown
				}
				shape, ok := wgNativeRouteShape(m, family)
				if !ok {
					return ErrUnknown
				}
				if _, known := counts[shape]; !known {
					if len(counts) >= 128 || shapeBytes+len(shape) > 24<<10 {
						return ErrUnknown
					}
					shapeBytes += len(shape)
				}
				counts[shape]++
				rows++
			}
		}
		return held.Err()
	})
	if err != nil || uses != 1 || ctx.Err() != nil {
		t.Fatal("bounded complete namespace-bound route shapes unavailable; no proof issued")
	}
	shapes := make([]string, 0, len(counts))
	for shape := range counts {
		shapes = append(shapes, shape)
	}
	slices.Sort(shapes)
	for _, shape := range shapes {
		t.Logf("count=%d %s", counts[shape], shape)
	}
	t.Logf("read-only RTM route shapes: rows=%d shapes=%d; WG service/peer/ownership/mutation proof=false", rows, len(shapes))
}

// This diagnostic envelope intentionally records UNKNOWN raw attribute kind
// bits/widths instead of interpreting their payload. It is not a route parser
// for presence or deletion. Even RTA_TABLE is printed only as numeric data.
func wgNativeRouteShape(m message, family byte) (string, bool) {
	if (family != 2 && family != 10) || m.kind != 24 || m.flags != 2 || len(m.data) < 12 || len(m.data) > 64<<10 || m.data[0] != family {
		return "", false
	}
	attributes := []string{}
	tableWidth, tableValue, tableCount := -1, uint32(0), 0
	for raw := m.data[12:]; len(raw) > 0; {
		if len(raw) < 4 || len(attributes) >= 256 {
			return "", false
		}
		n := int(binary.NativeEndian.Uint16(raw[:2]))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw) {
			return "", false
		}
		kind := binary.NativeEndian.Uint16(raw[2:4])
		attributes = append(attributes, fmt.Sprintf("%d:%d", kind, n-4))
		if kind == 15 {
			tableCount++
			tableWidth = n - 4
			if tableWidth == 4 {
				tableValue = binary.NativeEndian.Uint32(raw[4:n])
			}
		}
		raw = raw[aligned:]
	}
	slices.Sort(attributes)
	shape := fmt.Sprintf("kind=%d flags=%d family=%d dst_len=%d src_len=%d tos=%d table_header=%d table_attr_count=%d table_attr_width=%d table_attr=%d protocol=%d scope=%d type=%d route_flags=%d attrs=%s", m.kind, m.flags, m.data[0], m.data[1], m.data[2], m.data[3], m.data[4], tableCount, tableWidth, tableValue, m.data[5], m.data[6], m.data[7], binary.NativeEndian.Uint32(m.data[8:12]), strings.Join(attributes, ","))
	return shape, len(shape) <= 2048
}

func TestWGKernelRouteShapeDiagnosticNeverPrintsPayload(t *testing.T) {
	m := message{kind: 24, flags: 2, data: make([]byte, 12)}
	m.data[0], m.data[4], m.data[5], m.data[6], m.data[7] = 2, 206, 3, 253, 1
	m.data = append(m.data, attr(15, integer(206))...)
	m.data = append(m.data, attr(1, []byte("PRIVATE_PAYLOAD"))...)
	shape, ok := wgNativeRouteShape(m, 2)
	if !ok || strings.Contains(shape, "PRIVATE") || !strings.Contains(shape, "attrs=15:4,1:15") || !strings.Contains(shape, "table_attr=206") {
		t.Fatal("diagnostic leaked payload or lost numeric shape")
	}
	for _, bad := range []message{{kind: 24, flags: 2, data: []byte{2}}, {kind: 24, flags: 2, data: append(slices.Clone(m.data), 1)}, {kind: 24, flags: 0, data: m.data}} {
		if _, ok := wgNativeRouteShape(bad, 2); ok {
			t.Fatal("invalid diagnostic envelope accepted")
		}
	}
}
