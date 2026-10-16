package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func wgServiceRouteFixture(family int, table uint32) message {
	m := message{kind: 24, flags: 2, data: make([]byte, 12)}
	m.data[0], m.data[4], m.data[5], m.data[6], m.data[7] = 2, byte(table), 3, 253, 1
	if table > 255 {
		m.data[4] = 252
	}
	if family == 6 {
		m.data[0], m.data[6] = 10, 0
	}
	m.data = append(m.data, attr(15, integer(table))...)
	m.data = append(m.data, attr(4, integer(9))...)
	if family == 6 {
		m.data = append(m.data, attr(6, integer(1024))...)
		cache := make([]byte, 32)
		binary.NativeEndian.PutUint32(cache[4:8], 12345)
		m.data = append(m.data, attr(12, cache)...)
		m.data = append(m.data, attr(20, []byte{0})...)
	}
	return m
}

func TestWGKernelServiceTableNumericCompilerDefaultsAndOpaqueForeignRows(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, table := range []uint32{206, 43123} {
			t.Run(fmt.Sprintf("%d/%d", family, table), func(t *testing.T) {
				owned := wgServiceRouteFixture(family, table)
				foreign := wgServiceRouteFixture(family, 254)
				foreign.data[1], foreign.data[2], foreign.data[5], foreign.data[7] = 128, 99, 255, 7
				// Valid framing/table identity, deliberately uninterpretable foreign
				// payload/unknown attributes. Never decode it as a WG route tuple.
				foreign.data = append(foreign.data, attr(1, []byte("PRIVATE_NOT_A_ROUTE_ADDRESS"))...)
				foreign.data = append(foreign.data, attr(0x8000|91, []byte{255, 1})...)
				for _, frames := range [][]message{nil, {foreign}, {owned, foreign}} {
					route, err := wgKernelServiceTable(frames, table, family)
					want := len(frames) == 2
					if err != nil || route.present != want || want && route.oif != 9 {
						t.Fatal("complete numeric table/foreign envelope refused", err)
					}
				}
			})
		}
	}
}

func TestWGKernelServiceTableRouter554ForeignShapesNeverBecomeOwnedPresence(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			foreign := wgServiceRouteFixture(family, 16395)
			if family == 4 {
				foreign.data = append(foreign.data, attr(6, integer(1000))...)
				foreign.data = append(foreign.data, attr(7, []byte{192, 0, 2, 10})...)
			} else {
				// Firmware554 has family10/type7/protocol2/default/table0 plus
				// cache32, pref1, OIF4, metric4. This is not our unicast default.
				foreign = wgServiceRouteFixture(6, 0)
				foreign.data[5], foreign.data[7] = 2, 7
			}
			for _, frames := range [][]message{{foreign}, {foreign, wgServiceRouteFixture(family, 206)}} {
				route, err := wgKernelServiceTable(frames, 206, family)
				if err != nil || route.present != (len(frames) == 2) {
					t.Fatal("firmware foreign shape polluted owned table", err)
				}
			}
		})
	}
}

func TestWGKernelServiceTableInvalidQueriesPerformNoObservation(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 7}
	for _, cut := range []string{"table", "family", "iface", "identity", "cancel"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			table, family, iface, expected := 206, 4, "rz-wg", id
			switch cut {
			case "table":
				table = 0
			case "family":
				family = 5
			case "iface":
				iface = "bad/name"
			case "identity":
				expected = netidentity.Identity{}
			case "cancel":
				cancel()
			}
			current := func(context.Context, func(context.Context, netidentity.Identity) error) error {
				t.Fatal("invalid query observed namespace")
				return nil
			}
			capture := func(context.Context, byte) ([]message, error) { t.Fatal("invalid query read routes"); return nil, nil }
			links := func(context.Context) ([]message, error) { t.Fatal("invalid query read links"); return nil, nil }
			if n, err := readWGKernelServiceTable(ctx, expected, table, family, iface, current, capture, links); err == nil || n != 0 {
				t.Fatal("invalid query produced a fact")
			}
		})
	}
}

func TestWGKernelServiceTableRejectsEveryUnexpectedOwnedRoute(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, cut := range []string{"duplicate-default", "specific-before", "specific-after", "source-length", "tos", "protocol", "scope", "type", "route-flags", "gateway", "prefsrc", "source", "multipath", "unknown", "duplicate-oif", "duplicate-table", "table-conflict", "table-width", "table-nested", "oif-zero", "oif-negative", "oif-width", "metric", "metric-duplicate", "nested", "padding", "wrong-message", "wrong-flags", "wrong-family", "truncated", "no-oif", "v6-missing-metric", "v6-preference", "v6-cache-width"} {
			t.Run(fmt.Sprintf("%d/%s", family, cut), func(t *testing.T) {
				m := wgServiceRouteFixture(family, 206)
				frames := []message{m}
				specific := wgServiceRouteFixture(family, 206)
				specific.data[1] = 1
				switch cut {
				case "duplicate-default":
					frames = append(frames, m)
				case "specific-before":
					frames = append([]message{specific}, frames...)
				case "specific-after":
					frames = append(frames, specific)
				case "source-length":
					m.data[2] = 1
				case "tos":
					m.data[3] = 1
				case "protocol":
					m.data[5] = 4
				case "scope":
					m.data[6] ^= 253
				case "type":
					m.data[7] = 7
				case "route-flags":
					binary.NativeEndian.PutUint32(m.data[8:12], 16)
				case "gateway":
					m.data = append(m.data, attr(5, []byte{1, 2, 3, 4})...)
				case "prefsrc":
					m.data = append(m.data, attr(7, []byte{1, 2, 3, 4})...)
				case "source":
					m.data = append(m.data, attr(2, []byte{1, 2, 3, 4})...)
				case "multipath":
					m.data = append(m.data, attr(9, []byte{0})...)
				case "unknown":
					m.data = append(m.data, attr(99, nil)...)
				case "duplicate-oif":
					m.data = append(m.data, attr(4, integer(9))...)
				case "duplicate-table":
					m.data = append(m.data, attr(15, integer(206))...)
				case "table-conflict":
					m.data[4] = 205
				case "table-width":
					m.data = append(slices.Clone(m.data[:12]), attr(15, []byte{206})...)
				case "table-nested":
					binary.NativeEndian.PutUint16(m.data[14:16], 0x8000|15)
				case "oif-zero":
					binary.NativeEndian.PutUint32(m.data[24:28], 0)
				case "oif-negative":
					binary.NativeEndian.PutUint32(m.data[24:28], 0xffffffff)
				case "oif-width":
					m.data = append(slices.Clone(m.data[:20]), attr(4, []byte{9})...)
				case "metric":
					if family == 4 {
						m.data = append(m.data, attr(6, integer(1))...)
					} else {
						binary.NativeEndian.PutUint32(m.data[32:36], 1)
					}
				case "metric-duplicate":
					m.data = append(m.data, attr(6, integer(0))...)
					m.data = append(m.data, attr(6, integer(0))...)
				case "nested":
					m.data = append(m.data, attr(0x8000|4, integer(9))...)
				case "padding":
					m.data = append(m.data, attr(20, []byte{0})...)
					m.data[len(m.data)-1] = 1
				case "wrong-message":
					m.kind = 25
				case "wrong-flags":
					m.flags = 0x12
				case "wrong-family":
					m.data[0] = 0
				case "truncated":
					m.data = append(m.data, 1)
				case "no-oif":
					m.data = append(slices.Clone(m.data[:20]), m.data[28:]...)
				case "v6-missing-metric":
					if family == 4 {
						t.Skip("IPv6-specific")
					}
					m.data = append(slices.Clone(m.data[:28]), m.data[36:]...)
				case "v6-preference":
					if family == 4 {
						t.Skip("IPv6-specific")
					}
					m.data[len(m.data)-4] = 1
				case "v6-cache-width":
					if family == 4 {
						t.Skip("IPv6-specific")
					}
					m.data = append(slices.Clone(m.data[:36]), attr(12, []byte{0})...)
				}
				if len(frames) == 1 {
					frames[0] = m
				}
				if route, err := wgKernelServiceTable(frames, 206, family); err == nil || route.present {
					t.Fatal("unexpected owned route became exact default", cut)
				}
			})
		}
	}
}

func TestWGKernelServiceTableForeignTableAmbiguityAndBoundsRefuse(t *testing.T) {
	for _, cut := range []string{"duplicate-table", "table-width", "header-conflict", "compat-without-table", "oversized", "short", "frames-bound"} {
		t.Run(cut, func(t *testing.T) {
			m := wgServiceRouteFixture(4, 254)
			switch cut {
			case "duplicate-table":
				m.data = append(m.data, attr(15, integer(254))...)
			case "table-width":
				m.data = append(slices.Clone(m.data[:12]), attr(15, []byte{254})...)
			case "header-conflict":
				m.data[4] = 200
			case "compat-without-table":
				m.data = make([]byte, 12)
				m.data[0], m.data[4] = 2, 252
			case "oversized":
				m.data = append(m.data, make([]byte, 64<<10)...)
			case "short":
				m.data = m.data[:11]
			}
			frames := []message{m}
			if cut == "frames-bound" {
				frames = make([]message, 8193)
			}
			if route, err := wgKernelServiceTable(frames, 206, 4); err == nil || route.present {
				t.Fatal("ambiguous/incomplete foreign table filtered out")
			}
		})
	}
}

func TestWGKernelServiceTableWholeDumpByteAndAttributeBounds(t *testing.T) {
	large := message{kind: 24, flags: 2, data: make([]byte, 12)}
	large.data[0], large.data[4] = 2, 254
	large.data = append(large.data, attr(91, make([]byte, (64<<10)-16))...)
	frames := make([]message, 65)
	for i := range frames {
		frames[i] = large
	}
	if _, err := wgKernelServiceTable(frames, 206, 4); err == nil {
		t.Fatal("whole dump byte bound lost")
	}
	foreign := wgServiceRouteFixture(4, 254)
	for range 257 {
		foreign.data = append(foreign.data, attr(91, nil)...)
	}
	if _, err := wgKernelServiceTable([]message{foreign}, 206, 4); err == nil {
		t.Fatal("attribute scan was unbounded")
	}
}

func TestWGKernelServiceTableOriginalNamespaceMappingAndClosing(t *testing.T) {
	id := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 7}
	for _, cut := range []string{"none", "empty", "foreign-id", "missing-callback", "twice", "closing", "route-error", "link-error", "missing-link", "wrong-oif", "duplicate-link", "closing-route", "cancel", "unbounded", "volatile-cache"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if cut == "unbounded" {
				ctx = context.Background()
			}
			captures, linkReads := 0, 0
			current := func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
				if cut == "missing-callback" {
					return nil
				}
				actual := id
				if cut == "foreign-id" {
					actual.Inode++
				}
				if err := use(c, actual); err != nil {
					return err
				}
				if cut == "twice" {
					return use(c, actual)
				}
				if cut == "closing" {
					return errors.New("namespace closing changed")
				}
				return nil
			}
			capture := func(c context.Context, family byte) ([]message, error) {
				captures++
				if end, ok := c.Deadline(); !ok || time.Until(end) > 2*time.Second || family != 10 {
					t.Fatal("unbounded/wrong-family leaf")
				}
				m := wgServiceRouteFixture(6, 43123)
				if cut == "route-error" {
					return []message{m}, errors.New("partial dump")
				}
				if cut == "empty" {
					return nil, nil
				}
				if cut == "closing-route" && captures > 1 {
					return nil, nil
				}
				if cut == "volatile-cache" && captures > 1 {
					m.data[44]++
				}
				return []message{m}, nil
			}
			links := func(context.Context) ([]message, error) {
				linkReads++
				m := linkFrame(9, "rz-wg", "wireguard", "", 0)
				m.flags = 2
				if cut == "cancel" {
					cancel()
				}
				if cut == "link-error" {
					return []message{m}, errors.New("partial links")
				}
				if cut == "missing-link" {
					return wgLinkDumpFixture()[:1], nil
				}
				if cut == "wrong-oif" {
					m = linkFrame(8, "rz-wg", "wireguard", "", 0)
					m.flags = 2
				}
				if cut == "duplicate-link" {
					return []message{m, m}, nil
				}
				return []message{m}, nil
			}
			count, err := readWGKernelServiceTable(ctx, id, 43123, 6, "rz-wg", current, capture, links)
			if cut == "none" || cut == "volatile-cache" {
				if err != nil || count != 1 || captures != 2 || linkReads != 1 {
					t.Fatal("exact native557 tuple refused", err)
				}
			} else if cut == "empty" {
				if err != nil || count != 0 || captures != 2 || linkReads != 0 {
					t.Fatal("empty table invented link dependency", err)
				}
			} else if err == nil || count != 0 {
				t.Fatal("unknown mapping/namespace/capture returned a fact", cut, count, err)
			}
		})
	}
	if n, err := ReadWGKernelServiceTable(context.Background(), nil, id, 206, 4, "rz-wg"); n != 0 || err == nil {
		t.Fatal("unissued provider returned a fact")
	}
}
