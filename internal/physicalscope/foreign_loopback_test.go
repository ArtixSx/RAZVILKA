package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

func foreignBridgeLoopbackFrame() message {
	m := neighborFrame(1, "2001:db8::1", "00:00:00:00:00:00", 64)
	m.data[11] = 2
	m.data = append(m.data, attr(3, make([]byte, 16))...)
	m.data = append(m.data, attr(4, make([]byte, 4))...)
	return m
}

func TestSelectedProjectionForeignBridgeLoopbackPreservesOriginalBothPaths(t *testing.T) {
	selection := selectedTestSelection()
	original, err := captureSelectedTest(context.Background(), selection, selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	row := foreignBridgeLoopbackFrame()
	if len(row.data) != 72 {
		t.Fatal("fixture no longer reproduces the actual 72-byte kernel tuple")
	}
	frames := selectedTestNeighbors()
	frames[10] = append(frames[10], row)
	current, err := captureSelectedTest(context.Background(), selection, frames)
	if err != nil || !reflect.DeepEqual(original, current) {
		t.Fatal("bridge-local loopback alias changed the original cohort", err)
	}
	strict := selection
	strict.SelectedDevices = nil
	before, err := captureSelectedTest(context.Background(), strict, selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	after, err := captureSelectedTest(context.Background(), strict, frames)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("nil projection's original foreign bypass changed", err)
	}
	o, _, observed, transport, review, ctx := selectedTestReview(t)
	frozen := review.Snapshot()
	*observed = frames
	for _, kind := range []uint16{28, 29} {
		row.kind = kind
		transport.push(fenceTestDatagram{raw: frame(row)})
		if err := o.Verify(ctx, review); err != nil {
			t.Fatal("bridge-local alias revoked original forward", err)
		}
		if err := o.VerifyRetainedIncarnation(ctx, review); err != nil {
			t.Fatal("bridge-local alias revoked original retained path", err)
		}
		if !reflect.DeepEqual(frozen, review.Snapshot()) {
			t.Fatal("bridge-local alias adopted new original facts")
		}
	}
}

func loopbackRefusalCases() map[string]func(*message) {
	address := func(raw string) func(*message) {
		return func(m *message) { replaceForeignAttribute(m, 1, netip.MustParseAddr(raw).AsSlice(), false) }
	}
	return map[string]func(*message){
		"wrong-index":      func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], 30) },
		"selected-ingress": func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], 9) },
		"negative-index":   func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], ^uint32(0)) },
		"selected-IP":      address("2001:db8::20"),
		"excluded-IP":      address("2001:db8::30"),
		"router-IP":        address("2001:db8::5"),
		"same-subnet":      address("2001:db8::70"),
		"linklocal":        address("fe80::1"),
		"v4-mapped":        address("::ffff:192.0.2.1"),
		"multicast":        address("ff02::1"),
		"unspecified":      address("::"),
		"loopback-address": address("::1"),
		"selected-MAC":     func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 3}, false) },
		"excluded-MAC":     func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 6}, false) },
		"router-MAC":       func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 5}, false) },
		"ordinary-MAC":     func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 7}, false) },
		"broadcast-MAC":    func(m *message) { replaceForeignAttribute(m, 2, []byte{255, 255, 255, 255, 255, 255}, false) },
		"multicast-MAC":    func(m *message) { replaceForeignAttribute(m, 2, []byte{51, 51, 0, 0, 0, 1}, false) },
		"empty-MAC":        func(m *message) { replaceForeignAttribute(m, 2, nil, false) },
		"absent-MAC":       func(m *message) { replaceForeignAttribute(m, 2, nil, true) },
		"reachable":        func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 2) },
		"incomplete":       func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 1) },
		"failed":           func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 32) },
		"router-flag":      func(m *message) { m.data[10] = 128 },
		"proxy-flag":       func(m *message) { m.data[10] = 2 },
		"external-flag":    func(m *message) { m.data[10] = 16 },
		"unicast-type":     func(m *message) { m.data[11] = 1 },
		"broadcast-type":   func(m *message) { m.data[11] = 3 },
		"wrong-family":     func(m *message) { m.data[0] = 2 },
		"missing-DST":      func(m *message) { replaceForeignAttribute(m, 1, nil, true) },
		"short-DST":        func(m *message) { replaceForeignAttribute(m, 1, []byte{0}, false) },
		"missing-cache":    func(m *message) { replaceForeignAttribute(m, 3, nil, true) },
		"short-cache":      func(m *message) { replaceForeignAttribute(m, 3, []byte{0}, false) },
		"missing-probes":   func(m *message) { replaceForeignAttribute(m, 4, nil, true) },
		"short-probes":     func(m *message) { replaceForeignAttribute(m, 4, []byte{0}, false) },
		"extra-attribute":  func(m *message) { m.data = append(m.data, attr(9, []byte{0})...) },
		"nested-DST":       func(m *message) { binary.NativeEndian.PutUint16(m.data[14:16], 0x8001) },
		"duplicate-DST":    func(m *message) { m.data = append(m.data, attr(1, netip.MustParseAddr("2001:db8::1").AsSlice())...) },
		"unknown-message":  func(m *message) { m.kind = 99 },
	}
}

func TestSelectedProjectionForeignBridgeLoopbackRefusesOtherShapes(t *testing.T) {
	original, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range loopbackRefusalCases() {
		t.Run(name, func(t *testing.T) {
			row := foreignBridgeLoopbackFrame()
			change(&row)
			if _, bookkeeping, _ := decodeForeignKernelNeighbor(row, original.Segments); bookkeeping {
				t.Fatal("a nonlocal or malformed tuple acquired the loopback exemption")
			}
		})
	}
	for name, segments := range map[string][]Segment{
		"missing-segments": nil,
		"subnet-only":      {{IfIndex: 9, MAC: "02:00:00:00:00:01", LinkAddresses: []string{"2001:db8::/64"}}},
		"loopback-segment": {{IfIndex: 1, MAC: "02:00:00:00:00:01", LinkAddresses: []string{"2001:db8::1/64"}}},
		"unknown-MAC":      {{IfIndex: 9, MAC: "", LinkAddresses: []string{"2001:db8::1/64"}}},
		"malformed-local":  {{IfIndex: 9, MAC: "02:00:00:00:00:01", LinkAddresses: []string{"bad"}}},
		"ambiguous-owner":  append(slices.Clone(original.Segments), original.Segments[0]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, bookkeeping, _ := decodeForeignKernelNeighbor(foreignBridgeLoopbackFrame(), segments); bookkeeping {
				t.Fatal("unproved bridge facts acquired the exemption")
			}
		})
	}
	linklocal := foreignBridgeLoopbackFrame()
	replaceForeignAttribute(&linklocal, 1, netip.MustParseAddr("fe80::1").AsSlice(), false)
	if _, bookkeeping, _ := decodeForeignKernelNeighbor(linklocal, []Segment{{IfIndex: 9, MAC: "02:00:00:00:00:01", LinkAddresses: []string{"fe80::1/64"}}}); bookkeeping {
		t.Fatal("a matching link-local bridge address acquired a global alias exemption")
	}
}

func TestSelectedProjectionForeignBridgeLoopbackKeepsProtectedConflictsSticky(t *testing.T) {
	changes := loopbackRefusalCases()
	for _, name := range []string{"wrong-index", "selected-ingress", "selected-IP", "excluded-IP", "selected-MAC", "excluded-MAC", "router-MAC", "ordinary-MAC", "empty-MAC", "absent-MAC", "reachable", "incomplete", "failed", "router-flag", "proxy-flag", "external-flag", "unicast-type", "broadcast-type", "extra-attribute", "duplicate-DST"} {
		t.Run(name, func(t *testing.T) {
			row := foreignBridgeLoopbackFrame()
			changes[name](&row)
			frames := selectedTestNeighbors()
			frames[10] = append(frames[10], row)
			if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !errors.Is(err, ErrUnknown) {
				t.Fatal("loopback exemption hid a protected global conflict", err)
			}
			o, _, _, transport, review, ctx := selectedTestReview(t)
			transport.push(fenceTestDatagram{raw: frame(row)})
			if o.Verify(ctx, review) == nil || o.VerifyRetainedIncarnation(ctx, review) == nil || o.Verify(ctx, review) == nil {
				t.Fatal("protected conflict did not permanently revoke both original paths")
			}
		})
	}
	// The router's global address remains negative even though the router bit
	// was learned from its other, link-local address on the selected bridge.
	frames := selectedTestNeighbors()
	frames[10] = append(frames[10], neighborFrame(9, "2001:db8::5", "02:00:00:00:00:05", 4))
	original, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames)
	if err != nil {
		t.Fatal(err)
	}
	row := foreignBridgeLoopbackFrame()
	changes["router-IP"](&row)
	frames[10] = append(frames[10], row)
	if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !errors.Is(err, ErrUnknown) {
		t.Fatal("router's global client-facing address was treated as bridge-local", err)
	}
	transport := newFenceTestTransport()
	reader := newOriginalFenceCollector(transport.source())
	defer reader.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := reader.check(ctx, original); err != nil {
		t.Fatal(err)
	}
	transport.push(fenceTestDatagram{raw: frame(row)})
	if reader.check(ctx, original) == nil || reader.check(ctx, original) == nil {
		t.Fatal("router's global address conflict did not permanently revoke the original collector")
	}
	strict := selectedTestSelection()
	strict.SelectedDevices = nil
	frames = selectedTestNeighbors()
	row = foreignBridgeLoopbackFrame()
	changes["selected-ingress"](&row)
	frames[10] = append(frames[10], row)
	if _, err := captureSelectedTest(context.Background(), strict, frames); !errors.Is(err, ErrUnknown) {
		t.Fatal("nil/lan_except selected-segment decoder was weakened", err)
	}
}

func TestSelectedProjectionForeignBridgeLoopbackStillConsumesBounds(t *testing.T) {
	row := foreignBridgeLoopbackFrame()
	frames := selectedTestNeighbors()
	for i := 0; i < 4097; i++ {
		frames[10] = append(frames[10], row)
	}
	if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.limit") {
		t.Fatal("loopback alias bypassed complete-dump record bounds", err)
	}
	original, err := captureSelectedTest(context.Background(), selectedTestSelection(), selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	transport := newFenceTestTransport()
	for i := 0; i <= maxFencePendingDatagrams; i++ {
		transport.push(fenceTestDatagram{raw: frame(row)})
	}
	reader := newOriginalFenceCollector(transport.source())
	defer reader.close()
	waitFenceTest(t, reader.done)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := reader.check(ctx, original); !slices.Contains(DiagnosticStages(err), "fence.receive.pending-count-limit") {
		t.Fatal("loopback alias bypassed original startup bounds", err)
	}
	if reader.check(ctx, original) == nil {
		t.Fatal("alias restored a permanently failed original collector")
	}
}
