package physicalscope

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

func foreignZeroBroadcastFrame(index int, zeroMAC bool) message {
	mac := ""
	if zeroMAC {
		mac = "00:00:00:00:00:00"
	}
	m := neighborFrame(index, "0.0.0.0", mac, 64)
	if !zeroMAC {
		m.data = append(m.data, attr(2, nil)...)
	}
	m.data[11] = 3
	m.data = append(m.data, attr(3, make([]byte, 16))...)
	m.data = append(m.data, attr(4, make([]byte, 4))...)
	return m
}

func replaceForeignAttribute(m *message, kind uint16, raw []byte, remove bool) {
	a, _ := attrs(m.data[12:])
	for kind, raw := range a {
		a[kind] = slices.Clone(raw)
	}
	if remove {
		delete(a, kind)
	} else {
		a[kind] = raw
	}
	m.data = m.data[:12]
	for kind, raw := range a {
		m.data = append(m.data, attr(kind, raw)...)
	}
}

func TestSelectedProjectionForeignZeroBookkeepingPreservesOriginalBothPaths(t *testing.T) {
	selection := selectedTestSelection()
	original, err := captureSelectedTest(context.Background(), selection, selectedTestNeighbors())
	if err != nil {
		t.Fatal(err)
	}
	frames := selectedTestNeighbors()
	for _, row := range []message{foreignZeroBroadcastFrame(30, false), foreignZeroBroadcastFrame(31, true)} {
		frames[2] = append(frames[2], row)
	}
	current, err := captureSelectedTest(context.Background(), selection, frames)
	if err != nil || !reflect.DeepEqual(original, current) {
		t.Fatal("actual foreign bookkeeping shape changed the chosen cohort", err)
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
	for _, row := range frames[2][3:] {
		for _, kind := range []uint16{28, 29} {
			row.kind = kind
			transport.push(fenceTestDatagram{raw: frame(row)})
			if err := o.Verify(ctx, review); err != nil {
				t.Fatal("foreign bookkeeping revoked original forward", err)
			}
			if err := o.VerifyRetainedIncarnation(ctx, review); err != nil {
				t.Fatal("foreign bookkeeping revoked original retained path", err)
			}
			if !reflect.DeepEqual(frozen, review.Snapshot()) {
				t.Fatal("foreign bookkeeping adopted new original facts")
			}
		}
	}
}

func TestSelectedProjectionForeignZeroBookkeepingRefusesEveryOtherShape(t *testing.T) {
	for name, change := range map[string]func(*message){
		"selected-ingress":  func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], 9) },
		"selected-MAC":      func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 3}, false) },
		"excluded-MAC":      func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 6}, false) },
		"router-MAC":        func(m *message) { replaceForeignAttribute(m, 2, []byte{2, 0, 0, 0, 0, 5}, false) },
		"selected-IP":       func(m *message) { replaceForeignAttribute(m, 1, []byte{192, 0, 2, 20}, false) },
		"excluded-IP":       func(m *message) { replaceForeignAttribute(m, 1, []byte{192, 0, 2, 30}, false) },
		"router-IP":         func(m *message) { replaceForeignAttribute(m, 1, []byte{192, 0, 2, 5}, false) },
		"bridge-IP":         func(m *message) { replaceForeignAttribute(m, 1, []byte{192, 0, 2, 1}, false) },
		"broadcast-MAC":     func(m *message) { replaceForeignAttribute(m, 2, []byte{255, 255, 255, 255, 255, 255}, false) },
		"multicast-MAC":     func(m *message) { replaceForeignAttribute(m, 2, []byte{1, 0, 94, 0, 0, 1}, false) },
		"short-MAC":         func(m *message) { replaceForeignAttribute(m, 2, []byte{0}, false) },
		"absent-MAC":        func(m *message) { replaceForeignAttribute(m, 2, nil, true) },
		"reachable":         func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 2) },
		"failed":            func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 32) },
		"incomplete":        func(m *message) { binary.NativeEndian.PutUint16(m.data[8:10], 1) },
		"router-flag":       func(m *message) { m.data[10] = 128 },
		"proxy-flag":        func(m *message) { m.data[10] = 2 },
		"external-flag":     func(m *message) { m.data[10] = 16 },
		"unicast-type":      func(m *message) { m.data[11] = 1 },
		"multicast-type":    func(m *message) { m.data[11] = 5 },
		"other-family":      func(m *message) { m.data[0] = 10 },
		"zero-index":        func(m *message) { binary.NativeEndian.PutUint32(m.data[4:8], 0) },
		"missing-DST":       func(m *message) { replaceForeignAttribute(m, 1, nil, true) },
		"short-DST":         func(m *message) { replaceForeignAttribute(m, 1, []byte{0}, false) },
		"missing-cache":     func(m *message) { replaceForeignAttribute(m, 3, nil, true) },
		"short-cache":       func(m *message) { replaceForeignAttribute(m, 3, []byte{0}, false) },
		"missing-probes":    func(m *message) { replaceForeignAttribute(m, 4, nil, true) },
		"short-probes":      func(m *message) { replaceForeignAttribute(m, 4, []byte{0}, false) },
		"unknown-attribute": func(m *message) { m.data = append(m.data, attr(9, []byte{0})...) },
		"duplicate-DST":     func(m *message) { m.data = append(m.data, attr(1, []byte{0, 0, 0, 0})...) },
		"unknown-message":   func(m *message) { m.kind = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			row := foreignZeroBroadcastFrame(30, true)
			change(&row)
			frames := selectedTestNeighbors()
			frames[2] = append(frames[2], row)
			if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !errors.Is(err, ErrUnknown) {
				t.Fatal("foreign bookkeeping exemption hid unknown or protected evidence", err)
			}
			o, _, _, transport, review, ctx := selectedTestReview(t)
			transport.push(fenceTestDatagram{raw: frame(row)})
			if o.Verify(ctx, review) == nil || o.VerifyRetainedIncarnation(ctx, review) == nil || o.Verify(ctx, review) == nil {
				t.Fatal("unknown or protected bookkeeping shape did not permanently revoke both paths")
			}
		})
	}
	for _, zeroMAC := range []bool{false, true} {
		strict := selectedTestSelection()
		strict.SelectedDevices = nil
		frames := selectedTestNeighbors()
		frames[2] = append(frames[2], foreignZeroBroadcastFrame(9, zeroMAC))
		if _, err := captureSelectedTest(context.Background(), strict, frames); !errors.Is(err, ErrUnknown) {
			t.Fatal("nil/lan_except selected-bridge decoder was weakened", err)
		}
	}
}

func TestSelectedProjectionForeignZeroBookkeepingStillConsumesBounds(t *testing.T) {
	row := foreignZeroBroadcastFrame(30, false)
	frames := selectedTestNeighbors()
	for i := 0; i < 4097; i++ {
		frames[2] = append(frames[2], row)
	}
	if _, err := captureSelectedTest(context.Background(), selectedTestSelection(), frames); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.limit") {
		t.Fatal("foreign bookkeeping bypassed complete-dump record bounds", err)
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
		t.Fatal("foreign bookkeeping bypassed original pre-baseline startup bounds", err)
	}
	if reader.check(ctx, original) == nil {
		t.Fatal("bookkeeping restored a permanently failed original collector")
	}
}
