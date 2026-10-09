package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Socket-free models of the pinned OUTPUT producer, not its request policy.
func syntheticCTStockModelNative(value uint64, size int) []byte {
	b := make([]byte, size)
	if size == 4 {
		binary.NativeEndian.PutUint32(b, uint32(value))
	} else if size == 8 {
		binary.NativeEndian.PutUint64(b, value)
	}
	return b
}

func syntheticCTStockModelIfaces(mac bool) []byte {
	b := syntheticCTModelAttr(0, syntheticCTStockModelNative(0x01020304, 4))
	b = append(b, syntheticCTModelAttr(1, syntheticCTStockModelNative(0xfffffff9, 4))...)
	if mac {
		b = append(b, syntheticCTModelAttr(2, []byte{2, 3, 4, 5, 6, 7})...)
	}
	return append(b, syntheticCTModelAttr(3, syntheticCTModelBE(1, 4))...)
}

func syntheticCTStockModelNTCE(pad bool) []byte {
	b := syntheticCTModelAttr(0, syntheticCTStockModelNative(0x01020304, 4))
	b = append(b, syntheticCTModelAttr(1, syntheticCTStockModelNative(0x55667788, 4))...)
	if pad {
		b = append(b, syntheticCTModelAttr(6, nil)...)
	}
	b = append(b, syntheticCTModelAttr(2, syntheticCTStockModelNative(0x060504030201, 8))...)
	b = append(b, syntheticCTModelAttr(3, []byte{255})...)
	b = append(b, syntheticCTModelAttr(4, []byte{7})...)
	return append(b, syntheticCTModelAttr(5, []byte{7})...)
}

func syntheticCTStockModelBody(r syntheticCTRow) []byte {
	b := syntheticCTModelDrop(syntheticCTModelBody(r, 300), 12)
	return append(b, syntheticCTModelAttr(12, syntheticCTStockModelNative(uint64(r.ID), 4))...)
}

func syntheticCTStockModelReplace(b []byte, kind uint16, data []byte) []byte {
	// Reuse the top-level drop model solely by prepending its four-byte prefix.
	framed := append([]byte{2, 0, 0, 0}, b...)
	return append(syntheticCTModelDrop(framed, kind)[4:], syntheticCTModelAttr(kind, data)...)
}

func syntheticCTStockModelImage(t *testing.T, body []byte) syntheticCTImage {
	t.Helper()
	d, err := newSyntheticCTDecoderForABI(17, 29, syntheticCTStockNC1812)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][]byte{syntheticCTModelFrame(syntheticCTNew, 2, body), syntheticCTModelFrame(3, 2, make([]byte, 4))} {
		if err := d.consume(backendNFTDatagram{Data: f}); err != nil {
			t.Fatal(syntheticCTDiagnostic(err))
		}
	}
	i, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, nil })
	if err != nil || !i.complete || i.abi != syntheticCTStockNC1812 {
		t.Fatal("stock completion lost", syntheticCTDiagnostic(err))
	}
	return i
}

func TestSyntheticConntrackStockPinnedProducerPreservesAllVendorFields(t *testing.T) {
	for _, kind := range []string{"all", "mark-zero", "ifaces-no-mac", "ntce-no-pad", "status-only"} {
		t.Run(kind, func(t *testing.T) {
			r := syntheticCTModelRow()
			r.ID = 0x01020304
			r.Unsafe = true
			if kind == "all" || kind == "status-only" {
				r.Status |= syntheticCTStockStatusUnsafe
			}
			body := syntheticCTStockModelBody(r)
			if kind == "all" || kind == "mark-zero" {
				if kind == "all" {
					r.Stock.NDMMark = 0x1234561c
				}
				r.Stock.NDMMarkPresent = true
				body = append(body, syntheticCTModelAttr(24, syntheticCTStockModelNative(uint64(r.Stock.NDMMark), 4))...)
			}
			if kind == "all" || kind == "ifaces-no-mac" {
				r.Stock.IfacesPresent = true
				r.Stock.Ifaces = syntheticCTStockIfaces{WAN: 0x01020304, LAN: -7, Flags: 1}
				if kind == "all" {
					r.Stock.Ifaces.MAC, r.Stock.Ifaces.MACPresent = [6]byte{2, 3, 4, 5, 6, 7}, true
				}
				body = append(body, syntheticCTModelAttr(0x8019, syntheticCTStockModelIfaces(kind == "all"))...)
			}
			if kind == "all" || kind == "ntce-no-pad" {
				r.Stock.NTCEPresent = true
				r.Stock.NTCE = syntheticCTStockNTCE{App: 0x01020304, Group: 0x55667788, Attributes: 0x060504030201, OS: 255, Flags: 7, ServiceClass: 7}
				body = append(body, syntheticCTModelAttr(0x801a, syntheticCTStockModelNTCE(kind == "all"))...)
			}
			i := syntheticCTStockModelImage(t, body)
			if len(i.rows) != 1 || i.rows[0] != r {
				t.Fatal("typed producer fields or presence changed")
			}
			generic, _ := newSyntheticCTDecoder(17, 29)
			if generic.consume(backendNFTDatagram{Data: syntheticCTModelFrame(syntheticCTNew, 2, body)}) == nil {
				t.Fatal("stock observation entered generic ABI")
			}
			o, err := compareSyntheticSettlement(i, i, syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443"))
			if err != nil || len(o.second) != 1 || o.second[0].kind != "unsupported" || o.comparison != "unchanged" || o.pending == "" {
				t.Fatal("vendor row granted ownership or settlement")
			}
			// Classification also checks the retained vendor fields/status;
			// losing the convenience Unsafe bit cannot admit the candidate.
			i.rows[0].Unsafe = false
			o, err = compareSyntheticSettlement(i, i, syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443"))
			if err != nil || len(o.second) != 1 || o.second[0].kind != "unsupported" || o.pending == "" {
				t.Fatal("vendor candidate depended only on Unsafe boolean")
			}
		})
	}
}

func TestSyntheticConntrackStockUnknownStatusAndTopAttributesStillRefuse(t *testing.T) {
	for bit := uint(14); bit < 32; bit++ {
		if bit >= 20 && bit <= 24 {
			continue
		}
		t.Run(fmt.Sprintf("status-%d", bit), func(t *testing.T) {
			r := syntheticCTModelRow()
			r.Status |= uint32(1) << bit
			syntheticCTStockModelRefusal(t, syntheticCTStockModelBody(r), syntheticCTStatusMask)
		})
	}
	for _, kind := range []uint16{6, 13, 19, 21, 22, 23, 27, 99} {
		body := append(syntheticCTStockModelBody(syntheticCTModelRow()), syntheticCTModelAttr(kind, nil)...)
		syntheticCTStockModelRefusal(t, body, syntheticCTUnknownAttr)
	}
	// Global/generic tuple parsing still forbids zero, even under stock ABI.
	if _, err := syntheticCTAttrs(syntheticCTModelAttr(0, nil)); err == nil {
		t.Fatal("global kind-zero waiver")
	}
	r := syntheticCTModelRow()
	body := syntheticCTModelDrop(syntheticCTStockModelBody(r), 1)
	tuple := append(syntheticCTModelTuple(r.Original), syntheticCTModelAttr(0, nil)...)
	body = append(body, syntheticCTModelAttr(0x8001, tuple)...)
	syntheticCTStockModelRefusal(t, body, syntheticCTTupleShape)
	if _, err := newSyntheticCTDecoderForABI(17, 29, syntheticCTABI(99)); err == nil {
		t.Fatal("unknown ABI admitted")
	}
	// The producer's native ID stays mandatory, nonzero and unflagged.
	for _, bad := range []struct {
		kind uint16
		data []byte
		want syntheticCTReason
	}{
		{12, nil, syntheticCTIDShape},
		{12, make([]byte, 4), syntheticCTZeroID},
		{0x400c, syntheticCTStockModelNative(11, 4), syntheticCTIDShape},
	} {
		body := syntheticCTModelDrop(syntheticCTStockModelBody(r), 12)
		body = append(body, syntheticCTModelAttr(bad.kind, bad.data)...)
		syntheticCTStockModelRefusal(t, body, bad.want)
	}
}

func TestSyntheticConntrackStockDuplicateAndMalformedForeignPrefixNeverComplete(t *testing.T) {
	r := syntheticCTModelRow()
	r.Status |= 1 << 20
	valid := syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTStockModelBody(r))
	for _, kind := range []string{"duplicate-id", "foreign-unknown", "interrupted", "filtered", "missing-done", "terminal-drain"} {
		t.Run(kind, func(t *testing.T) {
			d, _ := newSyntheticCTDecoderForABI(17, 29, syntheticCTStockNC1812)
			if err := d.consume(backendNFTDatagram{Data: valid}); err != nil {
				t.Fatal(err)
			}
			frame := append([]byte(nil), valid...)
			switch kind {
			case "duplicate-id":
			case "foreign-unknown":
				foreign := r
				foreign.ID++
				foreign.Original.Destination = netip.MustParseAddr("203.0.113.1")
				body := append(syntheticCTStockModelBody(foreign), syntheticCTModelAttr(99, nil)...)
				frame = syntheticCTModelFrame(syntheticCTNew, 2, body)
			case "interrupted":
				binary.NativeEndian.PutUint16(frame[6:], 0x12)
			case "filtered":
				binary.NativeEndian.PutUint16(frame[6:], 0x22)
			case "missing-done":
				frame = nil
			case "terminal-drain":
				frame = syntheticCTModelFrame(3, 2, make([]byte, 4))
			}
			if len(frame) != 0 {
				err := d.consume(backendNFTDatagram{Data: frame})
				if kind != "terminal-drain" && err == nil {
					t.Fatal("invalid stock prefix admitted")
				}
				if kind == "terminal-drain" && err != nil {
					t.Fatal("valid DONE refused")
				}
			}
			image, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, kind == "terminal-drain", nil })
			if err == nil || image.complete || len(image.rows) != 0 {
				t.Fatal("stock prefix became complete evidence")
			}
		})
	}
}

func syntheticCTStockModelRefusal(t *testing.T, body []byte, want syntheticCTReason) {
	t.Helper()
	d, _ := newSyntheticCTDecoderForABI(17, 29, syntheticCTStockNC1812)
	err := d.consume(backendNFTDatagram{Data: syntheticCTModelFrame(syntheticCTNew, 2, body)})
	if err == nil || !errors.Is(err, errSyntheticConntrack) || syntheticCTDiagnostic(err) != want.label() {
		t.Fatal("stock refusal lost", syntheticCTDiagnostic(err))
	}
	i, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, nil })
	if err == nil || i.complete || len(i.rows) != 0 {
		t.Fatal("refused stock prefix became complete")
	}
}

func TestSyntheticConntrackStockVendorSchemasRefuseMalformedAndUnknown(t *testing.T) {
	for _, kind := range []uint16{24, 0x4018, 0x8018} {
		for _, size := range []int{1, 4, 8} {
			if kind == 24 && size == 4 {
				continue
			}
			body := append(syntheticCTStockModelBody(syntheticCTModelRow()), syntheticCTModelAttr(kind, make([]byte, size))...)
			syntheticCTStockModelRefusal(t, body, syntheticCTStockMarkShape)
		}
	}
	for _, top := range []uint16{25, 26} {
		base, max, reason := syntheticCTStockModelIfaces(true), uint16(3), syntheticCTStockIfacesShape
		if top == 26 {
			base, max, reason = syntheticCTStockModelNTCE(true), 6, syntheticCTStockNTCEShape
		}
		for _, malformed := range []string{"outer-plain", "outer-network", "unknown-child", "duplicate-zero", "child-flags", "short-child", "child-length", "bad-pad"} {
			t.Run(fmt.Sprintf("attribute-%d-%s", top, malformed), func(t *testing.T) {
				b, rawTop := append([]byte(nil), base...), top|0x8000
				switch malformed {
				case "outer-plain":
					rawTop = top
				case "outer-network":
					rawTop = top | 0x4000
				case "unknown-child":
					b = append(b, syntheticCTModelAttr(max+1, nil)...)
				case "duplicate-zero":
					b = append(b, syntheticCTModelAttr(0, make([]byte, 4))...)
				case "child-flags":
					binary.NativeEndian.PutUint16(b[2:], 0x4000)
				case "short-child":
					b = append(b, 1)
				case "child-length":
					b = syntheticCTStockModelReplace(b, 0, make([]byte, 2))
				case "bad-pad":
					b = syntheticCTStockModelReplace(b, 2, []byte{1})
					b[len(b)-1] = 1
				}
				body := append(syntheticCTStockModelBody(syntheticCTModelRow()), syntheticCTModelAttr(rawTop, b)...)
				syntheticCTStockModelRefusal(t, body, reason)
			})
		}
		for child := uint16(0); child <= max; child++ {
			if top == 25 && child == 2 || top == 26 && child == 6 {
				continue // only MAC and PAD are optional
			}
			b := syntheticCTModelDrop(append([]byte{2, 0, 0, 0}, base...), child)[4:]
			body := append(syntheticCTStockModelBody(syntheticCTModelRow()), syntheticCTModelAttr(top|0x8000, b)...)
			syntheticCTStockModelRefusal(t, body, reason)
		}
	}
	for _, bad := range []struct {
		top, child uint16
		data       []byte
		reason     syntheticCTReason
	}{
		{25, 3, syntheticCTModelBE(2, 4), syntheticCTStockIfacesShape},
		{25, 2, make([]byte, 5), syntheticCTStockIfacesShape},
		{26, 2, syntheticCTStockModelNative(1<<48, 8), syntheticCTStockNTCEShape},
		{26, 2, make([]byte, 4), syntheticCTStockNTCEShape},
		{26, 4, []byte{8}, syntheticCTStockNTCEShape},
		{26, 5, []byte{8}, syntheticCTStockNTCEShape},
		{26, 6, []byte{0}, syntheticCTStockNTCEShape},
	} {
		b := syntheticCTStockModelIfaces(true)
		if bad.top == 26 {
			b = syntheticCTStockModelNTCE(true)
		}
		b = syntheticCTStockModelReplace(b, bad.child, bad.data)
		body := append(syntheticCTStockModelBody(syntheticCTModelRow()), syntheticCTModelAttr(bad.top|0x8000, b)...)
		syntheticCTStockModelRefusal(t, body, bad.reason)
	}
}

func TestSyntheticConntrackStockIdentitySelectionIsOriginalAndClosed(t *testing.T) {
	stock := netidentity.Identity{Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: "11111111-2222-3333-4444-555555555555", PlatformReviewSHA256: syntheticCTStockScopeSHA256}
	generic := netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: stock.BootID, Inode: 123}
	for _, actual := range []netidentity.Identity{stock, generic} {
		want := syntheticCTGeneric
		if actual == stock {
			want = syntheticCTStockNC1812
		}
		got, err := syntheticCTABIForIdentity(actual)
		if err != nil || got != want {
			t.Fatal("exact identity ABI lost")
		}
	}
	for _, invalid := range []netidentity.Identity{{}, {Version: 1, Kind: netidentity.ReviewedSingleInitNet, BootID: stock.BootID, PlatformReviewSHA256: "unknown"}, {Version: 1, Kind: netidentity.ProcNetInode, BootID: stock.BootID, Inode: 123, PlatformReviewSHA256: stock.PlatformReviewSHA256}} {
		if _, err := syntheticCTABIForIdentity(invalid); err == nil {
			t.Fatal("unknown/mixed profile admitted")
		}
	}
	for _, kind := range []string{"stock", "generic", "drift", "no-callback", "double-callback", "closing-refusal", "unbounded", "cancelled", "leaf-unbounded", "leaf-extended"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			actual := stock
			if kind == "generic" {
				actual = generic
			}
			original := &networkPolicyIdentity{value: actual}
			original.withCurrent = func(held context.Context, use func(context.Context, netidentity.Identity) error) error {
				if kind == "leaf-unbounded" {
					held = context.Background()
				}
				if kind == "leaf-extended" {
					var finish context.CancelFunc
					held, finish = context.WithTimeout(context.Background(), 2*time.Second)
					defer finish()
				}
				if kind == "no-callback" {
					return nil
				}
				got := actual
				if kind == "drift" {
					got.BootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
				}
				if err := use(held, got); err != nil {
					return err
				}
				if kind == "double-callback" {
					return use(held, got)
				}
				if kind == "closing-refusal" {
					return ErrNetworkPolicyIdentity
				}
				return nil
			}
			if kind == "unbounded" {
				ctx = context.Background()
			}
			if kind == "cancelled" {
				cancel()
			}
			calls := 0
			err := syntheticCTWithOriginalIdentity(ctx, original, func(held context.Context, got netidentity.Identity) error {
				calls++
				if got != actual || held != ctx {
					t.Fatal("actual bracket identity/context replaced")
				}
				return nil
			})
			if kind == "stock" || kind == "generic" {
				if err != nil || calls != 1 {
					t.Fatal("original observation refused")
				}
			} else if err == nil {
				t.Fatal("identity boundary refusal waived")
			}
			if calls > 1 {
				t.Fatal("duplicate callback entered read")
			}
			if kind == "closing-refusal" && !errors.Is(err, ErrNetworkPolicyIdentity) {
				t.Fatal("closing cause lost")
			}
		})
	}
}

func TestSyntheticConntrackStockPreservedExtensionsRemainComparisonCandidates(t *testing.T) {
	r := syntheticCTModelRow()
	r.Status |= 1 << 20
	body := syntheticCTStockModelBody(r)
	body = append(body, syntheticCTModelAttr(24, syntheticCTStockModelNative(0, 4))...)
	body = append(body, syntheticCTModelAttr(0x8019, syntheticCTStockModelIfaces(true))...)
	body = append(body, syntheticCTModelAttr(0x801a, syntheticCTStockModelNTCE(true))...)
	first := syntheticCTStockModelImage(t, body)
	changes := []func(*syntheticCTRow){
		func(r *syntheticCTRow) { r.Stock.NDMMark++ },
		func(r *syntheticCTRow) { r.Stock.NDMMarkPresent = false },
		func(r *syntheticCTRow) { r.Stock.Ifaces.WAN++ },
		func(r *syntheticCTRow) { r.Stock.Ifaces.LAN++ },
		func(r *syntheticCTRow) { r.Stock.Ifaces.Flags = 0 },
		func(r *syntheticCTRow) { r.Stock.Ifaces.MAC[0]++ },
		func(r *syntheticCTRow) { r.Stock.Ifaces.MACPresent = false },
		func(r *syntheticCTRow) { r.Stock.IfacesPresent = false },
		func(r *syntheticCTRow) { r.Stock.NTCE.App++ },
		func(r *syntheticCTRow) { r.Stock.NTCE.Group++ },
		func(r *syntheticCTRow) { r.Stock.NTCE.Attributes++ },
		func(r *syntheticCTRow) { r.Stock.NTCE.OS-- },
		func(r *syntheticCTRow) { r.Stock.NTCE.Flags = 0 },
		func(r *syntheticCTRow) { r.Stock.NTCE.ServiceClass = 0 },
		func(r *syntheticCTRow) { r.Stock.NTCEPresent = false },
	}
	for _, change := range changes {
		row := first.rows[0]
		change(&row)
		second := syntheticCTImage{rows: []syntheticCTRow{row}, complete: true, abi: syntheticCTStockNC1812}
		o, err := compareSyntheticSettlement(first, second, syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443"))
		if err != nil || len(o.second) != 1 || o.second[0].kind != "unsupported" || o.comparison != "changed" || o.pending == "" {
			t.Fatal("vendor field change ignored or ownership granted")
		}
	}
	other := first
	other.abi = syntheticCTGeneric
	if _, err := compareSyntheticSettlement(first, other, syntheticCTModelMapping(), netip.MustParseAddrPort("192.168.1.1:10443")); err == nil {
		t.Fatal("mixed ABI images compared as same scope")
	}
}
