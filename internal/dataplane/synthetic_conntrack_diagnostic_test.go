package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Socket-free refusal models. A reason never makes a refused prefix complete.
func TestSyntheticConntrackDiagnosticRefusalReasons(t *testing.T) {
	check := func(t *testing.T, body []byte, flags uint16, want syntheticCTReason) {
		t.Helper()
		d, _ := newSyntheticCTDecoder(17, 29)
		err := d.consume(backendNFTDatagram{Data: syntheticCTModelFrame(syntheticCTNew, flags, body)})
		if err == nil || !errors.Is(err, errSyntheticConntrack) || syntheticCTDiagnostic(err) != want.label() {
			t.Fatal("refusal diagnostic lost", syntheticCTDiagnostic(err))
		}
		image, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, nil })
		if err == nil || image.complete || len(image.rows) != 0 {
			t.Fatal("refused prefix became complete")
		}
	}
	// Every unknown high status bit still refuses, including the vendor bits
	// 20..24. This diagnostic patch does not select or widen a vendor ABI.
	for bit := uint(16); bit < 32; bit++ {
		t.Run(fmt.Sprintf("status-bit-%d", bit), func(t *testing.T) {
			r := syntheticCTModelRow()
			r.Status |= uint32(1) << bit
			check(t, syntheticCTModelBody(r, 300), 2, syntheticCTStatusMask)
		})
	}
	for _, row := range []struct {
		kind uint16
		want syntheticCTReason
	}{{24, syntheticCTAttr24}, {25, syntheticCTAttr25}, {26, syntheticCTAttr26}, {99, syntheticCTUnknownAttr}} {
		t.Run(fmt.Sprintf("top-attribute-%d", row.kind), func(t *testing.T) {
			body := append(syntheticCTModelBody(syntheticCTModelRow(), 300), syntheticCTModelAttr(row.kind, []byte("private native payload"))...)
			check(t, body, 2, row.want)
		})
	}
	for _, flags := range []uint16{0, 1, 0x12, 0x22, 0x82} {
		check(t, syntheticCTModelBody(syntheticCTModelRow(), 300), flags, syntheticCTMessageFlags)
	}
	check(t, syntheticCTModelDrop(syntheticCTModelBody(syntheticCTModelRow(), 300), 12), 2, syntheticCTIDShape)
	// A fully decoded generic row keeps its exact observation and completion.
	r := syntheticCTModelRow()
	i := syntheticCTModelImage(t, syntheticCTModelFrame(syntheticCTNew, 2, syntheticCTModelBody(r, 300)))
	if !i.complete || len(i.rows) != 1 || i.rows[0] != r {
		t.Fatal("valid generic observation changed")
	}
}

func TestSyntheticConntrackDiagnosticScrubsCausesAndDrain(t *testing.T) {
	private := errors.New("native tuple=192.0.2.1:52000 seq=17 port=29 id=11")
	err := syntheticCTFailure(syntheticCTReceive, errors.Join(private, context.Canceled))
	if !errors.Is(err, private) || !errors.Is(err, context.Canceled) || !errors.Is(err, errSyntheticConntrack) {
		t.Fatal("cause identity lost")
	}
	if err.Error() != errSyntheticConntrack.Error()+": transport-receive" || strings.Contains(err.Error(), private.Error()) {
		t.Fatal("native cause text escaped")
	}
	if syntheticCTDiagnostic(errors.Join(errors.New("outer private error"), err)) != "transport-receive" {
		t.Fatal("wrapped reason lost")
	}
	if syntheticCTDiagnostic(private) != "unclassified" || syntheticCTDiagnostic(nil) != "none" {
		t.Fatal("unclassified reason escaped")
	}
	unknown := syntheticCTFailure(syntheticCTReason(private.Error()), private)
	if syntheticCTDiagnostic(unknown) != "unclassified" || unknown.Error() != errSyntheticConntrack.Error()+": unclassified" {
		t.Fatal("reason outside fixed allowlist escaped")
	}
	d, _ := newSyntheticCTDecoder(17, 29)
	if err := d.consume(backendNFTDatagram{Data: syntheticCTModelFrame(3, 2, make([]byte, 4))}); err != nil {
		t.Fatal("valid terminal refused")
	}
	image, err := d.finishReceive(func() (backendNFTDatagram, bool, error) { return backendNFTDatagram{}, false, private })
	if image.complete || len(image.rows) != 0 || !errors.Is(err, private) || syntheticCTDiagnostic(err) != "terminal-drain" || strings.Contains(err.Error(), private.Error()) {
		t.Fatal("drain failure escaped or became complete")
	}
}
