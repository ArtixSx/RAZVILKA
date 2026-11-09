package dnscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Exact former decoder: comparison concerns allocation only, never new
// parsing acceptance, filesystem checks, source authority or route readiness.
func decodeSyntheticDNSLedgerStringCopy(wire []byte) (syntheticDNSLedger, error) {
	var ledger syntheticDNSLedger
	decoder := json.NewDecoder(strings.NewReader(string(wire)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ledger) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateSyntheticDNSLedger(ledger) != nil {
		return ledger, ErrSyntheticDNSMapping
	}
	return ledger, nil
}

func syntheticDNSDecoderWire(t testing.TB, count int) []byte {
	t.Helper()
	ledger := syntheticDNSLedger{Schema: 1, Owner: syntheticDNSLedgerOwner}
	for i := 0; i < count; i++ {
		ledger.Reservations = append(ledger.Reservations, SyntheticDNSMappingObservation{
			Authority:     NetworkPolicyDNSAuthority{Generation: strings.Repeat("a", 64), ControlEpoch: 1, BindingRevision: 1, Exclusions: NetworkPolicyDNSExclusionStamp{Digest: strings.Repeat("b", 64)}},
			PublicationID: fmt.Sprintf("%032x", i+1), Client: netip.MustParseAddr("192.168.1.40"),
			DeviceID: "selected", MAC: "02:00:00:00:00:40", Ingress: "br0", QName: "service.example.com",
			CNAMEChain: []string{"cdn.example.com"}, Synthetic: syntheticDNSAddress(i), RealIPv4: netip.MustParseAddr("1.1.1.2"), ExpiresAt: time.Unix(1900000000, 0).UTC(),
		})
	}
	if err := validateSyntheticDNSLedger(ledger); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSyntheticDNSLedgerDecoderParity(t *testing.T) {
	wire := syntheticDNSDecoderWire(t, 1)
	inputs := [][]byte{nil, {}, []byte("null"), []byte("{}"), wire, append(append([]byte{}, wire...), []byte(" \n\t")...), append(append([]byte{}, wire...), []byte("{}")...), append(append([]byte{}, wire...), 0), []byte(strings.Replace(string(wire), syntheticDNSLedgerOwner, "foreign", 1)), []byte(strings.Replace(string(wire), "{", "{\"unknown\":true,", 1)), []byte{0xff, 0xfe}}
	for i := 0; i < len(wire); i++ {
		inputs = append(inputs, wire[:i])
	}
	for i, input := range inputs {
		before, beforeErr := decodeSyntheticDNSLedgerStringCopy(input)
		after, afterErr := decodeSyntheticDNSLedger(input)
		if beforeErr != afterErr || !reflect.DeepEqual(before, after) {
			t.Fatalf("decoder divergence at %d", i)
		}
	}
}

func TestSyntheticDNSLedgerDecoderOwnedReadIndependence(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	if _, err := s.Reserve(context.Background(), f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	// ReadLimited owns this freshly allocated wire. No source-owned buffer or
	// mutable ledger storage is lent to the synchronous decoder.
	wire, err := s.owned.ReadLimited(syntheticDNSLedgerName, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	before, oldErr := decodeSyntheticDNSLedgerStringCopy(wire)
	after, newErr := decodeSyntheticDNSLedger(wire)
	if oldErr != nil || newErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("actual private ledger mismatch", oldErr, newErr)
	}
	clear(wire)
	if !reflect.DeepEqual(before, after) || validateSyntheticDNSLedger(after) != nil {
		t.Fatal("decoded data retains mutable input")
	}
}

func BenchmarkSyntheticDNSLedgerDecoder(b *testing.B) {
	for _, rows := range []int{1, 16, syntheticDNSMaxReservations} {
		wire := syntheticDNSDecoderWire(b, rows)
		for _, variant := range []string{"before-string-copy", "candidate-byte-reader"} {
			b.Run(fmt.Sprintf("rows%d/%s", rows, variant), func(b *testing.B) {
				decode := decodeSyntheticDNSLedgerStringCopy
				if variant == "candidate-byte-reader" {
					decode = decodeSyntheticDNSLedger
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(wire)))
				b.ResetTimer()
				for range b.N {
					ledger, err := decode(wire)
					if err != nil || len(ledger.Reservations) != rows {
						b.Fatal("modeled parser failure", err)
					}
				}
				b.ReportMetric(float64(rows), "modeled_rows/op")
			})
		}
	}
}
