//go:build linux && razvilka_native_fixture

package nativecheckfixture

import (
	"bytes"
	"log"
	"sync"
	"testing"
)

// TLSObservation retains only closed counters, never log bytes or addresses.
// net/http's logger calls Write once per complete record. Oversized or partial
// records remain unknown; collection does not influence TLS admission.
type TLSObservation struct {
	mu     sync.Mutex
	counts TLSCounts
}

type TLSCounts struct {
	RecordVersion123e, OtherTLS, EOF, Unknown, Overflow uint64
}

func StartWithTLSObservation(t *testing.T) (*Fixture, *TLSObservation) {
	t.Helper()
	observation := &TLSObservation{}
	return start(t, log.New(observation, "", 0)), observation
}

func (o *TLSObservation) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case len(p) > 4096:
		o.counts.Overflow++
	case bytes.Count(p, []byte{'\n'}) != 1 || len(p) == 0 || p[len(p)-1] != '\n' || !bytes.HasPrefix(p, []byte("http: TLS handshake error from ")):
		o.counts.Unknown++
	case bytes.HasSuffix(p, []byte(": tls: received record with version 123e when expecting version 303\n")):
		o.counts.RecordVersion123e++
	case bytes.HasSuffix(p, []byte(": EOF\n")):
		o.counts.EOF++
	case bytes.Contains(p, []byte(": tls: ")):
		o.counts.OtherTLS++
	default:
		o.counts.Unknown++
	}
	return len(p), nil
}

func (o *TLSObservation) Snapshot() TLSCounts {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts
}

func (c TLSCounts) Since(before TLSCounts) TLSCounts {
	return TLSCounts{c.RecordVersion123e - before.RecordVersion123e, c.OtherTLS - before.OtherTLS, c.EOF - before.EOF, c.Unknown - before.Unknown, c.Overflow - before.Overflow}
}
