//go:build linux && razvilka_native_fixture

package nativecheckfixture

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestTLSObservationClosedPrivateCounters(t *testing.T) {
	o := &TLSObservation{}
	for _, line := range []string{
		"http: TLS handshake error from private-address: tls: received record with version 123e when expecting version 303\n",
		"http: TLS handshake error from private-address: tls: private-configuration\n",
		"http: TLS handshake error from private-address: EOF\n",
		"private-configuration\n", "http: TLS handshake error from private-address: EOF", "private\nprivate\n",
		strings.Repeat("private", 700),
	} {
		if n, err := o.Write([]byte(line)); n != len(line) || err != nil {
			t.Fatal("logger drain changed")
		}
	}
	got := o.Snapshot()
	if got != (TLSCounts{RecordVersion123e: 1, OtherTLS: 1, EOF: 1, Unknown: 3, Overflow: 1}) {
		t.Fatal("closed counters differ", got)
	}
	if strings.Contains(fmt.Sprint(got), "private") {
		t.Fatal("private output escaped")
	}
	if got.Since(got) != (TLSCounts{}) {
		t.Fatal("delta changed")
	}
}

func TestTLSObservationConcurrentCounters(t *testing.T) {
	o := &TLSObservation{}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				_, _ = o.Write([]byte("http: TLS handshake error from private: EOF\n"))
				_ = o.Snapshot()
			}
		}()
	}
	workers.Wait()
	if got := o.Snapshot(); got != (TLSCounts{EOF: 800}) {
		t.Fatal("concurrent counters differ", got)
	}
}
