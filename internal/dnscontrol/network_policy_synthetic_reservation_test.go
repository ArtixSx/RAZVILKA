package dnscontrol

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSyntheticDNSSameGateConcurrentReservationsReuseOriginal(t *testing.T) {
	f := syntheticDNSModelFixture(t, nil)
	s := f.source(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	held, release, err := f.gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	query := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	answer, err := f.r.resolveSyntheticAnswer(held, f.client, query, true)
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent children may borrow the same exclusive admission. Start all
	// workers just before the original mapping lookup, after their source checks.
	const workers = 32
	var arrived atomic.Int32
	startLookup := make(chan struct{})
	f.r.now = func() time.Time {
		if n := arrived.Add(1); n <= workers {
			if n == workers {
				close(startLookup)
			}
			select {
			case <-startLookup:
			case <-ctx.Done():
			}
		}
		return answer.resolvedAt
	}

	type reservation struct {
		mapping *SyntheticDNSMapping
		err     error
	}
	results := make(chan reservation, workers)
	for range workers {
		go func() {
			mapping, err := s.mappingForAnswer(held, f.client, query, answer, true)
			results <- reservation{mapping, err}
		}()
	}
	var original *SyntheticDNSMapping
	for range workers {
		result := <-results
		if result.err != nil || result.mapping == nil {
			t.Error("reservation failed", result.err)
			continue
		}
		if original == nil {
			original = result.mapping
		}
		if result.mapping != original {
			t.Error("shared Gate created a different handle for the same reservation")
		}
	}
	if got := len(s.ledger.Reservations); got != 1 {
		t.Fatalf("same DNS answer consumed %d aliases, want 1", got)
	}
}
