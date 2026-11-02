package dnscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Actual resolver/control/ledger and mapping ownership; publication/kernel
// coordination is explicitly modeled, never a native baseline acceptance.
func TestSyntheticDNSContinuationAppendsWithoutRevivingOldMapping(t *testing.T) {
	f, old, mapping, review, held, _ := syntheticDNSRetirementModel(t)
	query := scopedQuery(t, "service.example.com", dnsmessage.TypeA)
	if err := old.Publish(held, f.client, query, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := review.ReviewContinuation(held); err == nil {
		t.Fatal("live source issued continuation")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	continuation, err := review.ReviewContinuation(held)
	if err != nil || continuation.Reference().Count != 1 || len(continuation.Reference().PrefixSHA256) != 64 {
		t.Fatal(continuation, err)
	}
	copy := *continuation
	if _, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(held, context.Background(), f.r, f.control, f.root, f.definition, nil, &copy); err == nil {
		t.Fatal("copied continuation admitted")
	}
	if _, err := NewNetworkPolicyDNSSyntheticResolver(held, context.Background(), f.r, f.control, f.root, f.definition, nil); err == nil {
		t.Fatal("ordinary constructor adopted issued prefix")
	}
	next, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(held, context.Background(), f.r, f.control, f.root, f.definition, old.publication, continuation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	if _, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(held, context.Background(), f.r, f.control, f.root, f.definition, nil, continuation); err == nil {
		t.Fatal("continuation replayed")
	}
	if _, err := next.LookupPublished(held, f.client, netip.MustParseAddr("198.18.0.1")); err == nil || mapping.Current(held) == nil {
		t.Fatal("old row became live successor grant")
	}
	reserved, err := next.Reserve(held, f.client, query)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := reserved.Observation(held)
	if err != nil || observation.Synthetic != netip.MustParseAddr("198.18.0.2") {
		t.Fatal("occupied alias reused", observation, err)
	}
	if closed, err := review.ObserveClosed(held); err != nil || closed.Synthetic != netip.MustParseAddr("198.18.0.1") || !closed.PossiblyIssued {
		t.Fatal("original prefix lost after authorized append", closed, err)
	}
	nextReview, err := reserved.ReviewRetirement(held, next, f.r.defaultDNS.manager, f.r.frozenPlan, f.control, f.root, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Publish(held, f.client, query, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	secondToken, err := nextReview.ReviewContinuation(held)
	if err != nil {
		t.Fatal(err)
	}
	third, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(held, context.Background(), f.r, f.control, f.root, f.definition, nil, secondToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { third.Close() })
	thirdMapping, err := third.Reserve(held, f.client, query)
	if err != nil {
		t.Fatal(err)
	}
	thirdObservation, err := thirdMapping.Observation(held)
	if err != nil || thirdObservation.Synthetic != netip.MustParseAddr("198.18.0.3") {
		t.Fatal("older generation alias reused", thirdObservation, err)
	}
	if _, err := review.ObserveClosed(held); err != nil {
		t.Fatal("oldest original prefix lost after second linked successor", err)
	}
	if _, err := nextReview.ObserveClosed(held); err != nil {
		t.Fatal("middle original prefix lost after linked successor", err)
	}
	// A valid-looking extra row written outside the linked original writer is
	// not an append grant, even when the protected root and prefix are intact.
	third.mu.Lock()
	forged := cloneSyntheticDNSLedger(third.ledger)
	row := forged.Reservations[len(forged.Reservations)-1]
	row.Synthetic = syntheticDNSAddress(len(forged.Reservations))
	row.PublicationID = "ffffffffffffffffffffffffffffffff"
	forged.Reservations = append(forged.Reservations, row)
	third.mu.Unlock()
	wire, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, syntheticDNSLedgerName), wire, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := review.ObserveClosed(held); err == nil {
		t.Fatal("disk suffix adopted without original writer")
	}
}

func TestSyntheticDNSContinuationFailedAdmissionCannotConsumeToken(t *testing.T) {
	for _, kind := range []string{"canceled", "root-replacement"} {
		t.Run(kind, func(t *testing.T) {
			f, old, _, review, held, _ := syntheticDNSRetirementModel(t)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			c, err := review.ReviewContinuation(held)
			if err != nil {
				t.Fatal(err)
			}
			failed := held
			if kind == "canceled" {
				var cancel context.CancelFunc
				failed, cancel = context.WithCancel(held)
				cancel()
			} else {
				if err := os.Rename(f.root, f.root+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(f.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(failed, context.Background(), f.r, f.control, f.root, f.definition, nil, c); err == nil {
				s.Close()
				t.Fatal("failed admission adopted continuation")
			}
			if kind == "root-replacement" {
				if err := os.Remove(f.root); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.root+"-original", f.root); err != nil {
					t.Fatal(err)
				}
			}
			s, err := NewNetworkPolicyDNSSyntheticResolverWithContinuation(held, context.Background(), f.r, f.control, f.root, f.definition, nil, c)
			if err != nil {
				t.Fatal("known failed constructor consumed original token", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Typed history model written through the SAME actual original ledger writer;
// the added documentary rows have no live mapping or packet authority.
func TestSyntheticDNSContinuationRefusesActualLedgerCapacity(t *testing.T) {
	_, s, _, review, held, _ := syntheticDNSRetirementModel(t)
	s.mu.Lock()
	base := s.ledger.Reservations[0]
	for i := 1; i < syntheticDNSMaxReservations; i++ {
		row := base
		row.Synthetic = syntheticDNSAddress(i)
		row.PublicationID = fmt.Sprintf("%032x", i)
		if row.PublicationID == base.PublicationID {
			row.PublicationID = fmt.Sprintf("%032x", i+syntheticDNSMaxReservations)
		}
		s.ledger.Reservations = append(s.ledger.Reservations, row)
	}
	err := s.writeLedger(held)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := review.ReviewContinuation(held); err == nil || c != nil {
		t.Fatal("full256 prefix issued append permission", err)
	}
}
