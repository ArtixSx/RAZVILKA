package dnscontrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/net/dns/dnsmessage"
)

func syntheticDNSRetirementModel(t *testing.T) (syntheticDNSFixture, *NetworkPolicyDNSSyntheticResolver, *SyntheticDNSMapping, *SyntheticDNSRetirementReview, context.Context, func()) {
	t.Helper()
	f := syntheticDNSModelFixture(t, nil)
	owner := &syntheticDNSPublicationModel{use: func(c context.Context, _ *SyntheticDNSMapping, use func(context.Context) error) error { return use(c) }}
	s := f.source(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	held, release, err := f.gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	m, err := s.Reserve(held, f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.ReviewRetirement(held, f.r.defaultDNS.manager, f.r.frozenPlan, f.control, f.root, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	return f, s, m, r, held, release
}

func TestSyntheticDNSRetirementOriginalFinalPublicationAfterStopAndExpiry(t *testing.T) {
	f, s, m, r, held, release := syntheticDNSRetirementModel(t)
	if _, err := r.ClosedObservation(held); err == nil {
		t.Fatal("live source became closed evidence")
	}
	// Publication occurs AFTER review issuance; the reader must obtain the
	// latest durable issue bound rather than the pre-issued frozen snapshot.
	if err := s.Publish(held, f.client, scopedQuery(t, "service.example.com", dnsmessage.TypeA), func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(context.Background(), f.controlRoot, "11111111111111111111111111111111", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f.r.now = func() time.Time { return r.frozen.ExpiresAt.Add(time.Hour) }
	f.gate.FenceJournal()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	row, err := r.ClosedObservation(ctx)
	if err != nil || !row.PossiblyIssued || row.LastPossiblyIssuedAt.IsZero() || row.LastPossiblyIssuedTTLBound == 0 {
		t.Fatal(row, err)
	}
	deadline, err := r.CacheDeadline(ctx)
	if err != nil || deadline != row.LastPossiblyIssuedAt.Add(time.Duration(row.LastPossiblyIssuedTTLBound)*time.Second) {
		t.Fatal(deadline, err)
	}
	if m.Current(ctx) == nil {
		t.Fatal("retirement revived forward mapping")
	}
	row.QName = "forged.example.com"
	if again, err := r.ClosedObservation(ctx); err != nil || again.QName != "service.example.com" {
		t.Fatal(again, err)
	}
	release()
	if _, err := r.ClosedObservation(ctx); err == nil {
		t.Fatal("released operation revived by fresh context")
	}
	if _, err := os.Stat(filepath.Join(f.root, syntheticDNSLedgerName)); err != nil {
		t.Fatal("read-only review removed reservations", err)
	}
}

func TestSyntheticDNSRetirementCopiesRootsLedgerAndLifetimeRefuse(t *testing.T) {
	for _, change := range []string{"copy", "mapping-copy", "unbounded", "cancelled", "root", "ledger", "memory-coordinates", "close-not-joined", "control-closed"} {
		t.Run(change, func(t *testing.T) {
			f, s, m, r, _, _ := syntheticDNSRetirementModel(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "copy":
				copy := *r
				r = &copy
			case "mapping-copy":
				copy := *m
				r.mapping = &copy
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "root":
				if err := os.Rename(f.root, f.root+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(f.root, 0700); err != nil {
					t.Fatal(err)
				}
			case "ledger":
				wire, err := json.Marshal(syntheticDNSLedger{Schema: 1, Owner: syntheticDNSLedgerOwner})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.root, syntheticDNSLedgerName), wire, 0600); err != nil {
					t.Fatal(err)
				}
			case "memory-coordinates":
				s.ledger.Reservations[m.index].RealIPv4 = f.client
			case "close-not-joined":
				originalDone := s.closeDone
				t.Cleanup(func() { s.closeDone = originalDone })
				s.closeDone = make(chan struct{})
			case "control-closed":
				_ = f.control.Close()
			}
			if _, err := r.ClosedObservation(ctx); err == nil {
				t.Fatal("altered original admitted")
			}
		})
	}
}

func TestSyntheticDNSRetirementCannotIssueFromDTOOrAfterClose(t *testing.T) {
	f, s, m, _, held, _ := syntheticDNSRetirementModel(t)
	if _, err := new(SyntheticDNSMapping).ReviewRetirement(held, f.r.defaultDNS.manager, f.r.frozenPlan, f.control, f.root, f.definition); err == nil {
		t.Fatal("DTO issued retirement")
	}
	if _, err := m.ReviewRetirement(held, new(Manager), f.r.frozenPlan, f.control, f.root, f.definition); err == nil {
		t.Fatal("different manager issued retirement")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReviewRetirement(held, f.r.defaultDNS.manager, f.r.frozenPlan, f.control, f.root, f.definition); err == nil {
		t.Fatal("closed source issued retirement")
	}
}
