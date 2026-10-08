package strategylab

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Source predicate models only. These tests never issue an installer/runtime
// permission from an empty state, modeled receipt or interface marker.
func TestManagedCompatibilityInactiveRefusesUnknownHistoricalAndProbeOwners(t *testing.T) {
	for _, change := range []string{"running", "unknown", "blocked", "probe", "historical", "legacy-native"} {
		t.Run(change, func(t *testing.T) {
			m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := m.AddCandidate("tcp-tls", "initial expert", "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", "expert")
			if err != nil {
				t.Fatal(err)
			}
			m.Executor = nil
			m.mu.Lock()
			if _, _, err := managedCompatibilityInactiveStateLocked(m, nil); err != nil {
				t.Fatal("initial saved-source model", err)
			}
			switch change {
			case "running":
				m.nativeRunning = true
			case "unknown":
				m.compatibilityUnknown = true
			case "blocked":
				m.writeBlocked = true
			case "probe":
				m.Executor = &SystemProbeExecutor{}
			case "historical":
				session := compatibilityRecordFixture(t)
				m.state.SchemaVersion, m.state.CompatibilitySession = compatibilitySupervisedSchema, &session
			case "legacy-native":
				candidate.Validation.Native = true
				m.state.Candidates[candidate.ID] = candidate
			}
			_, _, err = managedCompatibilityInactiveStateLocked(m, nil)
			m.mu.Unlock()
			if err == nil {
				t.Fatal("unproved model owner admitted inactivity", change)
			}
		})
	}
}

func TestManagedCompatibilityInactivePublicReviewRefusesMissingOwnersWithoutWrite(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddCandidate("tcp-tls", "existing expert", "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", "expert"); err != nil {
		t.Fatal(err)
	}
	m.Executor = nil
	before := compatibilityStoreBytes(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, control := range []*operationgate.ControlEpochReview{nil, {}} {
		if review, err := m.ReviewManagedCompatibilityInactive(ctx, control); err == nil || review != nil {
			t.Fatal("declared/zero control issued public inactive review")
		}
	}
	r := &ManagedCompatibilityInactiveReview{manager: m}
	r.self = r
	copy := &ManagedCompatibilityInactiveReview{self: r, manager: m}
	for _, invalid := range []*ManagedCompatibilityInactiveReview{nil, {}, copy, r} {
		if !errors.Is(invalid.Current(ctx), ErrCompatibilityQuiescenceUnknown) {
			t.Fatal("unowned inactive handle observed actual source")
		}
	}
	if copy.Close() == nil || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
		t.Fatal("copied review closed original or any refusal changed source")
	}
}
