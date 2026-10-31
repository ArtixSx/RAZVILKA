package strategylab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func privateFixture(t *testing.T, state State) (*Manager, PrivateSnapshot) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "strategy-lab.json")
	data, err := json.MarshalIndent(state, "", " \t")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n', '\n')
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	in, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil || in == nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.Content, data) {
		t.Fatal("archive did not retain exact bytes")
	}
	return m, *in
}

func TestPrivateRestoreRetiresAuthorityPreservesHistoryAndRollback(t *testing.T) {
	ctx := context.Background()
	state := emptyState()
	state.Candidates["candidate"] = Candidate{ID: "candidate", Incarnation: "incarnation", Validation: Validation{OK: true, Native: true, Generation: "generation"}}
	state.Evidence = []Evidence{{CandidateID: "candidate", CandidateIncarnation: "incarnation", ValidationGeneration: "generation", Success: true}}
	state.Selections["manual"] = Selection{CandidateID: "candidate", Mode: "manual", Frozen: true}
	_, archive := privateFixture(t, state)
	destination, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := destination.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := target.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after, err := target.RestoreImage(ctx, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(ctx, before, after); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(destination.Path)
	if err != nil {
		t.Fatal(err)
	}
	c := reopened.state.Candidates["candidate"]
	if c.Validation.OK || c.Validation.Native || c.Validation.Generation != "generation" || c.Incarnation != "incarnation" {
		t.Fatal("restored authority/bindings changed", c)
	}
	if !reopened.state.Selections["manual"].Frozen || !reopened.state.Evidence[0].Success || reopened.state.Evidence[0].ValidationGeneration != "generation" {
		t.Fatal("history or intent lost")
	}
	if evidenceSourceCurrent(c) {
		t.Fatal("restored PASS became current")
	}
	target, err = reopened.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(ctx, after, before); err != nil {
		t.Fatal("rollback failed", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened.image.Exists {
		t.Fatal("rollback did not preserve absence")
	}
}

func TestPrivateRestoreUnknownFenceAndConflicts(t *testing.T) {
	ctx := context.Background()
	state := emptyState()
	state.SchemaVersion = compatibilityUnknownSchema
	_, archive := privateFixture(t, state)
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := m.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := target.Read(ctx)
	after, err := target.RestoreImage(ctx, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(ctx, before, after); err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(ctx, before, after); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("stale CAS accepted", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if !m.Snapshot().QuiescenceUnknown {
		t.Fatal("unknown cleared")
	}
	target, err = m.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.RestoreImage(ctx, archive); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("unknown destination overwritten", err)
	}
	target.Close()
}

func TestPrivateSnapshotRejectsCorruptionAndPreservesPayloadBytes(t *testing.T) {
	_, in := privateFixture(t, emptyState())
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PrivateSnapshot
	if json.Unmarshal(encoded, &decoded) != nil || !bytes.Equal(decoded.Content, in.Content) || ValidatePrivateSnapshot(decoded) != nil {
		t.Fatal("JSON round trip changed archive")
	}
	in.Content = append(in.Content, 'x')
	if ValidatePrivateSnapshot(in) == nil {
		t.Fatal("corruption accepted")
	}
	for _, raw := range []string{`{"schema_version":99}`, `{"schema_version":4,"schema_version":4}`, `{"schema_version":4,"unknown":true}`, `{"schema_version":4} {}`} {
		h := sha256.Sum256([]byte(raw))
		if ValidatePrivateSnapshot(PrivateSnapshot{Schema: 1, Content: []byte(raw), SHA256: hex.EncodeToString(h[:])}) == nil {
			t.Fatal("invalid state accepted", raw)
		}
	}
}

func TestPrivateSnapshotSupervisedArchiveCannotReplayOwnership(t *testing.T) {
	state := emptyState()
	session := compatibilityRecordFixture(t)
	state.SchemaVersion, state.CompatibilitySession, state.CompatibilityFinalizing = compatibilitySupervisedSchema, &session, true
	_, archive := privateFixture(t, state)
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	target, err := m.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := target.RestoreImage(context.Background(), archive); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("native ownership replayed", err)
	}
}

func TestPrivateSnapshotRejectsUnrepresentedMemoryFences(t *testing.T) {
	for _, kind := range []string{"running", "write-blocked", "memory-unknown"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := privateFixture(t, emptyState())
			switch kind {
			case "running":
				m.nativeRunning = true
			case "write-blocked":
				m.writeBlocked = true
			case "memory-unknown":
				m.compatibilityUnknown = true
			}
			if _, err := m.ExportPrivateIfPresent(context.Background()); err == nil {
				t.Fatal("memory fence omitted from archive")
			}
		})
	}
}

func TestPrivatePairReviewPreservesSettledSupervisedSessionWithoutAdoption(t *testing.T) {
	for _, version := range []int{3, 5, 7} {
		state := emptyState()
		state.SchemaVersion = version
		session := compatibilityRecordFixture(t)
		compatibilityRecordReceipt(session.DryRun, "reaped", true, 1)
		state.CompatibilitySession = &session
		_, in := privateFixture(t, state)
		before := bytes.Clone(in.Content)
		if schema, err := ReviewPrivatePairSnapshot(in); err != nil || schema != version {
			t.Fatal("acknowledged terminal data rejected", schema, err)
		}
		if !bytes.Equal(in.Content, before) {
			t.Fatal("pair review rewrote session or generation")
		}
		for _, kind := range []string{"unacknowledged", "unknown", "finalizing", "candidate-unknown"} {
			copy := state
			copiedSession := compatibilityRecordClone(t, session)
			copy.CompatibilitySession = &copiedSession
			switch kind {
			case "unacknowledged":
				copy.CompatibilitySession.DryRun.Acknowledged = false
			case "unknown":
				copy.CompatibilitySession.Unknown = true
			case "finalizing":
				copy.CompatibilityFinalizing = true
			case "candidate-unknown":
				copy.Candidates = map[string]Candidate{"candidate": {Validation: Validation{QuiescenceUnknown: true}}}
			}
			_, bad := privateFixture(t, copy)
			if _, err := ReviewPrivatePairSnapshot(bad); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
				t.Fatal(kind, err)
			}
		}
	}
	unknown := emptyState()
	unknown.SchemaVersion = compatibilityUnknownSchema
	_, in := privateFixture(t, unknown)
	if _, err := ReviewPrivatePairSnapshot(in); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("schema2 unknown became pair-ready", err)
	}
}
