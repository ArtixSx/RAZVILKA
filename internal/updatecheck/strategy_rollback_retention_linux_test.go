//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/strategylab"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Data/compatibility fixture only. The native copied-controller test separately
// mints retention from actual H/S/C/R/Wait provenance. These files grant no
// process, kernel, live validation or service health authority.
func strategyRetentionFixture(t *testing.T) (*SelfUpdateFileAdapter, fileReview, []byte, []byte, strategyRollbackRetention) {
	t.Helper()
	ctx := context.Background()
	a, u, review, prior := strategyPairFixture(t)
	a.strategyProbe = func(_ context.Context, _ selfupdatejournal.BinaryImage, flag string) (string, error) {
		if flag == "-strategy-lab-read-version" {
			return "7\n", nil
		}
		return "4\n", nil
	}
	pair, err := a.sealStrategyPair(ctx, review)
	if err != nil {
		t.Fatal(err)
	}
	review.StrategyPair = pair
	publishStrategyReview(t, a, u, review)
	store, err := a.OpenFileJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	okay := func(context.Context) error { return nil }
	if err := store.Prepare(ctx, review.ID, review.Files, okay, okay); err != nil {
		t.Fatal(err)
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "123", ExecutableSHA256: review.OldExecutableSHA256, Inode: 5}
	receipt := func(command string) fileCommandReceipt {
		r := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: command, State: "reaped", Parent: p, Supervisor: p, WaitECHILD: true}
		if command != "prepare-private-state" {
			r.DirectPID, r.Reaped = 22, 2
		}
		return r
	}
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := store.Execute(ctx, review.ID, command, okay, func(context.Context) error {
			if command == "prepare-private-state" {
				if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
					return err
				}
			}
			return writeFileCommand(root, receipt(command))
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Install(ctx, review.ID, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := store.Execute(ctx, review.ID, "start-candidate-panel", okay, func(context.Context) error { return writeFileCommand(root, receipt("start-candidate-panel")) }); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(a.installation, "razvilka/state/strategy-lab.json")
	manager, err := strategylab.New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddCandidate("tcp-tls", "recent manual history", "--filter-tcp=443", "expert"); err != nil {
		t.Fatal(err)
	}
	recent, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var intent selfupdatejournal.Receipt
	if err := store.Execute(ctx, review.ID, "stop-candidate-panel", okay, func(context.Context) error {
		var present bool
		intent, present, err = store.Current()
		if err != nil || !present {
			return ErrFileProtocol
		}
		return writeFileCommand(root, receipt("stop-candidate-panel"))
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := root.ReadLimited("private-snapshot.json", 6<<20)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := a.loadHeader(ctx, review.ID)
	if err != nil {
		t.Fatal(err)
	}
	proof := strategyRollbackRetention{Schema: 1, ID: review.ID, ReviewSHA256: record.FileReviewSHA256, SnapshotSHA256: digestBytes(snapshot), OriginalStateSHA256: pair.StateSHA256, StateSchema: 4, Current: restorejournal.Image{Exists: true, Data: recent}, Controllers: pair.Controllers, StopIntent: intent, CandidateFinal: receipt("start-candidate-panel")}
	raw, err := strategyRetentionBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, raw)
	return a, review, prior, recent, proof
}

func TestStrategyRollbackRetentionSavedCandidateProfileCannotReviveManagedHealth(t *testing.T) {
	a, review, _, _, proof := strategyRetentionFixture(t)
	record := strategylab.ManagedProbeEpochRecord{Scope: "router-output-https-tcp443-ipv4", PinnedAddress: "1.1.1.1", ID: strings.Repeat("1", 32), ServiceID: "service", CandidateID: "candidate", Incarnation: strings.Repeat("2", 32), ValidationGeneration: strings.Repeat("3", 32), NetworkID: "wan-candidate-profile", PolicyDigest: strings.Repeat("a", 64), RuntimeDigest: strings.Repeat("b", 64), CriteriaDigest: strings.Repeat("c", 64)}
	state := strategylab.State{SchemaVersion: 6, Candidates: map[string]strategylab.Candidate{"candidate": {ID: "candidate", Incarnation: record.Incarnation, PoolID: "tcp-tls", Name: "candidate profile history", Arguments: "--filter-tcp=443", Origin: "expert", Validation: strategylab.Validation{OK: true, Native: true, Generation: record.ValidationGeneration}}}, Selections: map[string]strategylab.Selection{"service|tcp|ipv4": {ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", CandidateID: "candidate", Frozen: true, Healthy: true, Status: "healthy"}}, ManagedProbeEpochs: map[string]strategylab.ManagedProbeEpochRecord{"service|tcp|ipv4|candidate": record}}
	for i := 0; i < strategylab.RequiredPasses; i++ {
		state.Evidence = append(state.Evidence, strategylab.Evidence{CandidateID: "candidate", CandidateIncarnation: record.Incarnation, ValidationGeneration: record.ValidationGeneration, ServiceID: "service", Protocol: "tcp", IPFamily: "ipv4", ManagedEpoch: record.ID, Success: true, RouteConfirmed: true, Stages: []strategylab.StageEvidence{{Stage: "read", Status: "pass"}}, CheckedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)})
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinaryStrategyImage(restorejournal.Image{Exists: true, Data: raw}); err != nil {
		t.Fatal("strong settled data fixture invalid", err)
	}
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
	proof.StateSchema, proof.Current = 6, restorejournal.Image{Exists: true, Data: raw}
	body, _ := strategyRetentionBytes(proof)
	retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, body)
	retainedFile(t, a.installation, "razvilka/state/staging/candidate-profile", []byte("candidate engine profile"))
	if err := a.restorePrivateSnapshot(context.Background(), review.ID); err != nil {
		t.Fatal(err)
	}
	manager, err := strategylab.New(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	view := manager.SnapshotWithContext(context.Background())
	if len(view.Evidence) != strategylab.RequiredPasses || len(view.Selections) != 1 || !view.Selections[0].Frozen || view.Selections[0].Healthy || len(view.Summaries) != 1 || view.Summaries[0].Eligible || view.Summaries[0].FreshPasses != 0 {
		t.Fatal("profile rollback/restart revived disk-only managed health", view)
	}
	if _, err := os.Stat(filepath.Join(a.installation, "razvilka/state/staging/candidate-profile")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate profile was not rolled back", err)
	}
	after, err := os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("retirement rewrote immutable history instead of requiring a fresh owner", err)
	}
}

func TestStrategyRollbackRetentionPreservesRecentHistoryAndImmutableSnapshot(t *testing.T) {
	a, review, prior, recent, _ := strategyRetentionFixture(t)
	ctx := context.Background()
	retainedFile(t, a.installation, "etc/razvilka/admin.token", []byte("candidate token"))
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("exact compatible current image rejected", err)
	}
	if err := a.restorePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal("recent-state retention rollback", err)
	}
	cold := *a
	if err := cold.restorePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal("cold known CAS retry", err)
	}
	got, err := os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil || !bytes.Equal(got, recent) {
		t.Fatal("rollback discarded recent manual history", err)
	}
	snapshot, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || !bytes.Equal(snapshot.Images["strategy"].Data, prior) {
		t.Fatal("retention rewrote original snapshot3", err)
	}
	if _, err := os.Stat(filepath.Join(a.installation, "etc/razvilka/admin.token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("other private target not restored", err)
	}
}

func TestStrategyRollbackRetentionRefusesDriftAndOlderReader(t *testing.T) {
	for _, change := range []string{"current-bytes", "restore-old-history", "record-digest", "duplicate-field", "source-final", "reader3", "unknown-state", "finalizing-state"} {
		t.Run(change, func(t *testing.T) {
			a, review, prior, recent, proof := strategyRetentionFixture(t)
			path := filepath.Join(a.installation, "razvilka/state/strategy-lab.json")
			switch change {
			case "current-bytes":
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", append(bytes.Clone(recent), '\n'))
			case "restore-old-history":
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", prior)
			case "record-digest":
				raw, _ := strategyRetentionBytes(proof)
				raw = append(raw, '\n')
				retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, raw)
			case "duplicate-field":
				raw, _ := strategyRetentionBytes(proof)
				raw = bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
				retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, raw)
			case "source-final":
				proof.CandidateFinal.Reaped++
				raw, _ := strategyRetentionBytes(proof)
				retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, raw)
			case "reader3":
				proof.Controllers = append([]strategyControllerProof(nil), proof.Controllers...)
				proof.Controllers[0].SnapshotReader = 3
				raw, _ := strategyRetentionBytes(proof)
				retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, raw)
			case "unknown-state":
				var state map[string]any
				if err := json.Unmarshal(recent, &state); err != nil {
					t.Fatal(err)
				}
				state["schema_version"] = 2
				raw, _ := json.Marshal(state)
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
			case "finalizing-state":
				var state map[string]any
				if err := json.Unmarshal(recent, &state); err != nil {
					t.Fatal(err)
				}
				state["compatibility_finalizing"] = true
				raw, _ := json.Marshal(state)
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
			}
			before, _ := os.ReadFile(path)
			if err := a.AuthorityAction(context.Background(), review.ID, review.Revision, "replace-to-rollback"); err == nil {
				t.Fatal("invalid preservation pair admitted")
			}
			if err := a.restorePrivateSnapshot(context.Background(), review.ID); err == nil {
				t.Fatal("invalid current image automatically rewound")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed retained history")
			}
		})
	}
}

func TestStrategyRollbackRetentionRequiresReader4WithoutBreakingSnapshot3(t *testing.T) {
	a, u, review, prior := strategyPairFixture(t)
	ctx := context.Background()
	a.strategyProbe = func(_ context.Context, _ selfupdatejournal.BinaryImage, flag string) (string, error) {
		if flag == "-strategy-lab-read-version" {
			return "7\n", nil
		}
		return "3\n", nil
	}
	pair, err := a.sealStrategyPair(ctx, review)
	if err != nil {
		t.Fatal("legacy unchanged reader3 pair refused", err)
	}
	review.StrategyPair = pair
	publishStrategyReview(t, a, u, review)
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); err != nil {
		t.Fatal("unchanged reader3 contract regressed", err)
	}
	if retentionReaders(pair, 4) {
		t.Fatal("state reader7 alone fabricated changed-state retention support")
	}
	manager, err := strategylab.New(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddCandidate("tcp-tls", "new history unsupported by old snapshot controller", "--filter-tcp=443", "expert"); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("legacy snapshot3 rewound changed state", err)
	}
	snapshot, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || !bytes.Equal(snapshot.Images["strategy"].Data, prior) {
		t.Fatal("legacy preimage rewritten", err)
	}
}
