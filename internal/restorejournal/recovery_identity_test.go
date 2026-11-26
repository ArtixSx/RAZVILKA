package restorejournal

import (
	"context"
	"strings"
	"testing"
)

func TestRecoveryIdentitySnapshotsActualOriginalJournalWithoutTargetEffects(t *testing.T) {
	j, _, _, targets := fixture(t)
	ctx := context.Background()
	initial, pending, err := j.RecoveryIdentity(ctx)
	if err != nil || pending || len(initial) != 64 {
		t.Fatal(initial, pending, err)
	}
	again, _, err := j.RecoveryIdentity(ctx)
	if err != nil || again != initial {
		t.Fatal("identity read initialized metadata", err)
	}
	doc := document{Kind: journalKind, Schema: 1, Scope: testScope, ID: strings.Repeat("a", 32), State: "prepared", Records: []record{{Target: "a", Before: content("old-a"), After: content("new-a")}}}
	if err := j.save(doc); err != nil {
		t.Fatal(err)
	}
	prepared, pending, err := j.RecoveryIdentity(ctx)
	if err != nil || !pending || prepared == initial {
		t.Fatal("prepared identity lost", pending, err)
	}
	doc.ID = strings.Repeat("b", 32)
	if err := j.save(doc); err != nil {
		t.Fatal(err)
	}
	replacement, pending, err := j.RecoveryIdentity(ctx)
	if err != nil || !pending || replacement == prepared {
		t.Fatal("new transaction revived stale review", err)
	}
	for _, target := range targets {
		if target.writes != 0 {
			t.Fatal("review touched a target")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if identity, _, err := j.RecoveryIdentity(canceled); err == nil || identity != "" {
		t.Fatal("canceled review returned authority", identity, err)
	}
}
