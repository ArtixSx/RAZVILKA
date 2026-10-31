package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// This fixture models an acknowledged terminal failed dry-run, not a live
// process or native capability. Actual filesystem pair/snapshot preservation
// and refusal of incompatible controllers are exercised below.
func TestStrategyPairPreservesSettledSupervisedHistory(t *testing.T) {
	a, u, review, _ := strategyPairFixture(t)
	raw, err := os.ReadFile("testdata/strategy-pair-modeled-settled5.json")
	if err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
	ctx := context.Background()
	if _, err := a.sealStrategyPair(ctx, review); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("reader5 standalone schema support became paired snapshot support", err)
	}
	a.strategyProbe = func(_ context.Context, _ selfupdatejournal.BinaryImage, flag string) (string, error) {
		if flag == "-strategy-lab-read-version" {
			return "7\n", nil
		}
		return "3\n", nil
	}
	proof, err := a.sealStrategyPair(ctx, review)
	if err != nil || proof.StateSchema != 5 {
		t.Fatal("settled history rejected", err)
	}
	review.StrategyPair = proof
	publishStrategyReview(t, a, u, review)
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	image, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || !bytes.Equal(image.Images["strategy"].Data, raw) {
		t.Fatal("history changed in snapshot", err)
	}
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" {
			candidate, err := os.ReadFile(file.Candidate)
			if err != nil {
				t.Fatal(err)
			}
			retainedFile(t, a.installation, "bin/razvilka", candidate)
		}
	}
	for _, action := range []string{"start/live", "replace-to-rollback"} {
		if err := a.AuthorityAction(ctx, review.ID, review.Revision, action); err != nil {
			t.Fatal(action, err)
		}
	}
	// The complete session cannot be read by a pre-supervision controller.
	a.strategyProbe = func(_ context.Context, _ selfupdatejournal.BinaryImage, flag string) (string, error) {
		if flag == "-strategy-lab-read-version" {
			return "5\n", nil
		}
		return "3\n", nil
	}
	if _, err := a.sealStrategyPair(ctx, review); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("incompatible reader accepted", err)
	}
	for _, mutation := range [][]byte{
		bytes.Replace(raw, []byte(`"acknowledged": true`), []byte(`"acknowledged": false`), 1),
		bytes.Replace(raw, []byte(`"schema_version": 5`), []byte(`"schema_version": 5,"compatibility_finalizing":true`), 1),
	} {
		if bytes.Equal(mutation, raw) {
			t.Fatal("fixture mutation did not exercise its fence")
		}
		retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", mutation)
		if err := a.AuthorityAction(ctx, review.ID, review.Revision, "replace-to-rollback"); !errors.Is(err, ErrStrategyStateAdmission) {
			t.Fatal("unknown/finalizing admitted", err)
		}
	}
}
