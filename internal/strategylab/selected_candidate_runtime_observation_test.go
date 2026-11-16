package strategylab

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

func TestSelectedCandidateRuntimeObservationCannotReplaceOriginalLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := &SelectedCandidateReview{runtime: &components.ManagedNFQWSRuntimeLease{}}
	if err := r.materialRuntimeCompare(ctx, &components.ManagedNFQWSRuntimeRead{}); err == nil {
		t.Fatal("empty read view minted runtime identity")
	}
	if err := r.materialRuntimeCompare(ctx, nil); err == nil {
		t.Fatal("original invalid lease became valid")
	}
	for _, canary := range []bool{false, true} {
		r.canary = canary
		if err := r.materialReadCurrentLocked(ctx); err == nil {
			t.Fatal("unowned canary bypassed original body")
		}
	}
}
