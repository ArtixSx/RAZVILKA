package strategylab

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelectedCandidateManagedOwnersCannotBeReconstructed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, source := range []*SelectedCandidateReview{nil, {}} {
		for _, owners := range []struct {
			runtime *components.ManagedNFQWSRuntimeLease
			control *operationgate.ControlEpochReview
		}{{}, {runtime: &components.ManagedNFQWSRuntimeLease{}, control: &operationgate.ControlEpochReview{}}} {
			if source.ManagedOwnersCurrent(ctx, owners.runtime, owners.control) == nil {
				t.Fatal("zero/copied detached owners replaced actual managed source")
			}
		}
	}
}
