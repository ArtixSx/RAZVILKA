package dataplane

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestNFQWSActiveMaterialRejectsDTOAndZeroOriginalOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m := New(t.TempDir())
	adapter := NewNFQWS2Adapter()
	if err := m.Register(adapter); err != nil {
		t.Fatal(err)
	}
	for _, current := range []context.Context{ctx, context.Background(), nil} {
		got, err := ReviewManagedNFQWSActiveMaterial(current, m, adapter, &strategylab.SelectedCandidateReview{}, &components.ManagedNFQWSRuntimeLease{}, &operationgate.ControlEpochReview{}, "unreviewed-control", netidentity.NewProcProvider(), 40321)
		if got != nil || err == nil || adapter.activeProcess != nil {
			t.Fatal("metadata/zero owners constructed actual ACTIVE material")
		}
	}
	var zero NFQWSActiveMaterial
	if zero.Current(ctx) == nil || zero.Close() == nil {
		t.Fatal("zero material accepted")
	}
	if got, err := zero.ReviewScope(ctx, strategylab.SelectedCandidateReference{}, Plan{}, nil); got != nil || err == nil {
		t.Fatal("zero material issued scoped source consumer")
	}
	// Explicit private identity model only; Current still refuses because it
	// has none of the concrete owners. A copy cannot even close the original.
	original := &NFQWSActiveMaterial{}
	original.self = original
	var copy NFQWSActiveMaterial
	reflect.ValueOf(&copy).Elem().Set(reflect.ValueOf(original).Elem())
	if copy.Current(ctx) == nil || copy.Close() == nil || original.closed {
		t.Fatal("copied material accepted or retired original")
	}
	if err := original.Close(); err != nil || original.Current(ctx) == nil {
		t.Fatal("closed material kept reader authority", err)
	}
}
