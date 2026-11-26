package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoReplacementInactivityRejectsManufacturedAndForeignReviews(t *testing.T) {
	m := New(t.TempDir())
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	for _, review := range []*components.MihomoReplacementReview{nil, {}} {
		if m.VerifyMihomoReplacementInactive(context.Background(), a, review) == nil {
			t.Fatal("manufactured replacement comparison granted inactivity")
		}
	}
	foreign := NewMihomoProbeAdapter(a.components, netidentity.NewProcProvider())
	if m.VerifyMihomoReplacementInactive(context.Background(), foreign, &components.MihomoReplacementReview{}) == nil {
		t.Fatal("unregistered adapter accepted")
	}
}

func TestMihomoReplacementObservationNeverExemptsAnotherRegisteredOwner(t *testing.T) {
	m := New(t.TempDir())
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	foreign := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "foreign-owner"}, observe: func(context.Context) error { return errors.New("foreign owner still active") }}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(foreign); err != nil {
		t.Fatal(err)
	}
	// The private comparison binding is not a general permission. Even a
	// malformed review cannot bypass the other original registry observers.
	ctx := context.WithValue(context.Background(), mihomoReplacementObservationKey{}, mihomoReplacementObservation{a, &components.MihomoReplacementReview{}})
	if err := m.VerifyRuntimeInactive(ctx); !errors.Is(err, ErrRuntimeInactivity) || foreign.calls != 1 {
		t.Fatal("foreign registered owner skipped", err, foreign.calls)
	}
	if len(foreign.fakeAdapter.calls) != 0 {
		t.Fatal("read-only observation performed lifecycle effects")
	}
}
