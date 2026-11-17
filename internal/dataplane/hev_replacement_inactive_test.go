package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"testing"
)

func TestHEVReplacementInactivityRejectsManufacturedAndForeignReviews(t *testing.T) {
	m := New(t.TempDir())
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*components.HEVReplacementReview{nil, {}} {
		if m.VerifyHEVReplacementInactive(context.Background(), a, r) == nil {
			t.Fatal("manufactured review granted inactivity")
		}
	}
	foreign := NewMihomoProbeAdapter(a.components, netidentity.NewProcProvider())
	if m.VerifyHEVReplacementInactive(context.Background(), foreign, &components.HEVReplacementReview{}) == nil {
		t.Fatal("unregistered owner")
	}
}
func TestHEVReplacementObservationPreservesEveryRegisteredOwner(t *testing.T) {
	m := New(t.TempDir())
	a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
	foreign := &networkPolicyInactiveObserver{fakeAdapter: &fakeAdapter{id: "foreign-owner"}, observe: func(context.Context) error { return errors.New("still active") }}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(foreign); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), hevReplacementObservationKey{}, hevReplacementObservation{a, &components.HEVReplacementReview{}})
	if err := m.VerifyRuntimeInactive(ctx); !errors.Is(err, ErrRuntimeInactivity) || foreign.calls != 1 {
		t.Fatal("registry observer skipped", err, foreign.calls)
	}
	if len(foreign.fakeAdapter.calls) != 0 {
		t.Fatal("observation performed effects")
	}
	both := context.WithValue(ctx, mihomoReplacementObservationKey{}, mihomoReplacementObservation{a, &components.MihomoReplacementReview{}})
	if _, err := a.hevReplacementObservation(both); err == nil {
		t.Fatal("mixed writer observations accepted")
	}
}
