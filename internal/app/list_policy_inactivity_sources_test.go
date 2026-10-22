package app

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type managedListSourceModel struct {
	provider  *netidentity.Provider
	inventory *dataplane.BackendInventory
	closed    bool
	checks    int
}

func (r *managedListSourceModel) CheckCurrent(context.Context) error {
	r.checks++
	if r.closed {
		return dataplane.ErrRuntimeInactivity
	}
	return nil
}
func (r *managedListSourceModel) Sources(ctx context.Context) (*netidentity.Provider, *dataplane.BackendInventory, error) {
	return r.provider, r.inventory, r.CheckCurrent(ctx)
}

func TestManagedListStartupReusesOriginalInactivitySourceWithoutSecondBind(t *testing.T) {
	ctx := context.Background()
	r := &managedListSourceModel{provider: netidentity.NewProcProvider(), inventory: &dataplane.BackendInventory{}}
	lookups, created, bound := 0, 0, 0
	lookup := func() (managedListInactivitySources, error) { lookups++; return r, nil }
	source, provider, inventory, err := selectManagedListInactivitySources(ctx, lookup, func(context.Context) (*netidentity.Provider, error) { created++; return nil, errors.New("replacement") })
	if err != nil || source != r || provider != r.provider || inventory != r.inventory {
		t.Fatal("startup replaced original observation objects", err)
	}
	retained, err := retainManagedListInactivitySources(ctx, source, func() error { bound++; return errors.New("second binding") }, lookup)
	if err != nil || retained != r || lookups != 1 || created != 0 || bound != 0 || r.checks != 2 {
		t.Fatal("startup performed a second binding or omitted original currentness", err)
	}
	r.closed = true
	if _, err := retainManagedListInactivitySources(ctx, source, func() error { bound++; return nil }, lookup); !errors.Is(err, dataplane.ErrRuntimeInactivity) || bound != 0 {
		t.Fatal("closed original source was rebound", err)
	}
}

func TestManagedListStartupOnlyTypedMissingSourcesPermitFirstBinding(t *testing.T) {
	for _, failure := range []error{dataplane.ErrRuntimeInactivity, context.Canceled, errors.New("changed source"), dataplane.ErrRuntimeInactivitySourcesMissing} {
		created := 0
		_, _, _, err := selectManagedListInactivitySources(context.Background(), func() (managedListInactivitySources, error) { return nil, failure }, func(context.Context) (*netidentity.Provider, error) {
			created++
			return netidentity.NewProcProvider(), nil
		})
		if errors.Is(failure, dataplane.ErrRuntimeInactivitySourcesMissing) {
			if err != nil || created != 1 {
				t.Fatal("first startup was refused", err)
			}
		} else if err == nil || created != 0 {
			t.Fatal("unknown/closed source caused replacement", failure)
		}
	}
	r := &managedListSourceModel{provider: netidentity.NewProcProvider(), inventory: &dataplane.BackendInventory{}}
	bound := 0
	actual, err := retainManagedListInactivitySources(context.Background(), nil, func() error { bound++; return nil }, func() (managedListInactivitySources, error) { return r, nil })
	if err != nil || actual != r || bound != 1 || r.checks != 1 {
		t.Fatal("initial binding was not joined to its actual owner", err)
	}
}
