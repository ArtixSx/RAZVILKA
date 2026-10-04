package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

func namedWGReviewedFixture(t *testing.T) (*WARPWireGuardAdapter, *warpFakeRunner, Plan, string, *wireguardprofile.Store, string) {
	t.Helper()
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	store := wireguardprofile.New(filepath.Join(t.TempDir(), "profiles"))
	meta, err := store.Put(context.Background(), "reviewed", "Reviewed", testOwnWireGuardProfile(""), "")
	if err != nil {
		t.Fatal(err)
	}
	a.Profiles, a.Configs = store, nil
	plan.Routes[0].Resolved, plan.Routes[0].Selected = "wireguard:reviewed", "wireguard:reviewed"
	plan.Routes[0].WireGuardProfileRevision = meta.Revision
	return a, r, plan, root, store, meta.Revision
}

func TestNamedWGReviewedRevisionIsRequiredBeforeSnapshot(t *testing.T) {
	for _, cut := range []string{"missing", "uppercase", "wrong", "selected-conflict", "two-revisions"} {
		t.Run(cut, func(t *testing.T) {
			a, r, plan, root, _, rev := namedWGReviewedFixture(t)
			switch cut {
			case "missing":
				plan.Routes[0].WireGuardProfileRevision = ""
			case "uppercase":
				plan.Routes[0].WireGuardProfileRevision = strings.ToUpper(rev)
			case "wrong":
				plan.Routes[0].WireGuardProfileRevision = strings.Repeat("a", 64)
			case "selected-conflict":
				plan.Routes[0].Selected = "wireguard:other"
			case "two-revisions":
				other := plan.Routes[0]
				other.WireGuardProfileRevision = strings.Repeat("b", 64)
				plan.Routes = append(plan.Routes, other)
			}
			if err := a.Snapshot(context.Background(), plan, root); !errors.Is(err, ErrWireGuardProfileRevision) {
				t.Fatal("unbound revision admitted", cut, err)
			}
			assertWGCanaryNoMutations(t, r.calls, root)
		})
	}
}

func TestNamedWGProfileChangeFencesEveryForwardLifecycleBoundary(t *testing.T) {
	for _, phase := range []string{"snapshot", "stage", "validate", "canary", "activate", "health", "commit", "reconcile", "refresh"} {
		t.Run(phase, func(t *testing.T) {
			a, r, plan, root, store, rev := namedWGReviewedFixture(t)
			ctx := context.Background()
			if phase != "snapshot" {
				if err := a.Snapshot(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
				if phase != "stage" {
					if err := a.Stage(ctx, plan, root); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := store.Put(ctx, "reviewed", "Changed", testOwnWireGuardProfile(""), rev); err != nil {
				t.Fatal(err)
			}
			r.calls = nil
			var err error
			switch phase {
			case "snapshot":
				err = a.Snapshot(ctx, plan, root)
			case "stage":
				err = a.Stage(ctx, plan, root)
			case "validate":
				err = a.Validate(ctx, plan, root)
			case "canary":
				err = a.Canary(ctx, plan.RoutePlanFor(a.ID()), root)
			case "activate":
				err = a.Activate(ctx, plan, root)
			case "health":
				err = a.Health(ctx, plan, root)
			case "commit":
				err = a.Commit(ctx, plan, root)
			case "reconcile":
				err = a.Reconcile(ctx, plan)
			case "refresh":
				_, err = a.RefreshPolicy(ctx, plan)
			}
			if !errors.Is(err, ErrWireGuardProfileRevision) {
				t.Fatal("stale named profile crossed phase", phase, err)
			}
			assertWGCanaryNoMutations(t, r.calls, root)
		})
	}
}

type namedWGChangeRunner struct {
	base   NFQWS2Runner
	change func()
}

func (r *namedWGChangeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := r.base.Run(ctx, name, args...)
	if r.change != nil {
		change := r.change
		r.change = nil
		change()
	}
	return out, err
}

func TestNamedWGProfileChangeDuringCommandStopsBeforeNextEffect(t *testing.T) {
	a, r, plan, root, store, rev := namedWGReviewedFixture(t)
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	a.Runner = &namedWGChangeRunner{base: r, change: func() {
		if _, err := store.Put(ctx, "reviewed", "Changed in command", testOwnWireGuardProfile(""), rev); err != nil {
			t.Fatal(err)
		}
	}}
	if err := a.Stage(ctx, plan, root); !errors.Is(err, ErrWireGuardProfileRevision) {
		t.Fatal("changed catalog crossed command readback", err)
	}
	assertWGCanaryNoMutations(t, r.calls, root)
}

func TestNamedWGClosingGuardRejectsSuccessfulProbeAfterCatalogChange(t *testing.T) {
	a, r, plan, root, store, rev := namedWGReviewedFixture(t)
	ctx := context.Background()
	if err := a.Snapshot(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(ctx, plan, root); err != nil {
		t.Fatal(err)
	}
	a.CanaryProbe = func(context.Context, string, string) error {
		if _, err := store.Put(ctx, "reviewed", "Changed in probe", testOwnWireGuardProfile(""), rev); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if err := a.Canary(ctx, plan.RoutePlanFor(a.ID()), root); !errors.Is(err, ErrWireGuardProfileRevision) {
		t.Fatal("old revision was reported checked", err)
	}
	if r.active || len(r.policy.entries) != 0 || len(r.policy.defaults) != 0 {
		t.Fatal("catalog change prevented owned candidate cleanup")
	}
}

func TestNamedWGCommandGuardKeepsFrozenRoutesAndCleanupAuthority(t *testing.T) {
	a, r, plan, _, store, rev := namedWGReviewedFixture(t)
	type unrelatedAuthorityKey struct{}
	ctx := context.WithValue(context.Background(), unrelatedAuthorityKey{}, "retained")
	guarded, err := a.namedProfileReviewContext(ctx, plan.Routes)
	if err != nil {
		t.Fatal(err)
	}
	newMeta, err := store.Put(ctx, "reviewed", "Changed", testOwnWireGuardProfile(""), rev)
	if err != nil {
		t.Fatal(err)
	}
	plan.Routes[0].WireGuardProfileRevision = newMeta.Revision
	if _, err := (wgNamedForwardRunner{base: r}).Run(guarded, "ip", "rule", "show"); !errors.Is(err, ErrWireGuardProfileRevision) || len(r.calls) != 0 {
		t.Fatal("route alias changed frozen command guard", err, r.calls)
	}
	cleanup := wgNamedCleanupContext(guarded)
	if cleanup.Value(unrelatedAuthorityKey{}) != "retained" {
		t.Fatal("cleanup discarded another owner's authority")
	}
	if _, err := a.run(cleanup, "ip", "rule", "show"); err != nil || len(r.calls) != 1 {
		t.Fatal("catalog change blocked authorized readback", err, r.calls)
	}
}
