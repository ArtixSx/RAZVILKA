package dataplane

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Dispatch model only: held-file/hash verification remains the responsibility
// of the original native observer tests. Kernel images below are always fresh.
type nfqwsPostAddObservationMarker struct{}
type nfqwsPostAddObserver struct {
	calls int
	enter func(context.Context) error
	close func() error
}

func (*nfqwsPostAddObserver) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrNFQWSScopedOwner
}
func (m *nfqwsPostAddObserver) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
	m.calls++
	if m.enter != nil {
		if err := m.enter(c); err != nil {
			return err
		}
	}
	err := use(context.WithValue(c, nfqwsPostAddObservationMarker{}, m))
	if m.close != nil {
		err = errors.Join(err, m.close())
	}
	return err
}

func TestNFQWSScopedPostAddObservationFreshImageAndRefusals(t *testing.T) {
	for _, cut := range []string{"fresh", "opening", "closing", "read-error", "cancel", "closing-owner", "foreign-plan"} {
		t.Run(cut, func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			b, m, _ := nfqwsScopedBindingFixture(t)
			e.binding, e.resource.plan = b, m.p
			e.material.execution, e.material.executionBound = e, true
			observer := &nfqwsPostAddObserver{}
			e.inventory.reader.Runner = observer
			sentinel := errors.New("original observation refused")
			c, cancel := context.WithCancel(c)
			defer cancel()
			reads := 0
			b.Runner = networkCleanupRunner(func(got context.Context, command string, args ...string) ([]byte, error) {
				reads++
				if got.Value(nfqwsPostAddObservationMarker{}) != observer {
					t.Fatal("post-RPC read escaped original observation")
				}
				if cut == "read-error" {
					return nil, sentinel
				}
				return m.Run(got, command, args...)
			})
			m.present[0] = 1 // Explicit completed RPC kernel model.
			p := m.p
			switch cut {
			case "opening":
				observer.enter = func(context.Context) error { return sentinel }
			case "closing":
				observer.close = func() error { return sentinel }
			case "cancel":
				observer.enter = func(context.Context) error { cancel(); return nil }
			case "closing-owner":
				observer.close = func() error { e.material.adapter.activeExecution = nil; return nil }
			case "foreign-plan":
				copy := *p
				p = &copy
			}
			err := b.postAdd(c, p, p.mixed.Effects[0].Tool, 0)
			if cut == "fresh" {
				if err != nil || reads == 0 || observer.calls != 1 {
					t.Fatal("original observation missing", err, reads, observer.calls)
				}
				for _, count := range []int{0, 2, 1} {
					before := reads
					m.present[0] = count
					err = b.postAdd(c, p, p.mixed.Effects[0].Tool, 0)
					if (err == nil) != (count == 1) || reads <= before {
						t.Fatal("post-RPC image reused across changes", count, err, reads, before)
					}
				}
				return
			}
			if err == nil {
				t.Fatal("refusal became successful ACK", cut)
			}
			if (cut == "opening" || cut == "closing" || cut == "read-error") && !errors.Is(err, sentinel) {
				t.Fatal("original error lost", err)
			}
			if cut == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if (cut == "opening" || cut == "cancel" || cut == "foreign-plan") && reads != 0 {
				t.Fatal("refused observation read kernel", reads)
			}
		})
	}
}

func TestNFQWSScopedPostAddClosingRefusalKeepsCOMMONIntent(t *testing.T) {
	e, c := nfqwsActiveCommandFixture(t)
	b, m, root := nfqwsScopedBindingFixture(t)
	e.binding, e.resource.plan = b, m.p
	e.material.execution, e.material.executionBound = e, true
	observer := &nfqwsPostAddObserver{}
	e.inventory.reader.Runner = observer
	mutated, postRead := false, false
	sentinel := errors.New("post-add original tool closing refusal")
	observer.close = func() error {
		if mutated {
			return sentinel
		}
		return nil
	}
	b.Runner = networkCleanupRunner(func(got context.Context, command string, args ...string) ([]byte, error) {
		if slices.Equal(args, m.p.mixed.Effects[0].Add) {
			if got.Value(nfqwsPostAddObservationMarker{}) != nil {
				t.Fatal("actual mutation borrowed readonly observation")
			}
			mutated = true
		} else if mutated {
			postRead = got.Value(nfqwsPostAddObservationMarker{}) == observer
		}
		return m.Run(got, command, args...)
	})
	err := b.Apply(c, m.p, root)
	status, inspectErr := b.Inspect(context.Background(), m.p, root)
	if !errors.Is(err, sentinel) || !errors.Is(err, ErrPolicyAdditionUnknown) || !mutated || !postRead || len(m.calls) != 1 || inspectErr != nil || !status.Unknown || status.Pending != 1 || status.Added != 0 {
		t.Fatal("closing refusal acknowledged or continued mutation", err, status, inspectErr, postRead, m.calls)
	}
}
