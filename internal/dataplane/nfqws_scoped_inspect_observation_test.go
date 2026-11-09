package dataplane

import (
	"context"
	"errors"
	"testing"
)

// Actual ExactPresence entry and fresh kernel model; the original tool-byte
// observer is modeled. Real file/command mutation and joined cleanup remain
// separately exercised by the native original tool and managed-flow fixtures.
func TestNFQWSScopedExactPresenceObservationFreshCountsAndRefusals(t *testing.T) {
	for _, cut := range []string{"fresh", "opening", "closing", "read-error", "cancel", "closing-owner", "foreign-plan"} {
		t.Run(cut, func(t *testing.T) {
			e, c := nfqwsActiveCommandFixture(t)
			b, m, _ := nfqwsScopedBindingFixture(t)
			e.binding, e.resource.plan = b, m.p
			e.material.execution, e.material.executionBound = e, true
			observer := &nfqwsPostAddObserver{}
			e.inventory.reader.Runner = observer
			sentinel := errors.New("exact-presence original source refused")
			c, cancel := context.WithCancel(c)
			defer cancel()
			reads := 0
			b.Runner = networkCleanupRunner(func(got context.Context, command string, args ...string) ([]byte, error) {
				reads++
				if got.Value(nfqwsPostAddObservationMarker{}) != observer {
					t.Fatal("exact presence escaped original observation")
				}
				if cut == "read-error" {
					return nil, sentinel
				}
				return m.Run(got, command, args...)
			})
			m.present[0] = 1
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
			count, err := b.inspect(c, p, 0)
			if cut == "fresh" {
				if err != nil || count != 1 || reads == 0 || observer.calls != 1 {
					t.Fatal("original exact presence missing", count, err, reads, observer.calls)
				}
				for _, present := range []int{0, 1, 0, 1} {
					before := reads
					m.present[0] = present
					count, err = b.inspect(c, p, 0)
					if err != nil || count != present || reads <= before {
						t.Fatal("kernel count reused across independent predicates", present, count, err, reads, before)
					}
				}
				return
			}
			if err == nil || count != 0 {
				t.Fatal("failed observation published positive presence", count, err)
			}
			if (cut == "opening" || cut == "closing" || cut == "read-error") && !errors.Is(err, sentinel) {
				t.Fatal("original refusal lost", err)
			}
			if cut == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if (cut == "opening" || cut == "cancel" || cut == "foreign-plan") && reads != 0 {
				t.Fatal("refused source read kernel", reads)
			}
			if len(m.calls) != 0 {
				t.Fatal("exact presence mutated kernel", m.calls)
			}
		})
	}
}
