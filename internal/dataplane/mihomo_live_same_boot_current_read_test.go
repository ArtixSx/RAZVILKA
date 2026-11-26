package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMihomoSameBootCurrentReadPreservesBudget(t *testing.T) {
	parent, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	short, stop := context.WithTimeout(parent, time.Second)
	defer stop()
	long, end := context.WithTimeout(context.WithoutCancel(parent), 2*time.Minute)
	defer end()
	if sameBootCurrentReadContext(parent, short) != nil || sameBootCurrentReadContext(parent, parent) != nil || sameBootCurrentReadContext(parent, long) == nil || sameBootCurrentReadContext(parent, context.WithoutCancel(parent)) == nil {
		t.Fatal("original finite budget changed")
	}
	cancel()
	if sameBootCurrentReadContext(parent, long) == nil {
		t.Fatal("original cancellation lost")
	}
}

// Structural handles cannot mint a successful actual Current. In particular,
// a producer that drops the original body's failure cannot convert it to PASS.
func TestMihomoSameBootCurrentReadNeverAcceptsMissingOrFailedObservation(t *testing.T) {
	for _, mode := range []string{"missing", "twice", "swallowed", "closing", "source-error", "cancel", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			root := filepath.Join(t.TempDir(), "dataplane")
			original := &RuntimeInactivitySourceReview{manager: New(root), root: root}
			original.self = original
			o := &mihomoSameBootCleanup{inputs: &mihomoSameBootInputs{statePath: root}, read: &mihomoColdReadRunner{original: original}}
			o.self = o
			reader := &sameBootAbsenceReadSourceModel{}
			o.read.source = reader
			cause := errors.New("source closing refused")
			calls := 0
			reader.observe = func(c context.Context, use func(context.Context) error) error {
				calls++
				if mode == "missing" {
					return nil
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "unbounded" {
					c = context.WithoutCancel(c)
				}
				_ = use(c)
				if mode == "twice" {
					_ = use(c)
				}
				if mode == "closing" {
					o.effectsClosed = true
				}
				if mode == "source-error" {
					return cause
				}
				return nil
			}
			if err := o.current(ctx); err == nil || calls != 1 || mode == "source-error" && !errors.Is(err, cause) {
				t.Fatal("invalid observation accepted or original error lost", err, calls)
			}
		})
	}
}
