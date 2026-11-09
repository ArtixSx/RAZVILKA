package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Association comparison only. This model grants neither a tool observation
// nor an absence result; the original native parent-death fixture covers both.
func TestMihomoSameBootAbsenceReadRejectsChangedAssociation(t *testing.T) {
	for _, change := range []string{"owner-copy", "source", "reader", "input", "provider", "review", "args", "plan", "phase", "unknown", "cancel"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			root := filepath.Join(t.TempDir(), "dataplane")
			m := New(root)
			source := &RuntimeInactivitySourceReview{manager: m, root: root}
			source.self = source
			o := &mihomoSameBootCleanup{inputs: &mihomoSameBootInputs{statePath: root}, read: &mihomoColdReadRunner{original: source}, planMissing: []string{"original"}}
			o.self = o
			o.read.tools.Provider = new(netidentity.Provider)
			o.read.engineSpec.Args = []string{"original"}
			r := o.freezeAbsenceRead()
			if r.current(ctx) != nil {
				t.Fatal("unchanged structural association refused")
			}
			switch change {
			case "owner-copy":
				copy := *o
				r.owner = &copy
			case "source":
				copy := *source
				o.read.original = &copy
			case "reader":
				copy := *o.read
				o.read = &copy
			case "input":
				copy := *o.inputs
				o.inputs = &copy
			case "provider":
				o.read.tools.Provider = new(netidentity.Provider)
			case "review":
				o.read.tools.ReviewSHA256 = "changed"
			case "args":
				o.read.engineSpec.Args[0] = "changed"
			case "plan":
				o.planMissing[0] = "changed"
			case "phase":
				o.effectsClosed = true
			case "unknown":
				o.effectUnknown = true
			case "cancel":
				cancel()
			}
			if r.current(ctx) == nil {
				t.Fatal("changed comparison accepted")
			}
		})
	}
}

type sameBootAbsenceReadSourceModel struct {
	observe func(context.Context, func(context.Context) error) error
}

func (*sameBootAbsenceReadSourceModel) MihomoColdReadTools() (any, SyntheticDNSCommandTools, string, error) {
	return nil, SyntheticDNSCommandTools{}, "", ErrMihomoLiveRetirement
}
func (*sameBootAbsenceReadSourceModel) RunMihomoColdRead(context.Context, string, ...string) ([]byte, error) {
	return nil, ErrMihomoLiveRetirement
}
func (m *sameBootAbsenceReadSourceModel) WithReadOnlyToolObservation(c context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
	return m.observe(c, use)
}

func TestMihomoSameBootAbsenceReadNeverAcceptsMissingOrFailedObservation(t *testing.T) {
	for _, change := range []string{"missing", "twice", "opening", "closing", "cancel", "source-error"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			root := filepath.Join(t.TempDir(), "dataplane")
			m := New(root)
			source := &RuntimeInactivitySourceReview{manager: m, root: root}
			source.self = source
			o := &mihomoSameBootCleanup{inputs: &mihomoSameBootInputs{statePath: root}, read: &mihomoColdReadRunner{original: source}}
			o.self = o
			cause := errors.New("original source refused after read")
			calls := 0
			reader := &sameBootAbsenceReadSourceModel{}
			o.read.source = reader
			reader.observe = func(c context.Context, use func(context.Context) error) error {
				calls++
				if change == "missing" {
					return nil
				}
				if change == "opening" {
					o.effectsClosed = !o.effectsClosed
				}
				if change == "cancel" {
					cancel()
				}
				// A deliberately incorrect producer drops the callback's error.
				// The original absence must still fail, never reuse an old result.
				_ = use(c)
				if change == "twice" {
					_ = use(c)
				}
				if change == "closing" {
					o.read.source = &sameBootAbsenceReadSourceModel{}
				}
				if change == "source-error" {
					return cause
				}
				return nil
			}
			identity, err := o.observeOriginalAbsence(ctx)
			if err == nil || identity != (netidentity.Identity{}) || calls != 1 {
				t.Fatal("missing/failed observation returned a positive result", err, calls)
			}
			if change == "source-error" && !errors.Is(err, cause) {
				t.Fatal("original source error lost", err)
			}
			if change == "missing" {
				_, err = o.observeOriginalAbsence(ctx)
				if err == nil || calls != 2 {
					t.Fatal("second observation reused a result", err, calls)
				}
			}
		})
	}
}
