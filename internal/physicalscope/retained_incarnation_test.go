package physicalscope

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Native facts/NI/fence are explicit private models. No cleanup/effect owner is
// installed by these tests; Root separately exercises the actual native producer.
func TestRetainedIncarnationSelectionRevocationNeverRefreshesForward(t *testing.T) {
	for _, phase := range []string{"opening", "closing", "read-error"} {
		t.Run(phase, func(t *testing.T) {
			o, m, ctx := newModel(t)
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			original := r.Snapshot()
			if phase == "opening" {
				m.selection.Revision++
			}
			if phase == "closing" {
				m.onSelection = func(n int) {
					if n == 4 {
						m.selection.PolicyRevision++
					}
				}
			}
			if phase == "read-error" {
				o.selection = func(context.Context) (Selection, error) { return Selection{}, errors.New("selection owner stopped") }
			}
			if o.Verify(ctx, r) == nil || r.state.physicalInvalid {
				t.Fatal("selection refusal lost its separate boundary")
			}
			reads, captures := m.reads, m.captures
			o.selection = func(context.Context) (Selection, error) {
				t.Fatal("retained check reread selection")
				return Selection{}, nil
			}
			o.source.open = func(context.Context) (lifecycleFence, error) {
				t.Fatal("retained check opened new fence")
				return nil, nil
			}
			if err := o.VerifyRetainedIncarnation(ctx, r); err != nil {
				t.Fatal(err)
			}
			if reads != m.reads || m.captures != captures+2 || !reflect.DeepEqual(original, r.Snapshot()) {
				t.Fatal("retained facts refreshed or omitted capture passes")
			}
			if o.Verify(ctx, r) == nil {
				t.Fatal("retained check renewed forward permission")
			}
		})
	}
}

func TestRetainedIncarnationPhysicalFailurePermanentlyRefusesBothPaths(t *testing.T) {
	for _, path := range []string{"forward", "retained"} {
		for _, change := range []string{"identity", "facts", "capture-unknown", "overflow-fence", "closing-identity"} {
			t.Run(path+"/"+change, func(t *testing.T) {
				o, m, ctx := newModel(t)
				r, err := o.Observe(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				originalIdentity, originalFacts := m.identity, cloneSnapshot(m.facts)
				capture := o.source.capture
				switch change {
				case "identity":
					m.identity.Inode++
				case "facts":
					m.facts.Segments[0].Members[0].IfIndex++
				case "capture-unknown":
					o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) { return nil, nil, ErrUnknown }
				case "overflow-fence":
					m.fence.changed = true
				case "closing-identity":
					m.onCapture = func(n int) {
						if n == 4 {
							m.identity.Inode++
						}
					}
				}
				var failed error
				if path == "forward" {
					failed = o.Verify(ctx, r)
				} else {
					failed = o.VerifyRetainedIncarnation(ctx, r)
				}
				if !errors.Is(failed, ErrUnknown) || !r.state.physicalInvalid {
					t.Fatal("physical uncertainty did not stick", failed)
				}
				m.identity, m.facts, m.fence.changed, m.onCapture, o.source.capture = originalIdentity, originalFacts, false, nil, capture
				if o.VerifyRetainedIncarnation(ctx, r) == nil || o.Verify(ctx, r) == nil {
					t.Fatal("restored physical tuple revived original Review")
				}
			})
		}
	}
}

func TestRetainedIncarnationClosingSelectionCannotHidePhysicalDrift(t *testing.T) {
	o, m, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	original := cloneSnapshot(m.facts)
	m.facts.Devices[0].Addresses[0] = "192.0.2.21"
	m.onSelection = func(n int) {
		if n == 4 {
			m.selection.Revision++
		}
	}
	if o.Verify(ctx, r) == nil || !r.state.physicalInvalid {
		t.Fatal("closing selection refusal waived already observed physical drift")
	}
	m.facts, m.onSelection = original, nil
	if o.VerifyRetainedIncarnation(ctx, r) == nil {
		t.Fatal("restoration revived drift hidden by selection")
	}
}

func TestRetainedIncarnationRequiresSameLiveReviewAndFiniteContext(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	copy := *r
	foreign, _, _ := newModel(t)
	for _, candidate := range []*Review{nil, {}, {state: &reviewState{snapshot: r.Snapshot()}}, &copy} {
		if o.VerifyRetainedIncarnation(ctx, candidate) == nil {
			t.Fatal("detached/copied review became original")
		}
	}
	if foreign.VerifyRetainedIncarnation(ctx, r) == nil {
		t.Fatal("foreign observer accepted original review")
	}
	if o.VerifyRetainedIncarnation(context.Background(), r) == nil {
		t.Fatal("unbounded caller accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(o.VerifyRetainedIncarnation(canceled, r), context.Canceled) {
		t.Fatal("canceled caller accepted")
	}
	if err := o.VerifyRetainedIncarnation(ctx, r); err != nil {
		t.Fatal("invalid caller poisoned live review", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if o.VerifyRetainedIncarnation(ctx, r) == nil {
		t.Fatal("closed original accepted")
	}
}

func TestRetainedIncarnationClosesOriginalIdentityAfterCapture(t *testing.T) {
	o, m, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	originalCurrent := o.source.current
	calls := 0
	o.source.current = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
		calls++
		if calls == 3 {
			m.identity.Inode++
		}
		return originalCurrent(c, use)
	}
	if o.VerifyRetainedIncarnation(ctx, r) == nil || !r.state.physicalInvalid || calls != 3 {
		t.Fatal("closing NI check omitted")
	}
}
