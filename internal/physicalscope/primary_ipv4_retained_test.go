package physicalscope

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// Actual Review/witness state and joins; native physical facts and complete
// address frames are explicit private models. No effect/consent grant here.
func TestPhysicalPrimaryIPv4RetainedAfterSelectionContextEnds(t *testing.T) {
	o, m, ctx := newModel(t)
	selectionCtx, cancelSelection := context.WithCancel(ctx)
	defer cancelSelection()
	selection := o.selection
	selectionReads := 0
	o.selection = func(c context.Context) (Selection, error) {
		selectionReads++
		if err := selectionCtx.Err(); err != nil {
			return Selection{}, err
		}
		return selection(c)
	}
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	dumps := 0
	p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), func(context.Context) ([]message, error) {
		dumps++
		return []message{primaryIPv4Cache(primaryIPv4Frame(9, "192.0.2.1/24", 0), uint32(100-dumps), uint32(200-dumps), 1, 1)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before, row := r.Snapshot(), p.state.row
	cancelSelection()
	if p.Current(ctx) == nil || r.state.physicalInvalid || p.state.invalid {
		t.Fatal("selection-only refusal became physical failure")
	}
	reads, captures := selectionReads, m.captures
	o.source.open = func(context.Context) (lifecycleFence, error) {
		t.Fatal("retained witness opened replacement Review")
		return nil, ErrUnknown
	}
	if err := p.CurrentRetained(ctx); err != nil {
		t.Fatal(err)
	}
	if selectionReads != reads || dumps != 4 || m.captures != captures+4 || !reflect.DeepEqual(before, r.Snapshot()) || p.state.row != row {
		t.Fatal("retained check reread selection, omitted physical/dump bookends or adopted facts")
	}
	if p.Current(ctx) == nil || o.Verify(ctx, r) == nil {
		t.Fatal("retained comparison renewed forward permission")
	}
}

func TestPhysicalPrimaryIPv4RetainedPhysicalFailureIsSticky(t *testing.T) {
	for _, change := range []string{"secondary", "prefix", "timestamp", "malformed-foreign", "second-pass", "identity", "fence", "physical-capture", "closing-physical"} {
		t.Run(change, func(t *testing.T) {
			o, m, ctx := newModel(t)
			r, err := o.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			active, dumps := false, 0
			originalIdentity := m.identity
			originalCapture := o.source.capture
			p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), func(context.Context) ([]message, error) {
				dumps++
				row := primaryIPv4Frame(9, "192.0.2.1/24", 0)
				if active {
					switch change {
					case "secondary":
						row = primaryIPv4Frame(9, "192.0.2.1/24", 0x81)
					case "prefix":
						row.data[1] = 25
					case "timestamp":
						row = primaryIPv4Cache(row, ^uint32(0), ^uint32(0), 1, 2)
					case "malformed-foreign":
						return []message{row, {kind: 20, flags: 2, data: []byte{2}}}, nil
					case "second-pass":
						if dumps == 4 {
							row = primaryIPv4Frame(9, "192.0.2.1/24", 0x80)
						}
					case "identity":
						m.identity.Inode++
					case "fence":
						m.fence.changed = true
					case "closing-physical":
						m.facts.Segments[0].Members[0].IfIndex++
					}
				}
				return []message{row}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			originalFacts := cloneSnapshot(m.facts)
			active = true
			if change == "physical-capture" {
				o.source.capture = func(context.Context, Selection) ([]Segment, []Device, error) { return nil, nil, ErrUnknown }
			}
			if p.CurrentRetained(ctx) == nil || !r.state.physicalInvalid {
				t.Fatal("changed or unknown physics accepted")
			}
			active, m.identity, m.facts, m.fence.changed, o.source.capture = false, originalIdentity, originalFacts, false, originalCapture
			count := dumps
			if p.CurrentRetained(ctx) == nil || p.Current(ctx) == nil || o.VerifyRetainedIncarnation(ctx, r) == nil || dumps != count {
				t.Fatal("restored tuple revived original physically invalid witness")
			}
		})
	}
}

func TestPhysicalPrimaryIPv4RetainedRequiresAlreadyIssuedSameLiveWitness(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), func(context.Context) ([]message, error) {
		return []message{primaryIPv4Frame(9, "192.0.2.1/24", 0)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	copy := &PrimaryIPv4Review{state: p.state}
	unissued := &PrimaryIPv4Review{state: &primaryIPv4ReviewState{observer: o, original: r}}
	unissued.state.self = unissued
	for _, candidate := range []*PrimaryIPv4Review{nil, {}, copy, unissued} {
		if candidate.CurrentRetained(ctx) == nil {
			t.Fatal("copied/unissued witness became retained source")
		}
	}
	for _, request := range []context.Context{nil, context.Background()} {
		if p.CurrentRetained(request) == nil {
			t.Fatal("unbounded caller became retained source")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := p.CurrentRetained(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := p.CurrentRetained(ctx); err != nil {
		t.Fatal("early canceled caller poisoned untouched witness", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if p.CurrentRetained(ctx) == nil {
		t.Fatal("closed Review revived retained source")
	}
}

func TestPhysicalPrimaryIPv4RetainedCloseJoinsAddressDump(t *testing.T) {
	o, _, ctx := newModel(t)
	r, err := o.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	entered, finish := make(chan struct{}), make(chan struct{})
	block := false
	p, err := o.reviewPrimaryIPv4(ctx, r, "Home", netip.MustParseAddr("192.0.2.1"), func(context.Context) ([]message, error) {
		if block {
			close(entered)
			<-finish
			block = false
		}
		return []message{primaryIPv4Frame(9, "192.0.2.1/24", 0)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	block = true
	result := make(chan error, 1)
	go func() { result <- p.CurrentRetained(ctx) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned before original address dump joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(finish)
	<-result // May refuse if Close wins between address and closing physical capture.
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if p.CurrentRetained(ctx) == nil {
		t.Fatal("Close completion revived witness")
	}
}
