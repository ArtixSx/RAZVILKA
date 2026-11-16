package dataplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// The original owner/session are real; kernel and tool bytes are explicit
// models here. Actual tool checks and full Apply require the native gate.
type wgObservedKernelModel struct {
	*wgKernelLinkSourceModel
	observe              func(context.Context, func(context.Context) error) error
	observations, tables int
}

func (m *wgObservedKernelModel) WithWGInactivityToolObservation(c context.Context, _ netidentity.Identity, _ string, use func(context.Context) error) error {
	m.observations++
	return m.observe(c, use)
}

func (m *wgObservedKernelModel) ReadWGKernelServiceTable(context.Context, netidentity.Identity, int, int, string) (int, error) {
	m.tables++
	return 0, m.err
}

func TestWGInactivityKernelToolClosingBeforeResult(t *testing.T) {
	for _, kind := range []string{"links", "table"} {
		for _, cut := range []string{"success", "closing", "body", "omitted", "duplicate", "swallowed", "foreign-context", "owner-change"} {
			t.Run(kind+"/"+cut, func(t *testing.T) {
				f, old, base := wgInactivityFixture(t, true)
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				m := &wgObservedKernelModel{wgKernelLinkSourceModel: &wgKernelLinkSourceModel{wgInactivityProcessModel: base, links: []physicalscope.WGKernelLink{{Name: "lo", Index: 1}}}}
				tools := old.tools
				tools.Runner = m
				r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				failure := errors.New("modeled tool/kernel failure")
				if cut == "body" || cut == "swallowed" {
					m.err = failure
				}
				m.observe = func(c context.Context, use func(context.Context) error) error {
					if cut == "omitted" {
						return nil
					}
					if cut == "foreign-context" {
						return use(f.ctx)
					}
					result := use(c)
					switch cut {
					case "closing":
						return failure
					case "duplicate":
						_ = use(c)
					case "swallowed":
						return nil
					case "owner-change":
						r.tools.ReviewSHA256 = "foreign"
					}
					return result
				}
				err = r.WithCurrent(f.ctx, nil, func(c context.Context) error {
					if kind == "table" {
						return r.readKernelEmptyTable(c, 219, 4)
					}
					links, err := r.readKernelLinks(c)
					if cut != "success" && len(links) != 0 {
						t.Fatal("unclosed provisional links escaped")
					}
					return err
				})
				if (err == nil) != (cut == "success") {
					t.Fatal(cut, err)
				}
				if m.observations != 1 {
					t.Fatal("original observer not called once", m.observations)
				}
				if cut == "success" && kind == "links" && m.calls.Load() != 1 {
					t.Fatal("kernel link source lost")
				}
				if cut == "success" && kind == "table" && m.tables != 1 {
					t.Fatal("kernel table source lost")
				}
			})
		}
	}
}

func TestWGKernelToolComparisonSealsAndJoins(t *testing.T) {
	for _, cut := range []string{"early-return", "reentrant", "recovered-panic", "observer-panic"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			entered, exited := make(chan struct{}), make(chan struct{})
			var escaped func(context.Context) error
			var invoke func(context.Context) error
			observe := func(c context.Context, use func(context.Context) error) error {
				escaped, invoke = use, use
				if cut == "early-return" || cut == "observer-panic" {
					go func() { _ = use(c) }()
					<-entered
					if cut == "observer-panic" {
						panic("observer")
					}
					return nil
				}
				if cut == "recovered-panic" {
					func() { defer func() { _ = recover() }(); _ = use(c) }()
					return nil
				}
				return use(c)
			}
			read := func(c context.Context) error {
				close(entered)
				defer close(exited)
				if cut == "recovered-panic" {
					panic("body")
				}
				if cut == "reentrant" {
					_ = invoke(c)
					return nil
				}
				<-c.Done()
				return c.Err()
			}
			var err error
			var caught any
			func() {
				defer func() { caught = recover() }()
				err = wgKernelToolComparison(ctx, observe, func(c context.Context) error { return c.Err() }, read)
			}()
			if cut == "observer-panic" {
				if caught != "observer" {
					t.Fatal(caught)
				}
			} else if err == nil {
				t.Fatal("incomplete observation passed")
			}
			select {
			case <-exited:
			default:
				t.Fatal("body not joined")
			}
			if escaped(ctx) == nil {
				t.Fatal("escaped callback still open")
			}
		})
	}
}
