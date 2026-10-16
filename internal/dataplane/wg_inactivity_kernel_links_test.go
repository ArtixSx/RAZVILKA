package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Kernel facts here are explicit portable models. Actual Manager/control/source
// and retained read-session lifetimes are used; this is not native acceptance.
type wgKernelLinkSourceModel struct {
	*wgInactivityProcessModel
	links   []physicalscope.WGKernelLink
	err     error
	calls   atomic.Int32
	after   func()
	block   bool
	started chan struct{}
}

func (m *wgKernelLinkSourceModel) ReadWGKernelLinks(ctx context.Context, _ netidentity.Identity) ([]physicalscope.WGKernelLink, error) {
	m.calls.Add(1)
	if m.started != nil {
		close(m.started)
	}
	if m.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if m.after != nil {
		m.after()
	}
	return m.links, m.err
}

func newWGKernelLinkSourceFixture(t *testing.T) (*wgSourceReadFixture, *WGInactivityRead, *wgKernelLinkSourceModel) {
	t.Helper()
	f, old, base := wgInactivityFixture(t, true)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	model := &wgKernelLinkSourceModel{wgInactivityProcessModel: base, links: []physicalscope.WGKernelLink{{Name: "lo", Index: 1}, {Name: "foreign-wg", Index: 77, Kind: "wireguard"}, {Name: "foreign-awg", Index: 78, Kind: "amneziawg"}}}
	tools := old.tools
	tools.Runner = model
	r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return f, r, model
}

func TestWGInactivityKernelLinksUseOriginalSourceAndNeverFallbackAfterRefusal(t *testing.T) {
	for _, cut := range []string{"none", "own", "candidate", "empty", "duplicate-name", "duplicate-index", "transport", "files", "adapter", "copy"} {
		t.Run(cut, func(t *testing.T) {
			f, r, model := newWGKernelLinkSourceFixture(t)
			switch cut {
			case "own":
				model.links = append(model.links, physicalscope.WGKernelLink{Name: r.shape.interfaceName(), Index: 91})
			case "candidate":
				model.links = append(model.links, physicalscope.WGKernelLink{Name: r.shape.interfaceName() + "-canary", Index: 91})
			case "empty":
				model.links = nil
			case "duplicate-name":
				model.links = append(model.links, physicalscope.WGKernelLink{Name: "foreign-wg", Index: 91})
			case "duplicate-index":
				model.links = append(model.links, physicalscope.WGKernelLink{Name: "other", Index: 77})
			case "transport":
				model.err = errors.New("partial kernel dump")
			case "files":
				model.after = func() {
					if err := os.MkdirAll(r.shape.StateRoot, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(r.shape.StateRoot, "new.json"), []byte("unknown"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "adapter":
				model.after = func() { r.adapter.RuntimeConfigPath += ".changed" }
			}
			var saved context.Context
			err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				saved = c
				source := r
				if cut == "copy" {
					source = &WGInactivityRead{self: r, tools: r.tools}
				}
				view := r.shape
				view.Runner = source
				return view.verifyWGInactiveLinks(c, []string{view.interfaceName(), view.interfaceName() + "-canary"})
			})
			if (err == nil) != (cut == "none") {
				t.Fatal("incorrect negative link observation", cut, err)
			}
			if model.wgInactivityProcessModel.calls.Load() != 0 {
				t.Fatal("kernel source refusal fell back to CLI")
			}
			if _, err := r.readKernelLinks(saved); err == nil {
				t.Fatal("escaped closed session read kernel facts")
			}
		})
	}
}

func TestWGInactivityKernelLinksCloseCancelsAndJoinsOriginalRead(t *testing.T) {
	f, r, model := newWGKernelLinkSourceFixture(t)
	model.block, model.started = true, make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.WithCurrent(f.ctx, nil, func(c context.Context) error { _, err := r.readKernelLinks(c); return err })
	}()
	select {
	case <-model.started:
	case <-time.After(time.Second):
		t.Fatal("original kernel read did not begin")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("source Close did not join canceled kernel read")
	}
	if err := <-done; err == nil {
		t.Fatal("canceled original kernel read published facts")
	}
	if model.calls.Load() != 1 {
		t.Fatal("read replayed while closing")
	}
}
