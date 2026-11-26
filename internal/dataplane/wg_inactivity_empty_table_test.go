package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Kernel table output is an explicit model; the original registered source,
// roots, control and joined read-session lifetimes remain actual mechanisms.
type wgInactiveTableModel struct {
	*wgInactivityProcessModel
	count         int
	err           error
	calls         atomic.Int32
	after         func()
	started       chan struct{}
	block         bool
	table, family int
	iface         string
	identity      netidentity.Identity
}

func (m *wgInactiveTableModel) ReadWGKernelServiceTable(ctx context.Context, id netidentity.Identity, table, family int, iface string) (int, error) {
	m.calls.Add(1)
	m.identity, m.table, m.family, m.iface = id, table, family, iface
	if m.started != nil {
		close(m.started)
	}
	if m.block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if m.after != nil {
		m.after()
	}
	return m.count, m.err
}

func wgInactiveTableFixture(t *testing.T) (*wgSourceReadFixture, *WGInactivityRead, *wgInactiveTableModel) {
	t.Helper()
	f, old, base := wgInactivityFixture(t, true)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	m := &wgInactiveTableModel{wgInactivityProcessModel: base}
	tools := old.tools
	tools.Runner = m
	r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return f, r, m
}

func TestWGInactivityEmptyTableOriginalSourceAndClosedRefusals(t *testing.T) {
	for _, mode := range []string{"empty", "present", "negative-count", "many", "transport", "files", "adapter", "copy", "copied-session", "foreign-session", "family", "foreign-table", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f, r, model := wgInactiveTableFixture(t)
			spec, err := r.shape.endpointSpec()
			if err != nil {
				t.Fatal(err)
			}
			table, family := spec.Table, 4
			switch mode {
			case "present":
				model.count = 1
			case "negative-count":
				model.count = -1
			case "many":
				model.count = 2
			case "transport":
				model.err = errors.New("partial route dump")
			case "files":
				model.after = func() {
					if err := os.MkdirAll(r.shape.StateRoot, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(r.shape.StateRoot, "foreign.json"), []byte("unknown"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "adapter":
				model.after = func() { r.adapter.RuntimeConfigPath += ".changed" }
			case "family":
				family = 5
			case "foreign-table":
				table = 220
			}
			var escaped context.Context
			err = r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				escaped = c
				source := r
				if mode == "copy" {
					source = &WGInactivityRead{self: r, shape: r.shape, tools: r.tools}
				}
				if mode == "copied-session" || mode == "foreign-session" {
					original := c.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
					copy := &wgInactivityReadSession{self: original, source: r, open: true, ctx: c}
					if mode == "foreign-session" {
						copy.self = copy
						copy.source = &WGInactivityRead{}
					}
					c = context.WithValue(c, wgInactivitySessionKey{}, copy)
				}
				if mode == "canceled" {
					child, cancel := context.WithCancel(c)
					cancel()
					c = child
				}
				view := r.shape
				view.Runner = source
				return view.verifyWGEmptyNumericTable(c, table, family)
			})
			if (err == nil) != (mode == "empty") {
				t.Fatal("incorrect original empty table result", mode, err)
			}
			if model.wgInactivityProcessModel.calls.Load() != 0 {
				t.Fatal("advertised kernel source fell back to CLI")
			}
			if mode == "empty" && (model.calls.Load() != 1 || model.identity != r.tools.Identity || model.table != table || model.family != family || model.iface != r.shape.interfaceName()) {
				t.Fatal("table/source identity changed")
			}
			if r.readKernelEmptyTable(escaped, table, family) == nil {
				t.Fatal("escaped read session admitted table query")
			}
		})
	}
}

func TestWGInactivityEmptyTableAllOwnedTablesAndCLIFallback(t *testing.T) {
	f, r, model := wgInactiveTableFixture(t)
	spec, err := r.shape.endpointSpec()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []int{spec.Table, spec.EndpointTable, 219} {
		for _, family := range []int{4, 6} {
			if err := r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				view := r.shape
				view.Runner = r
				return view.verifyWGEmptyNumericTable(c, table, family)
			}); err != nil {
				t.Fatal("original owned table refused", table, family, err)
			}
		}
	}
	if model.calls.Load() != 6 || model.wgInactivityProcessModel.calls.Load() != 0 {
		t.Fatal("owned table read population changed")
	}
	fallback, cli, cliModel := wgInactivityFixture(t, true)
	if cli.kernelEmptyTableAvailable() {
		t.Fatal("custom CLI source gained kernel capability")
	}
	if err := cli.WithCurrent(fallback.ctx, nil, func(c context.Context) error {
		view := cli.shape
		view.Runner, view.IP = cli, cli.tools.IP
		spec, err := view.endpointSpec()
		if err != nil {
			return err
		}
		return view.verifyWGEmptyNumericTable(c, spec.Table, 4)
	}); err != nil {
		t.Fatal("original CLI-only path changed", err)
	}
	if cliModel.calls.Load() != 1 {
		t.Fatal("original CLI path not executed exactly once")
	}
}

func TestWGInactivityEmptyTableCloseCancelsAndJoins(t *testing.T) {
	f, r, model := wgInactiveTableFixture(t)
	model.block, model.started = true, make(chan struct{})
	spec, err := r.shape.endpointSpec()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- r.WithCurrent(f.ctx, nil, func(c context.Context) error { return r.readKernelEmptyTable(c, spec.Table, 4) })
	}()
	select {
	case <-model.started:
	case <-time.After(time.Second):
		t.Fatal("kernel table read did not begin")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join original kernel table read")
	}
	if err := <-done; err == nil || model.calls.Load() != 1 {
		t.Fatal("canceled read published/replayed table absence", err)
	}
}

func TestWGInactivityEmptyTableKeepsNameFileBookends(t *testing.T) {
	previous := rtTablesSources
	defer func() { rtTablesSources = previous }()
	for _, mode := range []string{"numeric-alias", "changed", "replaced", "new-file"} {
		t.Run(mode, func(t *testing.T) {
			f, r, model := wgInactiveTableFixture(t)
			spec, err := r.shape.endpointSpec()
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			rtTablesSources = []string{root}
			path := filepath.Join(root, "rt_tables")
			data := []byte("255 local\n254 main\n")
			if mode == "numeric-alias" {
				data = []byte("220 " + strconv.Itoa(spec.Table) + "\n")
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			model.after = func() {
				switch mode {
				case "changed":
					if err := os.WriteFile(path, []byte("255 local\n254 altered\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "replaced":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				case "new-file":
					if err := os.Mkdir(filepath.Join(root, "rt_tables.d"), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				view := r.shape
				view.Runner = r
				return view.verifyWGEmptyNumericTable(c, spec.Table, 4)
			})
			if err == nil || model.wgInactivityProcessModel.calls.Load() != 0 {
				t.Fatal("name-file guard removed or CLI fallback used", mode, err)
			}
			if mode == "numeric-alias" && model.calls.Load() != 0 {
				t.Fatal("ambiguous numeric query reached kernel source")
			}
		})
	}
}
