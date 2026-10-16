package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestWGEmptyTableStock44NegotiatesOnlyExactDiagnosticAndEmptyText(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, mode := range []string{"json-empty", "unsupported-N", "unsupported-j", "route", "whitespace", "nul", "json-text", "oversized", "plain-error", "malformed-json", "nonempty-json", "permission", "diagnostic-lookalike", "successful-diagnostic", "canceled"} {
			t.Run(fmt.Sprintf("%d/%s", family, mode), func(t *testing.T) {
				a := NewWireGuardAdapter(nil, t.TempDir())
				a.IP = "ip"
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				wantJSON, wantText := []string{"-N"}, []string{}
				if family == 6 {
					wantJSON, wantText = append(wantJSON, "-6"), append(wantText, "-6")
				}
				wantJSON = append(wantJSON, "-j", "route", "show", "table", "206")
				wantText = append(wantText, "route", "show", "table", "206")
				a.Runner = networkCleanupRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
					calls++
					want := wantJSON
					if calls == 2 {
						want = wantText
					}
					if name != "ip" || calls > 2 || !slices.Equal(args, want) {
						t.Fatalf("unexpected command %s %v", name, args)
					}
					if calls == 1 {
						switch mode {
						case "json-empty":
							return []byte("[]"), nil
						case "malformed-json":
							return []byte("{}"), nil
						case "nonempty-json":
							return []byte(`[{"dst":"default","dev":"foreign"}]`), nil
						case "permission":
							return []byte("Permission denied\n"), errors.New("exit status 1")
						case "diagnostic-lookalike":
							return []byte("Option \"-j\" is unknown, try \"ip -help\".\nPermission denied"), errors.New("exit status 255")
						case "successful-diagnostic":
							return []byte("Option \"-j\" is unknown, try \"ip -help\".\n"), nil
						case "canceled":
							cancel()
						}
						option := "-N"
						if mode == "unsupported-j" {
							option = "-j"
						}
						return []byte(fmt.Sprintf("Option %q is unknown, try \"ip -help\".\n", option)), errors.New("exit status 255")
					}
					switch mode {
					case "route":
						return []byte("default dev foreign\n"), nil
					case "whitespace":
						return []byte("\n"), nil
					case "nul":
						return []byte{0}, nil
					case "json-text":
						return []byte("[]"), nil
					case "oversized":
						return []byte(strings.Repeat(" ", (1<<20)+1)), nil
					case "plain-error":
						return nil, errors.New("lost read")
					}
					return nil, nil // Actual stock518 empty table output is zero bytes.
				})
				err := a.verifyWGEmptyNumericTable(ctx, 206, family)
				ok := mode == "json-empty" || mode == "unsupported-N" || mode == "unsupported-j"
				if (err == nil) != ok {
					t.Fatal("wrong absence result", err)
				}
				wantCalls := 2
				if slices.Contains([]string{"json-empty", "malformed-json", "nonempty-json", "permission", "diagnostic-lookalike", "successful-diagnostic", "canceled"}, mode) {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Fatal("unexpected format retry", calls, wantCalls)
				}
			})
		}
	}
}

func TestWGEmptyTableStock44ReadIsAdapterFiniteAndNeverPositiveProof(t *testing.T) {
	for _, engine := range []string{"warp-wg", "wireguard", "amneziawg"} {
		t.Run(engine, func(t *testing.T) {
			a := NewWARPWireGuardAdapter(nil, t.TempDir())
			if engine == "wireguard" {
				a = NewWireGuardAdapter(nil, t.TempDir())
			} else if engine == "amneziawg" {
				a = NewAmneziaWGAdapter(nil, t.TempDir())
			}
			a.IP = "ip"
			spec, err := a.endpointSpec()
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			a.Runner = networkCleanupRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				calls++
				if slices.Contains(args, "-j") {
					return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
				}
				return nil, nil
			})
			for _, table := range []int{spec.Table, spec.EndpointTable, 219} {
				if err := a.verifyWGEmptyNumericTable(context.Background(), table, 4); err != nil {
					t.Fatal("fixed empty table refused", table, err)
				}
			}
			before := calls
			for _, table := range []int{0, 254, 255, -1, 999} {
				if a.verifyWGEmptyNumericTable(context.Background(), table, 4) == nil {
					t.Fatal("foreign table admitted", table)
				}
			}
			if a.verifyWGEmptyNumericTable(context.Background(), spec.Table, 0) == nil || calls != before {
				t.Fatal("invalid scope reached runner")
			}
			if _, err := a.readWGCompleteDetailedNumericTable(context.Background(), spec.Table, 4); err == nil || calls != before+1 {
				t.Fatal("positive detailed proof negotiated empty text")
			}
		})
	}
}

func TestWGEmptyTableStock44IsUsedByFullRepeatedInactiveObserver(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(strconv.FormatBool(occupied), func(t *testing.T) {
			a := NewWireGuardAdapter(nil, t.TempDir())
			a.IP = "ip"
			base := &wgInactiveRunner{}
			plainReads, processReads := 0, 0
			a.Runner = networkCleanupRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
				if slices.Contains(args, "route") && slices.Contains(args, "-j") {
					return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
				}
				plain := args
				if len(plain) > 0 && plain[0] == "-6" {
					plain = plain[1:]
				}
				if len(plain) == 4 && slices.Equal(plain[:3], []string{"route", "show", "table"}) {
					plainReads++
					if occupied {
						return []byte("default dev foreign\n"), nil
					}
					return nil, nil
				}
				return base.Run(c, name, args...)
			})
			err := a.verifyRuntimeInactive(context.Background(), func(context.Context, []string) error { processReads++; return nil })
			if occupied {
				if err == nil || plainReads != 1 || processReads != 0 {
					t.Fatal("foreign table became complete absence", err, plainReads, processReads)
				}
			} else if err != nil || plainReads != 12 || processReads != 2 {
				t.Fatal("full observer skipped negotiated table bookends", err, plainReads, processReads)
			}
		})
	}
}

type wgEmptyTableSourceModel struct {
	*wgInactivityProcessModel
	commands   [][]string
	afterFirst func()
}

func (m *wgEmptyTableSourceModel) RunWG(ctx context.Context, admission WGCommandAdmission, name string, args ...string) ([]byte, error) {
	m.commands = append(m.commands, slices.Clone(args))
	out, err := m.wgInactivityProcessModel.RunWG(ctx, admission, name, args...)
	if err != nil {
		return out, err
	}
	if len(m.commands) == 1 && m.afterFirst != nil {
		m.afterFirst()
	}
	if slices.Contains(args, "-j") {
		return []byte("Option \"-N\" is unknown, try \"ip -help\".\n"), errors.New("exit status 255")
	}
	return out, nil
}

func TestWGEmptyTableStock44KeepsOriginalSourceAcrossActualJoinedCommands(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(strconv.FormatBool(changed), func(t *testing.T) {
			f, old, base := wgInactivityFixture(t, true)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			model := &wgEmptyTableSourceModel{wgInactivityProcessModel: base}
			tools := old.tools
			tools.Runner = model
			r, err := ReviewWGInactivityRead(f.ctx, context.Background(), f.manager, f.control, tools)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if changed {
				model.afterFirst = func() { r.adapter.RuntimeConfigPath += ".changed" }
			}
			err = r.WithCurrent(f.ctx, nil, func(c context.Context) error {
				view := r.shape
				view.Runner, view.IP = r, r.tools.IP
				return view.verifyWGEmptyNumericTable(c, 205, 6)
			})
			if changed {
				if err == nil || len(model.commands) != 1 {
					t.Fatal("changed original owner retried or published absence", err, model.commands)
				}
			} else if err != nil || len(model.commands) != 2 || !slices.Equal(model.commands[1], []string{"-6", "route", "show", "table", "205"}) {
				t.Fatal("same original reader could not join format retry", err, model.commands)
			}
		})
	}
}
