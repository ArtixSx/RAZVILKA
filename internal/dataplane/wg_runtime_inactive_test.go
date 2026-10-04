package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wgInactiveRunner struct {
	cut   string
	calls []string
}

func (r *wgInactiveRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	r.calls = append(r.calls, name+" "+cmd)
	if r.cut == "command" {
		return nil, errors.New("inventory unavailable")
	}
	if cmd == "-j link show" {
		if r.cut == "link" {
			return []byte(`[{"ifname":"lo"},{"ifname":"rz-wg"}]`), nil
		}
		if r.cut == "candidate" {
			return []byte(`[{"ifname":"rz-wg-canary"}]`), nil
		}
		if r.cut == "empty-inventory" {
			return []byte(`[]`), nil
		}
		return []byte(`[{"ifname":"lo"}]`), nil
	}
	if strings.HasSuffix(cmd, "rule show") {
		if r.cut == "selector" {
			return []byte("70: from all lookup 206\n"), nil
		}
		if r.cut == "unknown" {
			return []byte("70: from all goto 71\n"), nil
		}
		if r.cut == "foreign-priority" {
			return []byte("28001: from all lookup 222\n"), nil
		}
		return []byte("0: from all lookup 255\n32766: from all lookup 254\n32767: from all lookup 253\n"), nil
	}
	if strings.Contains(cmd, "-j route show table") {
		family := 4
		if strings.Contains(cmd, "-6 ") {
			family = 6
		}
		if r.cut == "missing4" && family == 4 || r.cut == "missing6" && family == 6 || r.cut == "missing-text-occupied" || r.cut == "missing-lookalike" || r.cut == "missing-wrong-family" || r.cut == "missing-oversized" {
			message := fmt.Sprintf("Error: ipv%d: FIB table does not exist.\nDump terminated", family)
			if r.cut == "missing-lookalike" {
				message += "\nPermission denied"
			}
			if r.cut == "missing-wrong-family" {
				message = fmt.Sprintf("Error: ipv%d: FIB table does not exist.", 10-family)
			}
			if r.cut == "missing-oversized" {
				message += strings.Repeat("x", 1<<20)
			}
			return []byte(message), errors.New("exit status 2")
		}
		if r.cut == "route" {
			return []byte(`[{"dst":"192.0.2.1","dev":"foreign","protocol":4}]`), nil
		}
		return []byte(`[]`), nil
	}
	if strings.Contains(cmd, "route show table") {
		family := 4
		if strings.Contains(cmd, "-6 ") {
			family = 6
		}
		if r.cut == "missing-text-occupied" {
			return []byte("192.0.2.1 dev foreign proto kernel\n"), nil
		}
		if r.cut == "missing4" && family == 4 || r.cut == "missing6" && family == 6 {
			return []byte(fmt.Sprintf("Error: ipv%d: FIB table does not exist.\nDump terminated", family)), errors.New("exit status 2")
		}
	}
	return nil, errors.New("unexpected command: " + cmd)
}

func TestWGInactivityRequiresFreshCompleteAbsenceWithoutEffects(t *testing.T) {
	for _, cut := range []string{"none", "missing4", "missing6", "missing-text-occupied", "missing-lookalike", "missing-wrong-family", "missing-oversized", "link", "candidate", "empty-inventory", "route", "selector", "foreign-priority", "unknown", "command", "process", "pending", "orphan"} {
		t.Run(cut, func(t *testing.T) {
			a := NewWireGuardAdapter(nil, t.TempDir())
			a.IP = "ip"
			r := &wgInactiveRunner{cut: cut}
			a.Runner = r
			if cut == "pending" {
				if err := os.MkdirAll(filepath.Join(a.StateRoot, wgPolicyOperationDirectory), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if cut == "orphan" {
				if err := os.MkdirAll(a.StateRoot, 0700); err != nil {
					t.Fatal(err)
				}
				if err := writeAtomic(a.RuntimeConfigPath, []byte(testOwnWireGuardProfile("")), 0600); err != nil {
					t.Fatal(err)
				}
			}
			count := 0
			err := a.verifyRuntimeInactive(context.Background(), func(context.Context, []string) error {
				count++
				if cut == "process" {
					return errWGInactiveUnknown
				}
				return nil
			})
			if cut == "none" || cut == "missing4" || cut == "missing6" {
				if err != nil || count != 2 {
					t.Fatal("fresh absence refused", count, err)
				}
			} else if err == nil {
				t.Fatal("unknown/activity accepted", cut)
			}
			for _, call := range r.calls {
				if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " delete ") || strings.Contains(call, " set ") {
					t.Fatal("observer mutated runtime", call)
				}
			}
		})
	}
}

type wgInactiveReceiptRunner struct{ base *warpFakeRunner }

func (r wgInactiveReceiptRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == "-j link show" {
		if r.base.active {
			return []byte(`[{"ifname":"lo"},{"ifname":"rz-wg"}]`), nil
		}
		return []byte(`[{"ifname":"lo"}]`), nil
	}
	return r.base.Run(ctx, name, args...)
}

func TestWGInactivityRetainedRemovedReceiptIsRequired(t *testing.T) {
	a, r, plan, root := wgReceiptFixture(t)
	state, ref := commitWGReceiptFixture(t, a, plan, root)
	a.Runner = wgInactiveReceiptRunner{base: r}
	processes := func(context.Context, []string) error { return nil }
	if err := a.verifyRuntimeInactive(context.Background(), processes); err == nil {
		t.Fatal("live committed runtime claimed inactive")
	}
	if err := a.removeWGPolicyReference(context.Background(), ref, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.removeWGEndpoint(context.Background(), state.WireGuardEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := a.stopInterface(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyRuntimeInactive(context.Background(), processes); err != nil {
		t.Fatal("settled retained intent refused", err)
	}
	if err := os.Remove(filepath.Join(a.StateRoot, wgPolicyReferenceFile)); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyRuntimeInactive(context.Background(), processes); err == nil {
		t.Fatal("retained intent without receipt accepted")
	}
}
