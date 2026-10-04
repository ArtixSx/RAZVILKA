package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type policyEffectCall struct {
	index int
	add   bool
	name  string
	args  []string
}

type policyEffectFixture struct {
	plan             PolicyEffectPlan
	root             string
	options          policyAdditionOptions
	runtime          PolicyEffectRuntime
	present          map[int]int
	calls            []policyEffectCall
	preflights       int
	inspections      int
	guards           int
	foreign          bool
	foreignReference bool
	lostAdd          int
	lostDelete       int
}

func mixedPolicyEffectPlan() PolicyEffectPlan {
	plan := PolicyEffectPlan{Generation: strings.Repeat("a", 64)}
	for _, family := range []string{"4", "6"} {
		base := len(plan.Effects)
		tool := PolicyEffectIPTables
		source := "192.168.10.0/24"
		if family == "6" {
			tool = PolicyEffectIP6Tables
			source = "fd00:10::/64"
		}
		chain := "RZL_00000000000" + family
		plan.Effects = append(plan.Effects,
			PolicyEffect{Tool: PolicyEffectIP, Add: []string{"-" + family, "rule", "add", "priority", "73", "nop"}, Delete: []string{"-" + family, "rule", "del", "priority", "73", "nop"}},
			PolicyEffect{Tool: PolicyEffectIP, Add: []string{"-" + family, "rule", "add", "priority", "53", "iif", "br-lan", "fwmark", "0x08000000/0x08000000", "goto", "73"}, Delete: []string{"-" + family, "rule", "del", "priority", "53", "iif", "br-lan", "fwmark", "0x08000000/0x08000000", "goto", "73"}, Needs: []int{base}},
			PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-N", chain}, Delete: []string{"-t", "mangle", "-X", chain}},
			PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-A", chain, "-m", "mark", "--mark", "0x08000000/0x08000000", "-j", "RETURN"}, Delete: []string{"-t", "mangle", "-D", chain, "-m", "mark", "--mark", "0x08000000/0x08000000", "-j", "RETURN"}, Needs: []int{base + 2}},
			PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-A", chain, "-s", source, "-j", "MARK", "--set-xmark", "0x20000000/0x28000000"}, Delete: []string{"-t", "mangle", "-D", chain, "-s", source, "-j", "MARK", "--set-xmark", "0x20000000/0x28000000"}, Needs: []int{base + 2, base + 3}},
			PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-A", chain, "-m", "mark", "--mark", "0x20000000/0x28000000", "-j", "RETURN"}, Delete: []string{"-t", "mangle", "-D", chain, "-m", "mark", "--mark", "0x20000000/0x28000000", "-j", "RETURN"}, Needs: []int{base + 2, base + 3, base + 4}},
			PolicyEffect{Tool: tool, Add: []string{"-t", "mangle", "-I", "PREROUTING", "1", "-i", "br-lan", "-j", chain}, Delete: []string{"-t", "mangle", "-D", "PREROUTING", "-i", "br-lan", "-j", chain}, Needs: []int{base, base + 1, base + 2, base + 3, base + 4, base + 5}},
		)
	}
	return plan
}

func newPolicyEffectFixture(t *testing.T) *policyEffectFixture {
	t.Helper()
	plan, _, err := copyPolicyEffectPlan(mixedPolicyEffectPlan())
	if err != nil {
		t.Fatal(err)
	}
	f := &policyEffectFixture{plan: plan, root: privateScopedXrayFixtureDir(t), present: map[int]int{}, lostAdd: -1, lostDelete: -1,
		options: policyAdditionOptions{boot: func() (string, error) { return "mixed-test-boot", nil }}}
	f.runtime = PolicyEffectRuntime{Runner: f, Tools: PolicyEffectTools{IP: "trusted-ip", IPTables: "trusted-iptables", IP6Tables: "trusted-ip6tables"},
		Preflight: func(context.Context) error { f.preflights++; return nil },
		Guard:     func(context.Context, int) error { f.guards++; return nil },
		ExactPresence: func(_ context.Context, index int) (int, error) {
			f.inspections++
			if f.foreign {
				return 0, errors.New("foreign shared namespace occupant")
			}
			return f.present[index], nil
		},
		BeforeDelete: func(context.Context, int) error {
			if f.foreign || f.foreignReference {
				return errors.New("foreign chain reference")
			}
			return nil
		}}
	return f
}

func (f *policyEffectFixture) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	for index, effect := range f.plan.Effects {
		if name != f.runtime.Tools.command(effect.Tool) {
			continue
		}
		add := reflect.DeepEqual(args, effect.Add)
		if !add && !reflect.DeepEqual(args, effect.Delete) {
			continue
		}
		f.calls = append(f.calls, policyEffectCall{index: index, add: add, name: name, args: append([]string(nil), args...)})
		if add {
			f.present[index]++
			if index == f.lostAdd {
				return nil, errors.New("lost add acknowledgement")
			}
		} else {
			if f.present[index] == 0 {
				return nil, errors.New("already absent")
			}
			f.present[index]--
			if index == f.lostDelete {
				return nil, errors.New("lost delete acknowledgement")
			}
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected untrusted command: %s %v", name, args)
}

func (f *policyEffectFixture) apply() error {
	return applyPolicyEffects(context.Background(), f.runtime, f.plan, f.root, f.options)
}
func (f *policyEffectFixture) remove() error {
	return removePolicyEffects(context.Background(), f.runtime, f.plan, f.root, f.options)
}
func (f *policyEffectFixture) read(t *testing.T) policyAdditionDocument {
	t.Helper()
	s, err := openPolicyEffectSession(context.Background(), f.plan, f.root, f.options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s.doc
}

func TestPolicyEffectsReceiptLifecycleUsesTrustedToolsAndReverseDependencies(t *testing.T) {
	f := newPolicyEffectFixture(t)
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	doc := f.read(t)
	if doc.Schema != 2 || doc.Generation != f.plan.Generation || doc.EffectsHash == "" || f.preflights != 1 {
		t.Fatal(doc, f.preflights)
	}
	for i, call := range f.calls {
		if call.index != i || !call.add || call.name != f.runtime.Tools.command(f.plan.Effects[i].Tool) {
			t.Fatal("wrong startup mapping or dependency order", call)
		}
	}
	before := len(f.calls)
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionExists) || len(f.calls) != before || f.preflights != 1 {
		t.Fatal("generation replayed", err)
	}
	if err := f.remove(); err != nil {
		t.Fatal(err)
	}
	for i, call := range f.calls[before:] {
		if call.add || call.index != len(f.plan.Effects)-1-i {
			t.Fatal("cleanup violated reverse dependencies", call)
		}
	}
	before = len(f.calls)
	if err := f.remove(); err != nil || len(f.calls) != before {
		t.Fatal("consumed receipt replayed", err)
	}
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionExists) || len(f.calls) != before {
		t.Fatal("consumed generation reused", err)
	}
	status, err := inspectPolicyEffects(context.Background(), f.plan, f.root, f.options)
	if err != nil || !status.Removed || status.Unknown || status.Added != 0 || status.Cleaned != len(f.plan.Effects) {
		t.Fatal(status, err)
	}
	if _, err := os.Stat(filepath.Join(f.root, policyAdditionLock)); err != nil {
		t.Fatal("permanent lock marker removed", err)
	}
}

func TestPolicyEffectsReceiptCrashBoundariesFenceEntireUnknownGeneration(t *testing.T) {
	for _, role := range []string{"apply", "remove"} {
		points := []string{"intent", "add", "added"}
		if role == "remove" {
			points = []string{"cleanup-intent", "delete", "removed"}
		}
		// Anchors, chain creation, MARK and attached jumps in both families.
		for _, index := range []int{0, 2, 4, 6, 13} {
			for _, point := range points {
				t.Run(fmt.Sprintf("%s-%s-%d", role, point, index), func(t *testing.T) {
					f := newPolicyEffectFixture(t)
					if role == "remove" {
						if err := f.apply(); err != nil {
							t.Fatal(err)
						}
					}
					f.options.fault = func(got string, at int) error {
						if got == point && at == index {
							return errors.New("process cut")
						}
						return nil
					}
					var err error
					if role == "apply" {
						err = f.apply()
					} else {
						err = f.remove()
					}
					if err == nil {
						t.Fatal("missed fault boundary")
					}
					f.options.fault = nil
					status, err := inspectPolicyEffects(context.Background(), f.plan, f.root, f.options)
					unknown := point != "added" && point != "removed"
					if err != nil || status.Unknown != unknown {
						t.Fatal("wrong fresh-reader status", status, err)
					}
					before := len(f.calls)
					kernelBefore := map[int]int{}
					for k, v := range f.present {
						kernelBefore[k] = v
					}
					if err := f.remove(); unknown {
						if !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before || !reflect.DeepEqual(f.present, kernelBefore) {
							t.Fatal("unknown child lost its prerequisite subtree", err, f.calls[before:])
						}
					} else if err != nil {
						t.Fatal("known state could not settle", err)
					}
				})
			}
		}
	}
}

func TestPolicyEffectsReceiptLostRPCAcknowledgementsNeverReplay(t *testing.T) {
	for _, role := range []string{"add", "delete"} {
		t.Run(role, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			last := len(f.plan.Effects) - 1
			if role == "add" {
				f.lostAdd = last
				if err := f.apply(); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal(err)
				}
			} else {
				if err := f.apply(); err != nil {
					t.Fatal(err)
				}
				f.lostDelete = last
				if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal(err)
				}
			}
			before := len(f.calls)
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("unknown RPC repeated", err)
			}
			for i := 0; i < last; i++ {
				if f.present[i] != 1 {
					t.Fatal("unknown attachment dropped a prerequisite", i)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptPreflightAndGuardsRefuseBeforeMutation(t *testing.T) {
	for _, mode := range []string{"preflight", "guard-before-preflight", "guard-after-intent", "cancel-inspector"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "preflight":
				f.runtime.Preflight = func(context.Context) error { f.preflights++; return errors.New("IPv6 shared namespace collision") }
			case "guard-before-preflight":
				f.runtime.Guard = func(context.Context, int) error { cancel(); return ctx.Err() }
			case "guard-after-intent":
				f.options.fault = func(point string, index int) error {
					if point == "intent" && index == 0 {
						cancel()
					}
					return nil
				}
			case "cancel-inspector":
				count := 0
				f.runtime.ExactPresence = func(context.Context, int) (int, error) {
					count++
					if count == 2 {
						cancel()
					}
					return 0, nil
				}
			}
			if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err == nil || len(f.calls) != 0 {
				t.Fatal("refused/canceled admission mutated kernel", err)
			}
			if mode == "preflight" || mode == "guard-before-preflight" {
				if _, err := os.Stat(filepath.Join(f.root, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("preflight refusal created a receipt", err)
				}
				if mode == "guard-before-preflight" && f.preflights != 0 {
					t.Fatal("preflight ran after canceled guard")
				}
			} else {
				f.options.fault = nil
				if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 0 {
					t.Fatal("canceled durable intent replayed", err)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptPreexistingForeignAndLateReferencesSurvive(t *testing.T) {
	for _, mode := range []string{"preexisting", "duplicate", "foreign", "late-add-copy", "late-preexisting-attachment", "late-delete-copy", "late-delete-reference", "guard-delete-reference"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			last := len(f.plan.Effects) - 1
			if mode == "preexisting" {
				f.present[0] = 1
				if err := f.apply(); !errors.Is(err, ErrPolicyAdditionReceipt) || !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 0 {
					t.Fatal(err)
				}
				if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 0 || f.present[0] != 1 {
					t.Fatal("preexisting intent granted cleanup", err)
				}
				return
			}
			if mode == "late-add-copy" || mode == "late-preexisting-attachment" {
				target := 0
				if mode == "late-preexisting-attachment" {
					target = last
				}
				f.options.fault = func(point string, index int) error {
					if point == "intent" && index == target {
						f.present[target] = 1
					}
					return nil
				}
				if err := f.apply(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != target || f.present[target] != 1 {
					t.Fatal("appended an indistinguishable late foreign copy", err)
				}
				if mode == "late-preexisting-attachment" {
					// Exact external attachment is not ours. Even a deficient no-op
					// reference guard cannot let cleanup strip its ACKed prerequisites.
					f.runtime.BeforeDelete = func(context.Context, int) error { return nil }
					for i := 0; i < target; i++ {
						if f.present[i] != 1 {
							t.Fatal("late attachment lost prerequisite", i)
						}
					}
				}
			} else {
				if err := f.apply(); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "duplicate":
					f.present[last] = 2
				case "foreign":
					f.foreign = true
				case "guard-delete-reference":
					guardCount := 0
					f.runtime.Guard = func(_ context.Context, index int) error {
						if index == last {
							guardCount++
							// Initial full scan, first delete guard, post-intent guard.
							if guardCount == 3 {
								f.foreignReference = true
							}
						}
						return nil
					}
				case "late-delete-copy", "late-delete-reference":
					f.options.fault = func(point string, index int) error {
						if point == "cleanup-intent" && index == last {
							if mode == "late-delete-copy" {
								f.present[last] = 2
							} else {
								f.foreignReference = true
							}
						}
						return nil
					}
				}
				before := len(f.calls)
				if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
					t.Fatal("foreign/duplicate effect deleted", err)
				}
			}
			before := len(f.calls)
			f.options.fault = nil
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("foreign/unknown cleanup repeated", err)
			}
		})
	}
}

func TestPolicyEffectsReceiptExpectedPlanAndMetadataMismatchNeverMutate(t *testing.T) {
	for _, mode := range []string{"missing", "checksum", "argv", "tool", "needs", "parent-state", "schema", "generation", "plan", "boot", "copied-root", "unknown-field", "duplicate-key", "lock"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			if err := f.apply(); err != nil {
				t.Fatal(err)
			}
			doc := f.read(t)
			path := filepath.Join(f.root, policyAdditionFile)
			write := false
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				doc.Checksum = strings.Repeat("0", 64)
				write = true
			case "argv":
				doc.Steps[0].Delete[3] = "foreign"
				write = true
			case "tool":
				doc.Steps[0].Tool = PolicyEffectIPTables
				write = true
			case "needs":
				doc.Steps[6].Needs = []int{0}
				write = true
			case "parent-state":
				doc.Steps[0].State = "removed"
				write = true
			case "schema":
				doc.Schema = 1
				write = true
			case "generation":
				doc.Generation = strings.Repeat("b", 64)
				write = true
			case "plan":
				f.plan.Generation = strings.Repeat("b", 64)
			case "boot":
				f.options.boot = func() (string, error) { return "another-boot", nil }
			case "copied-root":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.root = privateScopedXrayFixtureDir(t)
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-field", "duplicate-key":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				prefix := `{"unknown":true,`
				if mode == "duplicate-key" {
					prefix = `{"schema":2,`
				}
				if err := os.WriteFile(path, append([]byte(prefix), data[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionLock), []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if write {
				if mode != "checksum" {
					doc.Checksum = policyAdditionChecksum(doc)
				}
				data, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, inspected := len(f.calls), f.inspections
			if err := f.remove(); err == nil || len(f.calls) != before || f.inspections != inspected {
				t.Fatal("mismatched receipt acquired kernel authority", err)
			}
		})
	}
}

func TestPolicyEffectsReceiptCleanupScanFencesUnownedPlannedAndReinsertedEffects(t *testing.T) {
	for _, mode := range []string{"planned-guard-abort", "removed-reinserted"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			last := len(f.plan.Effects) - 1
			if mode == "planned-guard-abort" {
				f.runtime.Guard = func(_ context.Context, index int) error {
					if index == last {
						f.present[last] = 1 // External exact jump before our intent.
						return errors.New("installation sequence changed")
					}
					return nil
				}
				if err := f.apply(); err == nil || len(f.calls) != last {
					t.Fatal("late guard refusal did not preserve earlier ACKs", err)
				}
				if doc := f.read(t); doc.Steps[last].State != "planned" {
					t.Fatal("test did not reach planned-child gap", doc.Steps[last])
				}
			} else {
				if err := f.apply(); err != nil {
					t.Fatal(err)
				}
				f.options.fault = func(point string, index int) error {
					if point == "removed" && index == last {
						return errors.New("failure after durable attachment removal")
					}
					return nil
				}
				if err := f.remove(); err == nil {
					t.Fatal("known removal cut ignored")
				}
				if doc := f.read(t); doc.Steps[last].State != "removed" {
					t.Fatal("test did not reach known removed-child gap", doc.Steps[last])
				}
				f.present[last] = 1 // Somebody else reinserted an exact jump.
			}
			f.options.fault = nil
			f.runtime.Guard = func(context.Context, int) error { return nil }
			// The generic initial scan must fence independently of this guard.
			f.runtime.BeforeDelete = func(context.Context, int) error { return nil }
			before := len(f.calls)
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("unowned attachment let cleanup strip known guards", err)
			}
			for i := range f.plan.Effects {
				if f.present[i] != 1 {
					t.Fatal("unowned attachment or acknowledged prerequisite changed", i)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptInitiallyAbsentAckFencesFreshCopiesAndRetainsChildren(t *testing.T) {
	for _, mode := range []string{"parent", "attachment", "cancel", "fence-boundary"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			if err := f.apply(); err != nil {
				t.Fatal(err)
			}
			target := len(f.plan.Effects) - 1
			if mode == "parent" {
				target = 0
			}
			f.present[target] = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			originalInspector := f.runtime.ExactPresence
			if mode == "cancel" {
				f.runtime.ExactPresence = func(ctx context.Context, index int) (int, error) {
					count, err := originalInspector(ctx, index)
					if index == target {
						cancel()
					}
					return count, err
				}
			}
			cutHit := false
			if mode == "fence-boundary" {
				f.options.fault = func(point string, index int) error {
					if point == "cleanup-scan-intent" && index == -1 {
						cutHit = true
						return errors.New("cut after durable absence fence")
					}
					return nil
				}
			}
			before := len(f.calls)
			err := removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("initial absence did not fence whole generation", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("absence fence lost cancellation provenance", err)
			}
			if mode == "fence-boundary" && !cutHit {
				t.Fatal("scan fence fault was not hit")
			}
			if doc := f.read(t); doc.Steps[target].State != "cleanup-intent" {
				t.Fatal("absence fence not durable", doc.Steps[target])
			}
			status, err := inspectPolicyEffects(context.Background(), f.plan, f.root, f.options)
			if err != nil || !status.Unknown || status.Complete {
				t.Fatal("missing parent with live children did not remain readable Unknown", status, err)
			}
			f.present[target] = 1 // New exact external copy after observed absence.
			f.runtime.ExactPresence = originalInspector
			f.runtime.BeforeDelete = func(context.Context, int) error { return nil }
			f.options.fault = nil
			err = f.remove()
			if !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal("fresh retry adopted a new exact copy", err)
			}
			if len(f.calls) != before {
				t.Fatal("fresh retry made mutation RPC")
			}
			for i := range f.plan.Effects {
				if f.present[i] != 1 {
					t.Fatal("copy or prerequisite changed", i)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptCleanupScanWriteBoundaries(t *testing.T) {
	for _, point := range []string{"cleanup-scan-save", "cleanup-scan-intent", "cleanup-scan-restore", "cleanup-scan-restored"} {
		t.Run(point, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			if err := f.apply(); err != nil {
				t.Fatal(err)
			}
			before, reads := len(f.calls), f.inspections
			hit := false
			f.options.fault = func(got string, index int) error {
				if got == point && index == -1 {
					hit = true
					return errors.New("scan metadata IO/process boundary failure")
				}
				return nil
			}
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || !hit || len(f.calls) != before {
				t.Fatal("scan boundary did not prevent mutation", err, hit)
			}
			if point == "cleanup-scan-save" || point == "cleanup-scan-intent" {
				if f.inspections != reads {
					t.Fatal("kernel inspected before successful initial fence")
				}
			} else if f.inspections-reads != len(f.plan.Effects) {
				t.Fatal("restore boundary did not follow a complete consistent scan")
			}
			status, err := inspectPolicyEffects(context.Background(), f.plan, f.root, f.options)
			if err != nil {
				t.Fatal(err)
			}
			fenced := point == "cleanup-scan-intent" || point == "cleanup-scan-restore"
			if status.Unknown != fenced || status.Complete == fenced {
				t.Fatal(status)
			}
			f.options.fault = nil
			if fenced {
				if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
					t.Fatal("durable scan fence was replayed", err)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptPerStepAbsenceSettlementFailureKeepsDurableFence(t *testing.T) {
	for _, mode := range []string{"write-failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			if err := f.apply(); err != nil {
				t.Fatal(err)
			}
			last := len(f.plan.Effects) - 1
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.options.fault = func(point string, index int) error {
				if point == "cleanup-intent" && index == last {
					f.present[last] = 0 // Disappearance after the full consistent scan.
				}
				if point == "cleanup-absent-settlement" && index == last {
					if mode == "cancel" {
						cancel()
						return nil
					}
					return errors.New("transient settlement write failure; old valid ledger remains")
				}
				return nil
			}
			before := len(f.calls)
			err := removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options)
			if !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before || f.present[last] != 0 {
				t.Fatal("per-step disappearance lost durable revocation", err)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if doc := f.read(t); doc.Steps[last].State != "cleanup-intent" {
				t.Fatal("old valid ledger retained ACK instead of pre-read intent", doc.Steps[last])
			}
			f.present[last] = 1
			f.options.fault = nil
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("fresh retry adopted replacement copy", err)
			}
			for i := range f.plan.Effects {
				if f.present[i] != 1 {
					t.Fatal("replacement copy/prerequisite changed", i)
				}
			}
		})
	}
}

func TestPolicyEffectsReceiptClosingGuardPreventsRPCThroughReadonlyDrift(t *testing.T) {
	for _, role := range []string{"add", "delete"} {
		t.Run(role, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			target := 0
			if role == "delete" {
				if err := f.apply(); err != nil {
					t.Fatal(err)
				}
				target = len(f.plan.Effects) - 1
			}
			inspector := f.runtime.ExactPresence
			afterIntent, finalReadDone := role == "add", false
			readCount := 0
			f.runtime.ExactPresence = func(ctx context.Context, index int) (int, error) {
				count, err := inspector(ctx, index)
				if index == target && afterIntent {
					readCount++
					if role == "delete" || readCount == 2 {
						finalReadDone = true
					}
				}
				return count, err
			}
			f.options.fault = func(point string, index int) error {
				if role == "delete" && point == "cleanup-intent" && index == target {
					afterIntent = true
				}
				return nil
			}
			f.runtime.Guard = func(context.Context, int) error {
				if finalReadDone {
					return errors.New("sealed installation sequence changed during inspection")
				}
				return nil
			}
			before := len(f.calls)
			var err error
			if role == "add" {
				err = f.apply()
			} else {
				err = f.remove()
			}
			if !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("authority drift passed through to RPC", err)
			}
		})
	}
}

func TestPolicyEffectsReceiptPlanBoundsAndGraphRejectBeforeOpeningRoot(t *testing.T) {
	for _, mode := range []string{"count", "args", "arg-bytes", "aggregate-bytes", "aggregate-json", "aggregate-args", "aggregate-needs", "unknown-tool", "generation", "forward-parent", "duplicate-parent", "unsorted-parent", "nul"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			switch mode {
			case "count":
				f.plan.Effects = make([]PolicyEffect, MaxPolicyEffects+1)
			case "args":
				f.plan.Effects[0].Add = make([]string, maxPolicyEffectArgs+1)
			case "arg-bytes":
				f.plan.Effects[0].Add[0] = strings.Repeat("x", maxPolicyEffectArgBytes+1)
			case "aggregate-bytes":
				effect := f.plan.Effects[0]
				effect.Add = make([]string, maxPolicyEffectArgs)
				for i := range effect.Add {
					effect.Add[i] = strings.Repeat("x", maxPolicyEffectArgBytes)
				}
				f.plan.Effects = make([]PolicyEffect, 10)
				for i := range f.plan.Effects {
					f.plan.Effects[i] = effect
				}
			case "aggregate-json":
				effect := f.plan.Effects[0]
				effect.Add = make([]string, maxPolicyEffectArgs)
				for i := range effect.Add {
					effect.Add[i] = strings.Repeat("\t", maxPolicyEffectArgBytes)
				}
				f.plan.Effects = make([]PolicyEffect, 7)
				for i := range f.plan.Effects {
					f.plan.Effects[i] = effect
				}
			case "aggregate-args":
				effect := f.plan.Effects[0]
				effect.Add = make([]string, maxPolicyEffectArgs)
				effect.Delete = make([]string, maxPolicyEffectArgs)
				for i := range effect.Add {
					effect.Add[i], effect.Delete[i] = "x", "y"
				}
				f.plan.Effects = make([]PolicyEffect, 513)
				for i := range f.plan.Effects {
					f.plan.Effects[i] = effect
				}
			case "aggregate-needs":
				effect := f.plan.Effects[0]
				f.plan.Effects = make([]PolicyEffect, 370)
				for i := range f.plan.Effects {
					f.plan.Effects[i] = effect
					f.plan.Effects[i].Needs = make([]int, i)
					for j := range f.plan.Effects[i].Needs {
						f.plan.Effects[i].Needs[j] = j
					}
				}
			case "unknown-tool":
				f.plan.Effects[0].Tool = PolicyEffectTool("/foreign/bin/ip")
			case "generation":
				f.plan.Generation = strings.Repeat("A", 64)
			case "forward-parent":
				f.plan.Effects[1].Needs = []int{1}
			case "duplicate-parent":
				f.plan.Effects[6].Needs = []int{0, 0}
			case "unsorted-parent":
				f.plan.Effects[6].Needs = []int{1, 0}
			case "nul":
				f.plan.Effects[0].Add[0] = "\x00"
			}
			if err := f.apply(); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != 0 || f.preflights != 0 {
				t.Fatal("invalid plan reached effects", err)
			}
			entries, err := os.ReadDir(f.root)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid plan opened/wrote a generation", entries, err)
			}
		})
	}
}

func TestPolicyEffectsReceiptCopiesExpectedCommandsBeforeCallbacks(t *testing.T) {
	f := newPolicyEffectFixture(t)
	input, _, err := copyPolicyEffectPlan(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := PolicyEffectPlanDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.Preflight = func(context.Context) error {
		input.Effects[0].Add[3] = "foreign-mutated-caller"
		input.Effects[6].Needs[0] = 5
		return nil
	}
	if err := applyPolicyEffects(context.Background(), f.runtime, input, f.root, f.options); err != nil {
		t.Fatal("caller mutation changed private execution", err)
	}
	doc := f.read(t)
	if doc.EffectsHash != wanted || !reflect.DeepEqual(doc.Steps[0].Add, f.plan.Effects[0].Add) {
		t.Fatal("receipt changed with caller slice")
	}
}

func TestPolicyEffectsReceiptPromotionTransfersOneGrantAndRejectsConsumedRetry(t *testing.T) {
	for _, mode := range []string{"active", "removed", "promoted", "promotion-intent", "promotion-copy"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			if err := f.apply(); err != nil {
				t.Fatal(err)
			}
			destination := privateScopedXrayFixtureDir(t)
			if strings.HasPrefix(mode, "promotion-") {
				f.options.fault = func(point string, _ int) error {
					if point == mode {
						return errors.New("transfer cut")
					}
					return nil
				}
			}
			before := len(f.calls)
			err := promotePolicyEffects(context.Background(), f.plan, f.root, destination, f.options)
			if strings.HasPrefix(mode, "promotion-") {
				if err == nil {
					t.Fatal("transfer cut ignored")
				}
				f.options.fault = nil
				if err := promotePolicyEffects(context.Background(), f.plan, f.root, destination, f.options); !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("intent retried", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				source := f.read(t)
				if source.Phase != "promoted" {
					t.Fatal(source)
				}
				if mode == "removed" {
					if err := removePolicyEffects(context.Background(), f.runtime, f.plan, destination, f.options); err != nil {
						t.Fatal(err)
					}
				} else if mode == "promoted" {
					if err := promotePolicyEffects(context.Background(), f.plan, destination, privateScopedXrayFixtureDir(t), f.options); err != nil {
						t.Fatal(err)
					}
				}
				err = promotePolicyEffects(context.Background(), f.plan, f.root, destination, f.options)
				if mode == "active" && err != nil || mode != "active" && !errors.Is(err, ErrPolicyAdditionUnknown) {
					t.Fatal("bad retry ownership", err)
				}
			}
			if mode != "removed" && len(f.calls) != before {
				t.Fatal("promotion ran commands")
			}
			before = len(f.calls)
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != before {
				t.Fatal("source retained cleanup permission", err)
			}
		})
	}
}

func TestPolicyEffectsReceiptAndLegacyShareLockButNeverReinterpretReceipts(t *testing.T) {
	f := newPolicyEffectFixture(t)
	held, err := openPolicyEffectSession(context.Background(), f.plan, f.root, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionBusy) || len(f.calls) != 0 {
		t.Fatal(err)
	}
	legacy := &recordedPolicyFakeRunner{}
	if err := applyPolicyAddition(context.Background(), legacy, "ip", testEarlyPolicy(), f.root, f.options); !errors.Is(err, ErrPolicyAdditionBusy) || len(legacy.calls) != 0 {
		t.Fatal(err)
	}
	held.close()
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	if err := removePolicyAddition(context.Background(), legacy, "ip", testEarlyPolicy(), f.root, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(legacy.calls) != 0 {
		t.Fatal("legacy consumed mixed receipt", err)
	}
	if err := applyPolicyAddition(context.Background(), legacy, "ip", testEarlyPolicy(), f.root, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(legacy.calls) != 0 {
		t.Fatal("legacy overwrote mixed generation", err)
	}
	other := privateScopedXrayFixtureDir(t)
	if err := applyPolicyAddition(context.Background(), legacy, "ip", testEarlyPolicy(), other, f.options); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	if err := removePolicyEffects(context.Background(), f.runtime, f.plan, other, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != before {
		t.Fatal("mixed consumed legacy receipt", err)
	}
	if err := applyPolicyEffects(context.Background(), f.runtime, f.plan, other, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != before {
		t.Fatal("mixed overwrote legacy generation", err)
	}
}

func TestPolicyEffectsReceiptRuntimeRequiresEveryTrustedCallbackAndTool(t *testing.T) {
	for _, mode := range []string{"runner", "preflight", "guard", "presence", "before-delete", "tool"} {
		t.Run(mode, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			switch mode {
			case "runner":
				f.runtime.Runner = nil
			case "preflight":
				f.runtime.Preflight = nil
			case "guard":
				f.runtime.Guard = nil
			case "presence":
				f.runtime.ExactPresence = nil
			case "before-delete":
				f.runtime.BeforeDelete = nil
			case "tool":
				f.runtime.Tools.IP6Tables = ""
			}
			if err := f.apply(); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != 0 || f.preflights != 0 {
				t.Fatal("missing trusted runtime admitted", err)
			}
			if _, err := os.Stat(filepath.Join(f.root, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid runtime created a receipt", err)
			}
		})
	}
}

func TestPolicyEffectsReceiptFailedDurableAckDoesNotGrantCleanup(t *testing.T) {
	f := newPolicyEffectFixture(t)
	f.options.fault = func(point string, index int) error {
		if point == "add" && index == 0 {
			path := filepath.Join(f.root, policyAdditionFile)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionUnknown) || f.present[0] != 1 || len(f.calls) != 1 {
		t.Fatal("failed durable ACK cleaned/granted ownership", err)
	}
	f.options.fault = nil
	if err := f.remove(); !errors.Is(err, ErrPolicyAdditionReceipt) || f.present[0] != 1 || len(f.calls) != 1 {
		t.Fatal("unavailable ledger granted cleanup", err)
	}
}

func TestPolicyEffectsReceiptLegacyCanonicalBytesAndChecksumUnchanged(t *testing.T) {
	state, root, runner, options := additionFixture(t)
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	doc := readAdditionFixture(t, state, root, options)
	type oldStep struct {
		Add    []string `json:"add"`
		Delete []string `json:"delete"`
		State  string   `json:"state"`
	}
	type oldDocument struct {
		Schema          int       `json:"schema"`
		ID              string    `json:"id"`
		Boot            string    `json:"boot"`
		PolicyHash      string    `json:"policy_sha256"`
		RootHash        string    `json:"root_sha256"`
		Phase           string    `json:"phase"`
		PromotionTarget string    `json:"promotion_target,omitempty"`
		Steps           []oldStep `json:"steps"`
		Checksum        string    `json:"receipt_sha256,omitempty"`
	}
	old := oldDocument{Schema: doc.Schema, ID: doc.ID, Boot: doc.Boot, PolicyHash: doc.PolicyHash, RootHash: doc.RootHash, Phase: doc.Phase, PromotionTarget: doc.PromotionTarget}
	for _, step := range doc.Steps {
		old.Steps = append(old.Steps, oldStep{Add: step.Add, Delete: step.Delete, State: step.State})
	}
	withoutChecksum, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if routeidentity.Hash(withoutChecksum) != doc.Checksum {
		t.Fatal("schema 1 checksum changed")
	}
	old.Checksum = doc.Checksum
	wanted, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(root, policyAdditionFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, wanted) {
		t.Fatal("schema 1 canonical bytes changed")
	}
}
