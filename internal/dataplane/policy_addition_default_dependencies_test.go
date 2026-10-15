package dataplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Mutations use the shared independent kernel model. This fixture supplies
// unknown/read-failed RPDB output without interpreting ownership or selectors.
type additionDefaultDependencyRunner struct {
	base             *recordedPolicyFakeRunner
	family           int
	kind             string
	row              string
	foreign          policyKernelEntry
	numericReads     map[int]int
	afterNumericRead func(int)
	// A failed numeric read also fails the plain fallback read that follows.
	fallbackFails bool
}

func (r *additionDefaultDependencyRunner) arm(family int, kind string, table int) {
	r.family, r.kind = family, kind
	r.row = ""
	switch kind {
	case "foreign", "different-table":
		r.foreign = policyKernelEntry{family: family, priority: 61, table: strconv.Itoa(table)}
		if family == 4 {
			r.foreign.source, r.foreign.dest = "192.168.1.41/32", "1.1.1.1/32"
		} else {
			r.foreign.source, r.foreign.dest = "fd00::41/128", "2606:4700::1111/128"
		}
		r.base.kernel.entries = append(r.base.kernel.entries, r.foreign)
	case "unknown":
		r.row = "61: from all iif mystery goto 99"
	case "alias":
		r.row = "61: from all lookup main"
	}
}

func (r *additionDefaultDependencyRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plain, numeric := args, false
	if len(plain) > 0 && plain[0] == "-N" {
		plain, numeric = plain[1:], true
	}
	family := 4
	if len(plain) > 0 && plain[0] == "-6" {
		plain, family = plain[1:], 6
	}
	read := reflect.DeepEqual(plain, []string{"rule", "show"})
	if numeric && read {
		if r.numericReads == nil {
			r.numericReads = make(map[int]int)
		}
		r.numericReads[family]++
		if r.afterNumericRead != nil {
			r.afterNumericRead(family)
		}
	}
	if read && family == r.family && r.kind == "read-failed" && (numeric || r.fallbackFails) {
		r.fallbackFails = numeric
		return nil, errors.New("dependency RPDB read failed")
	}
	output, err := r.base.Run(ctx, command, args...)
	if err != nil || !read || family != r.family {
		return output, err
	}
	if numeric {
		switch r.kind {
		case "numeric-unsupported":
			return []byte("unknown option -N"), errors.New("numeric RPDB read unsupported")
		case "builtin-alias":
			return []byte(strings.Replace(string(output), "32766: from all lookup 254", "32766: from all lookup main", 1)), nil
		}
	}
	if r.row != "" {
		output = append(output, []byte(r.row+"\n")...)
	}
	return output, nil
}

func additionDependencyDefaultDeletes(calls []string) []string {
	var deletes []string
	for _, call := range receiptMutationCalls(calls) {
		if strings.Contains(call, "route del default") {
			deletes = append(deletes, call)
		}
	}
	return deletes
}

func assertAdditionDependencyHeld(t *testing.T, state PolicyState, root string, options policyAdditionOptions, runner *additionDefaultDependencyRunner, defaults map[string]string, states [2]string) {
	t.Helper()
	if !reflect.DeepEqual(runner.base.kernel.defaults, defaults) {
		t.Fatal("dependency changed a prerequisite default", runner.base.kernel.defaults, defaults)
	}
	doc := readAdditionFixture(t, state, root, options)
	for i, wanted := range states {
		if doc.Steps[i].State != wanted {
			t.Fatalf("default %d settled despite dependency: %s, want %s", i, doc.Steps[i].State, wanted)
		}
	}
	if (&policyAdditionSession{doc: doc}).status().Removed {
		t.Fatal("dependent/absent default became a settled Stop receipt")
	}
	if runner.kind == "foreign" || runner.kind == "different-table" {
		if !reflect.DeepEqual(runner.base.kernel.entries, []policyKernelEntry{runner.foreign}) {
			t.Fatal("cleanup changed the foreign selector or retained an owned one", runner.base.kernel.entries)
		}
	} else if len(runner.base.kernel.entries) != 0 {
		t.Fatal("acknowledged own selectors were not cleaned exactly", runner.base.kernel.entries)
	}
}

func cloneAdditionDependencyDefaults(defaults map[string]string) map[string]string {
	clone := make(map[string]string, len(defaults))
	for key, value := range defaults {
		clone[key] = value
	}
	return clone
}

func TestPolicyAdditionDefaultDependenciesRetainBothFamilies(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"foreign", "unknown", "alias", "builtin-alias", "read-failed", "numeric-unsupported"} {
			t.Run(fmt.Sprintf("IPv%d/%s", family, kind), func(t *testing.T) {
				state, root, base, options := additionFixture(t)
				if kind == "numeric-unsupported" {
					aliasReservedTableName(t, state.Table)
				}
				runner := &additionDefaultDependencyRunner{base: base}
				ctx := context.Background()
				if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
					t.Fatal(err)
				}
				defaults := cloneAdditionDependencyDefaults(base.kernel.defaults)
				runner.arm(family, kind, state.Table)
				before := len(base.calls)
				err := removePolicyAddition(ctx, runner, "ip", state, root, options)
				if !errors.Is(err, ErrPolicyAdditionUnknown) || !errors.Is(err, ErrPolicyDefaultReferenced) || len(additionDependencyDefaultDeletes(base.calls[before:])) != 0 || runner.numericReads[family] == 0 {
					t.Fatal("dependency did not hold both defaults", err, base.calls[before:])
				}
				assertAdditionDependencyHeld(t, state, root, options, runner, defaults, [2]string{"added", "added"})
				before = len(base.calls)
				if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(base.calls[before:])) != 0 {
					t.Fatal("fresh retry gained dependent cleanup authority", err, base.calls[before:])
				}
			})
		}
	}
}

func TestPolicyAdditionDefaultDependenciesRecheckAfterDurableIntent(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, kind := range []string{"foreign", "unknown", "alias", "builtin-alias", "read-failed", "numeric-unsupported"} {
			t.Run(fmt.Sprintf("IPv%d/%s", family, kind), func(t *testing.T) {
				state, root, base, options := additionFixture(t)
				if kind == "numeric-unsupported" {
					aliasReservedTableName(t, state.Table)
				}
				runner := &additionDefaultDependencyRunner{base: base}
				ctx := context.Background()
				if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
					t.Fatal(err)
				}
				defaults := cloneAdditionDependencyDefaults(base.kernel.defaults)
				intents := 0
				options.fault = func(point string, index int) error {
					if point == "cleanup-intent" && index == 1 {
						intents++
						if runner.numericReads[4] == 0 || runner.numericReads[6] == 0 {
							t.Fatal("default intent preceded the complete two-family dependency check")
						}
						runner.arm(family, kind, state.Table)
					}
					return nil
				}
				before := len(base.calls)
				err := removePolicyAddition(ctx, runner, "ip", state, root, options)
				if !errors.Is(err, ErrPolicyAdditionUnknown) || !errors.Is(err, ErrPolicyDefaultReferenced) || intents != 1 || runner.numericReads[family] < 2 || len(additionDependencyDefaultDeletes(base.calls[before:])) != 0 {
					t.Fatal("late dependency passed the durable intent", err, base.calls[before:])
				}
				options.fault = nil
				assertAdditionDependencyHeld(t, state, root, options, runner, defaults, [2]string{"added", "added"})
				doc := readAdditionFixture(t, state, root, options)
				if (&policyAdditionSession{doc: doc}).status().Unknown {
					t.Fatal("definite pre-command refusal lost the original ACKed grant")
				}
				before = len(base.calls)
				if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(base.calls[before:])) != 0 {
					t.Fatal("fresh retry replayed a dependent intent", err, base.calls[before:])
				}
				// The temporary dependency vanishes independently. A retry can
				// use the original add ACK, without acquiring any foreign grant.
				if kind == "foreign" {
					base.kernel.entries = nil
				}
				runner.family, runner.kind, runner.row = 0, "", ""
				before = len(base.calls)
				if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err != nil || len(additionDependencyDefaultDeletes(base.calls[before:])) != 2 || len(base.kernel.defaults) != 0 || len(base.kernel.entries) != 0 {
					t.Fatal("cleanup did not recover after definite pre-command refusal", err, base.calls[before:])
				}
			})
		}
	}
}

func TestPolicyAdditionDefaultDependenciesFailedPreCommandRestoreStaysFenced(t *testing.T) {
	state, root, base, options := additionFixture(t)
	runner := &additionDefaultDependencyRunner{base: base}
	if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options.fault = func(point string, index int) error {
		if point == "cleanup-intent" && index == 1 {
			runner.arm(4, "foreign", state.Table)
			runner.afterNumericRead = func(family int) {
				if family == 4 {
					cancel() // also prevents the durable known-not-invoked restore
				}
			}
		}
		return nil
	}
	before := len(base.calls)
	if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, context.Canceled) || len(additionDependencyDefaultDeletes(base.calls[before:])) != 0 {
		t.Fatal("failed restore invoked delete", err, base.calls[before:])
	}
	options.fault, runner.afterNumericRead = nil, nil
	doc := readAdditionFixture(t, state, root, options)
	if doc.Steps[1].State != "cleanup-intent" || !(&policyAdditionSession{doc: doc}).status().Unknown {
		t.Fatal("failed save released the durable intent")
	}
	base.kernel.entries = nil
	runner.family, runner.kind = 0, ""
	before = len(base.calls)
	if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(additionDependencyDefaultDeletes(base.calls[before:])) != 1 || !strings.Contains(additionDependencyDefaultDeletes(base.calls[before:])[0], "ip route del") {
		t.Fatal("retry adopted readback after failed restore", err, base.calls[before:])
	}
	doc = readAdditionFixture(t, state, root, options)
	if doc.Steps[1].State != "cleanup-intent" || base.kernel.defaults["6/"+strconv.Itoa(state.Table)] == "" {
		t.Fatal("unknown IPv6 grant was reconstructed from readback")
	}
}

func TestPolicyAdditionDefaultDependenciesAbsentDefaultCannotSettleStop(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, missing := range []string{"first-default", "all-defaults"} {
			for _, kind := range []string{"foreign", "unknown", "read-failed"} {
				t.Run(fmt.Sprintf("IPv%d/%s/%s", family, missing, kind), func(t *testing.T) {
					state, root, base, options := additionFixture(t)
					runner := &additionDefaultDependencyRunner{base: base}
					ctx := context.Background()
					if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
						t.Fatal(err)
					}
					delete(base.kernel.defaults, "6/"+strconv.Itoa(state.Table))
					if missing == "all-defaults" {
						delete(base.kernel.defaults, "4/"+strconv.Itoa(state.Table))
					}
					defaults := cloneAdditionDependencyDefaults(base.kernel.defaults)
					runner.arm(family, kind, state.Table)
					before := len(base.calls)
					if err := removePolicyAddition(ctx, runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || !errors.Is(err, ErrPolicyDefaultReferenced) || len(additionDependencyDefaultDeletes(base.calls[before:])) != 0 {
						t.Fatal("missing default bypassed dependency refusal", err, base.calls[before:])
					}
					assertAdditionDependencyHeld(t, state, root, options, runner, defaults, [2]string{"added", "added"})
				})
			}
		}
	}
}

func TestPolicyAdditionDefaultDependenciesDifferentTableRemainsUntouched(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			state, root, base, options := additionFixture(t)
			runner := &additionDefaultDependencyRunner{base: base}
			ctx := context.Background()
			if err := applyPolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
				t.Fatal(err)
			}
			runner.arm(family, "different-table", state.Table+1)
			before := len(base.calls)
			if err := removePolicyAddition(ctx, runner, "ip", state, root, options); err != nil {
				t.Fatal("unrelated known selector retained owned defaults", err)
			}
			if len(base.kernel.defaults) != 0 || !reflect.DeepEqual(base.kernel.entries, []policyKernelEntry{runner.foreign}) || len(additionDependencyDefaultDeletes(base.calls[before:])) != 2 || runner.numericReads[4] != 4 || runner.numericReads[6] != 4 {
				t.Fatal("two-family cleanup changed the unrelated table", base.kernel, runner.numericReads)
			}
			doc := readAdditionFixture(t, state, root, options)
			if !(&policyAdditionSession{doc: doc}).status().Removed {
				t.Fatal("verified cleanup did not settle receipt")
			}
		})
	}
}

func TestPolicyAdditionDefaultDependenciesRollbackAfterDefaultACKRetainsBoth(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			state, root, base, options := additionFixture(t)
			runner := &additionDefaultDependencyRunner{base: base}
			options.fault = func(point string, index int) error {
				if point == "added" && index == 1 {
					runner.arm(family, "foreign", state.Table)
					return errors.New("failure after durable IPv6 default ACK")
				}
				return nil
			}
			if err := applyPolicyAddition(context.Background(), runner, "ip", state, root, options); err == nil || len(additionDependencyDefaultDeletes(base.calls)) != 0 || runner.numericReads[family] == 0 || len(base.kernel.defaults) != 2 {
				t.Fatal("in-call compensation dropped dependent defaults", err, base.calls)
			}
			options.fault = nil
			defaults := cloneAdditionDependencyDefaults(base.kernel.defaults)
			assertAdditionDependencyHeld(t, state, root, options, runner, defaults, [2]string{"added", "added"})
			before := len(base.calls)
			if err := removePolicyAddition(context.Background(), runner, "ip", state, root, options); !errors.Is(err, ErrPolicyAdditionUnknown) || len(receiptMutationCalls(base.calls[before:])) != 0 {
				t.Fatal("fresh cleanup converted failed compensation into authority", err, base.calls[before:])
			}
		})
	}
}
