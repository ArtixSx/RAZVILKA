package startuptools

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestWGStockNumericReadKeepsExactOriginalAdmission(t *testing.T) {
	// Unit mapping only: this callback models the original logical issuer.
	// It neither executes a process nor proves production tool admission.
	for _, args := range [][]string{{"-N", "rule", "show"}, {"-4", "-N", "rule", "show"}, {"-N", "-4", "rule", "show"}, {"-N", "-6", "rule", "show"}, {"-6", "-N", "rule", "show"}} {
		actual, ok := wgStockNumericRuleArguments(args)
		if !ok || slices.Contains(actual, "-N") || !slices.Equal(actual[len(actual)-2:], []string{"rule", "show"}) {
			t.Fatal("stock read mapping", args, actual)
		}
		original := slices.Clone(args)
		calls, starts := 0, 0
		ctx := WithCommandAdmission(context.Background(), admissionFunc(func(_ context.Context, name string, command []string, digest string, begin func() error) error {
			calls++
			if name != "/opt/sbin/ip" || digest != "original-held-review" || !slices.Equal(command, original) {
				t.Fatal("original issuer replaced", name, command, digest)
			}
			return begin()
		}))
		mapped, err := wgStockReadContext(ctx, "/opt/sbin/ip", "original-held-review", args, actual)
		if err != nil {
			t.Fatal(err)
		}
		args[0], actual[0] = "mutated logical argv", "mutated CLI argv"
		wrapper := mapped.Value(admissionKey{}).(commandAdmission).owner.(*wgStockRuleAdmission)
		for _, changed := range []struct {
			name, review string
			args         []string
		}{{"/other/ip", wrapper.review, wrapper.actual}, {wrapper.name, "caller-hash", wrapper.actual}, {wrapper.name, wrapper.review, []string{"route", "flush", "table", "main"}}} {
			if err := wrapper.WithStart(mapped, changed.name, changed.args, changed.review, func() error { starts++; return nil }); !errors.Is(err, ErrUnknown) {
				t.Fatal("changed actual stock command", err)
			}
		}
		if starts != 0 || calls != 0 {
			t.Fatal("changed read reached issuer", starts, calls)
		}
		if err := wrapper.WithStart(mapped, wrapper.name, wrapper.actual, wrapper.review, func() error { starts++; return nil }); err != nil {
			t.Fatal(err)
		}
		if starts != 1 || calls != 1 {
			t.Fatal("original mapped read", starts, calls)
		}
	}
	for _, args := range [][]string{{"-N", "rule", "add", "priority", "70"}, {"-N", "rule", "show", "table", "219"}, {"-j", "-N", "rule", "show"}, {"-4", "-N", "route", "show"}, {"rule", "show"}} {
		if _, ok := wgStockNumericRuleArguments(args); ok {
			t.Fatal("broadened stock read", args)
		}
	}
	if _, err := wgStockReadContext(context.Background(), "/opt/sbin/ip", "digest", nil, nil); !errors.Is(err, ErrUnknown) {
		t.Fatal("adapter issued its own admission", err)
	}
}
