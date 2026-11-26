package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type policyEffectInvocationTestRunner func(context.Context, string, ...string) ([]byte, error)

func (f policyEffectInvocationTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

// Genuine COMMON writer/parser/files and per-RPC scopes, explicit kernel model.
func TestPolicyEffectCommandInvocationAddRemoveOneUseAndEscapedContext(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var escaped context.Context
	starts, deletes := 0, 0
	f.runtime.Guard = func(c context.Context, _ int) error {
		if _, err := observePolicyEffectCommandInvocation(c, f.plan, f.root, "ip", []string{"-4", "rule", "show"}); !errors.Is(err, ErrPolicyAdditionReceipt) {
			t.Fatal("guard manufactured per-RPC issuer", err)
		}
		return nil
	}
	f.runtime.Runner = policyEffectInvocationTestRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
		i, err := observePolicyEffectCommandInvocation(c, f.plan, f.root, name, args)
		if err != nil {
			t.Fatal("original exact per-RPC issuer", err)
		}
		escaped = c
		for _, wrong := range []struct {
			name, root string
			args       []string
		}{
			{name + "-foreign", f.root, args}, {name, f.root + "-foreign", args}, {name, f.root, append(append([]string(nil), args...), "foreign")},
		} {
			if _, err := observePolicyEffectCommandInvocation(c, f.plan, wrong.root, wrong.name, wrong.args); !errors.Is(err, ErrPolicyAdditionReceipt) {
				t.Fatal("foreign command/root acquired issuer", err)
			}
		}
		copy := &policyEffectCommandInvocation{self: i.self, session: i.session, tools: i.tools, index: i.index, cleanup: i.cleanup, open: true}
		copiedContext := context.WithValue(c, policyEffectCommandInvocationKey{}, copy)
		if err := copy.withStart(copiedContext, func() error { t.Fatal("copied issuer started"); return nil }); !errors.Is(err, ErrPolicyAdditionReceipt) {
			t.Fatal(err)
		}
		if err := i.withStart(c, func() error {
			starts++
			if i.cleanup {
				deletes++
			}
			return nil
		}); err != nil {
			t.Fatal("original intent failed", err)
		}
		if err := i.withStart(c, func() error { t.Fatal("per-RPC issuer repeated Start"); return nil }); !errors.Is(err, ErrPolicyAdditionReceipt) {
			t.Fatal(err)
		}
		return f.Run(c, name, args...)
	})
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal(err)
	}
	if _, err := observePolicyEffectCommandInvocation(escaped, f.plan, f.root, f.calls[0].name, f.calls[0].args); !errors.Is(err, ErrPolicyAdditionReceipt) {
		t.Fatal("escaped Apply issuer revived", err)
	}
	if err := removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal("actual Remove borrowed original writer", err)
	}
	if starts != 2*len(f.plan.Effects) || deletes != len(f.plan.Effects) {
		t.Fatal("missing Add/Delete command coverage", starts, deletes)
	}
	status, err := inspectPolicyEffects(ctx, f.plan, f.root, f.options)
	if err != nil || !status.Removed || status.Unknown {
		t.Fatal("cleanup settlement", status, err)
	}
	last := f.calls[len(f.calls)-1]
	if _, err := observePolicyEffectCommandInvocation(escaped, f.plan, f.root, last.name, last.args); !errors.Is(err, ErrPolicyAdditionReceipt) {
		t.Fatal("escaped Remove issuer revived", err)
	}
}

func TestPolicyEffectCommandInvocationRefusesForgedCleanupImageBeforeStart(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil {
		t.Fatal(err)
	}
	f.runtime.Runner = policyEffectInvocationTestRunner(func(c context.Context, name string, args ...string) ([]byte, error) {
		i, err := observePolicyEffectCommandInvocation(c, f.plan, f.root, name, args)
		if err != nil || !i.cleanup {
			t.Fatal("original cleanup intent", err)
		}
		data, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
		if err != nil {
			t.Fatal(err)
		}
		var forged policyAdditionDocument
		if err := json.Unmarshal(data, &forged); err != nil {
			t.Fatal(err)
		}
		forged.ID = "ffffffffffffffffffffffffffffffff"
		forged.Checksum = policyAdditionChecksum(forged)
		data, _ = json.Marshal(forged)
		if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), data, 0600); err != nil {
			t.Fatal(err)
		}
		return nil, i.withStart(c, func() error { t.Fatal("forged original cleanup image reached Start"); return nil })
	})
	before := len(f.calls)
	if err := removePolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); !errors.Is(err, ErrPolicyAdditionReceipt) || len(f.calls) != before {
		t.Fatal("forged receipt admitted Delete", err, f.calls)
	}
}
