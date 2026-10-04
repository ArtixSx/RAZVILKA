package dataplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNodeTransitRegistrationRemovalAuthorityCannotReachApplyRetry(t *testing.T) {
	l, runner, _ := nodeTransitFixture(t)
	ctx := context.WithValue(context.Background(), nodeTransitRemovalKey{}, true)
	ctx = context.WithValue(ctx, nodeTransitCleanupKey{}, true)
	var removalModes []bool
	register := l.runtime.register
	refuse := errors.New("forward WAN freshness refused")
	l.runtime.register = func(ctx context.Context, spec NodeTransitSpec, root, digest string) error {
		removal, ok := ctx.Value(nodeTransitRemovalKey{}).(bool)
		if !ok {
			t.Fatal("lease omitted its explicit registration mode")
		}
		removalModes = append(removalModes, removal)
		if cleanup, _ := ctx.Value(nodeTransitCleanupKey{}).(bool); !cleanup {
			t.Fatal("registration mode changed independent cleanup guard scope")
		}
		if !removal {
			return refuse
		}
		return register(ctx, spec, root, digest)
	}
	first := l.Apply(ctx)
	if !errors.Is(first, refuse) || !isNodeTransitBeforeEffects(first) {
		t.Fatal("first forward refusal lost its before-effects classification", first)
	}
	if err := l.Apply(ctx); !errors.Is(err, refuse) || isNodeTransitBeforeEffects(err) {
		t.Fatal("retry borrowed removal authority or unused classification", err)
	}
	if !reflect.DeepEqual(removalModes, []bool{false, false}) || runner.adds != 0 || runner.deletes != 0 {
		t.Fatal("forward retry acquired held-scope cleanup registration", removalModes, runner.adds, runner.deletes)
	}
}

func TestNodeTransitRegistrationRemoveUsesOnlyExistingResourceMode(t *testing.T) {
	l, runner, _ := nodeTransitFixture(t)
	var removalModes []bool
	register := l.runtime.register
	l.runtime.register = func(ctx context.Context, spec NodeTransitSpec, root, digest string) error {
		removal, ok := ctx.Value(nodeTransitRemovalKey{}).(bool)
		if !ok {
			t.Fatal("lease omitted its explicit registration mode")
		}
		removalModes = append(removalModes, removal)
		return register(ctx, spec, root, digest)
	}
	ctx := context.WithValue(context.Background(), nodeTransitRemovalKey{}, false)
	if err := l.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove(ctx); err != nil {
		t.Fatal("existing resource cleanup retry failed", err)
	}
	if !reflect.DeepEqual(removalModes, []bool{false, true, true}) || runner.adds != 1 || runner.deletes != 1 {
		t.Fatal("Remove lost existing-resource mode or repeated kernel mutation", removalModes, runner.adds, runner.deletes)
	}
}
