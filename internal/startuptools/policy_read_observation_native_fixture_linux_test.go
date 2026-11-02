//go:build linux && amd64 && razvilka_native_fixture

package startuptools

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestStaticVersionFactNativePolicyReadObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l := staticFactNativeLease(t, ctx)
	foreign := staticFactNativeLease(t, ctx)
	tools, runner, err := l.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	_, foreignRunner, err := foreign.PolicyRuntimeTools()
	if err != nil {
		t.Fatal(err)
	}
	var expected [2][]byte
	for n, family := range []string{"-4", "-6"} {
		expected[n], err = runner.Run(ctx, tools.IP, family, "-N", "rule", "show")
		if err != nil {
			t.Fatal("ordinary original policy inspection", nativeStages(err))
		}
	}
	var late context.Context
	err = l.WithReadOnlyToolObservation(ctx, l.identity, l.digest, func(observed context.Context) error {
		late = observed
		for n, family := range []string{"-4", "-6"} {
			actual, e := runner.Run(observed, tools.IP, family, "-N", "rule", "show")
			if e != nil {
				return e
			}
			if !bytes.Equal(actual, expected[n]) {
				t.Fatal("actual original RPDB changed between pure reads")
			}
		}
		if _, e := foreignRunner.Run(observed, tools.IP, "-4", "-N", "rule", "show"); !errors.Is(e, ErrUnknown) {
			t.Fatal("foreign original lease borrowed view", e)
		}
		if _, e := runner.Run(observed, tools.IP, "-4", "rule", "add", "table", "173"); !errors.Is(e, ErrUnknown) {
			t.Fatal("mutation crossed readonly loan", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual policy read in original observation", nativeStages(err))
	}
	if _, err := runner.Run(late, tools.IP, "-4", "-N", "rule", "show"); !errors.Is(err, ErrUnknown) {
		t.Fatal("expired observation reused", err)
	}
	t.Log("actual original IPv4/IPv6 rule read output unchanged; foreign/expired original loan and mutation refused")
}
