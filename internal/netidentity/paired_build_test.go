package netidentity

import (
	"context"
	"testing"
	"time"
)

func TestProviderPairedBuildDoesNotSpanCallerAndStillRefusesDrift(t *testing.T) {
	for _, drift := range []bool{false, true} {
		p := modelProvider(false, true)
		pairs, callback := 0, false
		p.build = func(context.Context) (buildTuple, error) {
			t.Fatal("paired provider reopened individual image graph")
			return buildTuple{}, ErrUnknown
		}
		p.buildPair = func(ctx context.Context) (buildTuple, buildTuple, error) {
			pairs++
			if (pairs == 1 && callback) || (pairs == 2 && !callback) {
				t.Fatal("metadata session crossed caller boundary")
			}
			deadline, finite := ctx.Deadline()
			if !finite || time.Until(deadline) > 2*time.Second {
				t.Fatal("paired leaf expanded original budget")
			}
			before, after := nc1812Profile().Build, nc1812Profile().Build
			if drift && pairs == 2 {
				after.Model += "changed"
			}
			return before, after, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := p.WithCurrent(ctx, func(context.Context, Identity) error { callback = true; return nil })
		cancel()
		if pairs != 2 || (err != nil) != drift {
			t.Fatalf("closing pair drift=%t pairs=%d err=%v", drift, pairs, err)
		}
	}
}
