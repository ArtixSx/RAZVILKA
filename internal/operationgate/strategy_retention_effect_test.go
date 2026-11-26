package operationgate

import (
	"context"
	"errors"
	"testing"
)

func TestStrategyRetentionSealPreservesStopAndCannotGrantStart(t *testing.T) {
	ctx, path := context.Background(), controlTestRoot(t)
	ready, err := InitializeSelfUpdateControl(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RequestSelfUpdateStop(ctx, path, controlTestID, 12); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"stop-owned", "replace-to-rollback", "start/live", "read/observe"} {
		called := false
		err := WithSelfUpdateStoppedEffectAdmission(ctx, path, controlTestID, ready.InstallationID, ready.Sequence, 12, action, "strategy-rollback-retention-seal", func() error { called = true; return nil })
		if action == "stop-owned" {
			if err != nil || !called {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrSelfUpdateStopChanged) || called {
			t.Fatal("metadata retention granted another effect class", action, err)
		}
	}
	if stopped, present, err := ReadSelfUpdateStop(ctx, path); err != nil || !present || !stopped.Stopped || stopped.Sequence != ready.Sequence+1 {
		t.Fatal("retention changed explicit Stop", err)
	}
}
