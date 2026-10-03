package maintenancebatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixtures(outcomes []Outcome, errs []error) (Hooks, *[]string, *string) {
	var calls []string
	pending := ""
	i := 0
	h := Hooks{
		Guard: func(context.Context) error {
			if pending != "" {
				return ErrPending
			}
			return nil
		},
		Begin: func(_ context.Context, it Item) error {
			pending = it.ID
			calls = append(calls, "begin:"+it.ID)
			return nil
		},
		Update: func(_ context.Context, it Item) (Outcome, error) {
			calls = append(calls, "update:"+it.ID)
			n := i
			i++
			return outcomes[n], errs[n]
		},
		Finish: func(_ context.Context, it Item, _ Outcome) error {
			calls = append(calls, "finish:"+it.ID)
			pending = ""
			return nil
		},
	}
	return h, &calls, &pending
}
func items() []Item { return []Item{{"sing-box", "Sing-box", "sing-box-go"}, {"xray", "Xray", "xray"}} }
func TestUnknownRollbackStopsBatchAndRetainsReceipt(t *testing.T) {
	h, c, p := fixtures([]Outcome{Unknown}, []error{errors.New("rollback unconfirmed")})
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || !r.RecoveryRequired || *p != "sing-box" || len(*c) != 2 || strings.Contains(r.Message, "версии сохранены") {
		t.Fatal(r, *c, *p)
	}
	// Same durable receipt on the next invocation refuses BEFORE another update.
	before := len(*c)
	r = Run(context.Background(), items(), time.Second, h)
	if len(*c) != before || r.Complete {
		t.Fatal("retried unknown update", r, *c)
	}
}
func TestVerifiedRollbackIsNotFalseSuccess(t *testing.T) {
	h, c, p := fixtures([]Outcome{RolledBack, Updated}, []error{errors.New("new version failed"), nil})
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || r.RecoveryRequired || *p != "" || len(*c) != 6 || !strings.Contains(r.Message, "Откат подтверждён") {
		t.Fatal(r, *c)
	}
}
func TestFailedIntentDoesNotStartMutation(t *testing.T) {
	h, c, _ := fixtures(nil, nil)
	h.Begin = func(context.Context, Item) error { return errors.New("disk full") }
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || len(*c) != 0 {
		t.Fatal(r, *c)
	}
}
func TestFailedReceiptStopsFollowingMutation(t *testing.T) {
	h, c, _ := fixtures([]Outcome{Updated}, []error{nil})
	h.Finish = func(context.Context, Item, Outcome) error { return errors.New("fsync") }
	r := Run(context.Background(), items(), time.Second, h)
	if !r.RecoveryRequired || len(*c) != 2 {
		t.Fatal(r, *c)
	}
}
func TestWindowGuardRecheckedForEveryComponent(t *testing.T) {
	h, c, _ := fixtures([]Outcome{Updated}, []error{nil})
	n := 0
	h.Guard = func(context.Context) error {
		n++
		if n == 2 {
			return errors.New("window closed")
		}
		return nil
	}
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || len(*c) != 3 || n != 2 {
		t.Fatal(r, *c, n)
	}
}
func TestSharedPackageUpdatedOnce(t *testing.T) {
	h, c, _ := fixtures([]Outcome{Updated}, []error{nil})
	is := []Item{{"wireguard", "WG", "wireguard-tools"}, {"warp-wg", "WARP", "wireguard-tools"}}
	r := Run(context.Background(), is, time.Second, h)
	if !r.Complete || len(*c) != 3 {
		t.Fatal(r, *c)
	}
}
func TestErrorCannotMasqueradeAsUpdated(t *testing.T) {
	h, _, p := fixtures([]Outcome{Updated}, []error{errors.New("lost response")})
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || !r.RecoveryRequired || *p == "" {
		t.Fatal(r)
	}
}
func TestCancelledBeforeBatchHasNoWrites(t *testing.T) {
	h, c, _ := fixtures(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Run(ctx, items(), time.Second, h)
	if r.Complete || len(*c) != 0 {
		t.Fatal(r, *c)
	}
}
func TestNotStartedCanContinueButNotCompleteWindow(t *testing.T) {
	h, c, p := fixtures([]Outcome{NotStarted, Updated}, []error{errors.New("not installed"), nil})
	r := Run(context.Background(), items(), time.Second, h)
	if r.Complete || r.RecoveryRequired || *p != "" || len(*c) != 6 {
		t.Fatal(r, *c)
	}
}
