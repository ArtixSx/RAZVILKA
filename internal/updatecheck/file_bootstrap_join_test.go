package updatecheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBootstrapQuiesceJoinRequiresOriginalWaitOwner(t *testing.T) {
	_, _, _, command, _ := bootstrapRoleFixture(t)
	a := &SelfUpdateFileAdapter{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if value, err := bootstrapQuiesceJoinFor(ctx, a, command, command.Supervisor.PID); value != nil || err != nil {
		t.Fatal("running receipt minted original join", err)
	}
	held, revoke := bootstrapJoinedQuiesceContext(a, ctx, command, 1)
	defer revoke()
	value, err := bootstrapQuiesceJoinFor(held, a, command, command.Supervisor.PID)
	if value == nil || err != nil {
		t.Fatal("original wait scope refused", err)
	}
	derived, stop := context.WithTimeout(held, time.Second)
	defer stop()
	if fresh, err := bootstrapQuiesceJoinFor(derived, a, command, command.Supervisor.PID); err != nil || fresh != value {
		t.Fatal("derived read lost original owner", err)
	}
	for _, kind := range []string{"copy", "other-adapter", "parent-caller", "child-caller", "changed-command", "reaped-receipt", "released", "cancelled", "expired", "wider-deadline", "ordinary-join", "ordinary-installer", "nil-marker", "foreign-marker"} {
		t.Run(kind, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			scope, release := bootstrapJoinedQuiesceContext(a, original, command, 1)
			defer release()
			w := scope.Value(bootstrapQuiesceJoinKey{}).(*bootstrapQuiesceJoin)
			adapter, changed, caller := a, command, command.Supervisor.PID
			switch kind {
			case "copy":
				copy := &bootstrapQuiesceJoin{self: w, adapter: w.adapter, original: w.original, deadline: w.deadline, command: w.command, reaped: w.reaped}
				copy.active.Store(true)
				scope = context.WithValue(original, bootstrapQuiesceJoinKey{}, copy)
			case "other-adapter":
				adapter = &SelfUpdateFileAdapter{}
			case "parent-caller":
				caller = command.Parent.PID
			case "child-caller":
				caller = command.DirectPID
			case "changed-command":
				changed.DirectPID++
			case "reaped-receipt":
				changed.State, changed.Reaped, changed.WaitECHILD = "reaped", 1, true
			case "released":
				release()
			case "cancelled":
				cancel()
			case "expired":
				w.deadline = time.Now().Add(-time.Second)
			case "wider-deadline":
				w.deadline = time.Now().Add(time.Second)
			case "ordinary-join":
				scope = context.WithValue(scope, ordinaryQuiesceJoinKey{}, &ordinaryQuiesceJoin{})
			case "ordinary-installer":
				scope = context.WithValue(scope, ordinaryInstallerJoinKey{}, &ordinaryInstallerJoin{})
			case "nil-marker":
				scope = context.WithValue(scope, bootstrapQuiesceJoinKey{}, (*bootstrapQuiesceJoin)(nil))
			case "foreign-marker":
				scope = context.WithValue(scope, bootstrapQuiesceJoinKey{}, "foreign")
			}
			if value, err := bootstrapQuiesceJoinFor(scope, adapter, changed, caller); value != nil || !errors.Is(err, ErrInstallerControllerRole) {
				t.Fatal("invalid original wait accepted", err)
			}
		})
	}
}

func TestBootstrapQuiesceJoinCannotBeIssuedFromReceiptOrUnboundedContext(t *testing.T) {
	_, _, _, command, _ := bootstrapRoleFixture(t)
	a := &SelfUpdateFileAdapter{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, kind := range []string{"nil", "unbounded", "no-wait", "terminal-receipt", "ordinary", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			original, changed, reaped := ctx, command, 1
			switch kind {
			case "nil":
				original = nil
			case "unbounded":
				original = context.Background()
			case "no-wait":
				reaped = 0
			case "terminal-receipt":
				changed.State, changed.Reaped, changed.WaitECHILD = "reaped", 1, true
			case "ordinary":
				original = context.WithValue(ctx, ordinaryQuiesceJoinKey{}, &ordinaryQuiesceJoin{})
			case "duplicate":
				original = context.WithValue(ctx, bootstrapQuiesceJoinKey{}, "foreign")
			}
			held, release := bootstrapJoinedQuiesceContext(a, original, changed, reaped)
			defer release()
			if held != original {
				t.Fatal("invalid producer minted witness")
			}
		})
	}
}
