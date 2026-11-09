//go:build linux

package updatecheck

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestBootstrapJoinedChildAbsenceRequiresActualReaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := fileCommandReceipt{DirectPID: os.Getpid()}
	if bootstrapJoinedChildAbsent(ctx, command) == nil {
		t.Fatal("live or reused PID treated as absent")
	}
	child := exec.CommandContext(ctx, "/bin/true")
	if err := child.Run(); err != nil || child.ProcessState == nil {
		t.Fatal("actual child not joined", err)
	}
	command.DirectPID = child.Process.Pid
	if err := bootstrapJoinedChildAbsent(ctx, command); err != nil {
		t.Fatal("joined child still present", err)
	}
	cancel()
	if bootstrapJoinedChildAbsent(ctx, command) == nil {
		t.Fatal("canceled absence accepted")
	}
}

func TestBootstrapOriginalAdapterRejectsReconstructedAndForeignOwners(t *testing.T) {
	_, _, _, command, _ := bootstrapRoleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if adapter, err := OriginalBootstrapInstallerControllerAdapter(ctx, command.ID); err != nil || adapter != nil {
		t.Fatal("cold receipt became owner", err)
	}
	command.Supervisor.PID = os.Getpid()
	a := &SelfUpdateFileAdapter{installation: "/tmp/foreign"}
	held, release := bootstrapJoinedQuiesceContext(a, ctx, command, 1)
	defer release()
	if adapter, err := OriginalBootstrapInstallerControllerAdapter(held, command.ID); err == nil || adapter != nil {
		t.Fatal("custom root became production original adapter")
	}
}
