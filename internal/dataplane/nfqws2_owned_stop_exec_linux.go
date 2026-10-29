//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The admitted owned_stop init is foreground-only: it removes firewall rules
// and stops the previously identified daemon, never launches a new daemon.
// Give its shell and inherited foreground children one owned process group so
// parent cancellation does not leave an iptables -w child running after return.
func nfqws2OwnedStopCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("NFQWS2 stop context unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	// Bound output draining even if an unexpected descendant detached or retained
	// an inherited pipe. Such a result is an error and never inactivity evidence.
	cmd.WaitDelay = 250 * time.Millisecond
	output, err := cmd.CombinedOutput() // exactly one Run/Wait of the original parent
	return output, errors.Join(err, ctx.Err())
}
