//go:build !linux

package dataplane

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// Routers use the Linux implementation. Other hosts retain test/tool execution
// support without claiming native Linux process-group ownership.
func nfqws2OwnedStopCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("NFQWS2 stop context unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	output, err := cmd.CombinedOutput()
	return output, errors.Join(err, ctx.Err())
}
