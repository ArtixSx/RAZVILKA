package dataplane

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"time"
)

type backendInventoryOutput struct {
	data       []byte
	limit      int
	onOverflow func()
}

func (w *backendInventoryOutput) Write(data []byte) (int, error) {
	if w == nil || w.limit <= 0 || len(data) > w.limit-len(w.data) {
		if w != nil && w.onOverflow != nil {
			w.onOverflow()
		}
		return 0, errBackendInventory
	}
	needed := len(w.data) + len(data)
	if needed > cap(w.data) {
		capacity := min(w.limit, max(needed, max(1024, 2*cap(w.data))))
		next := make([]byte, len(w.data), capacity)
		copy(next, w.data)
		w.data = next
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

// Existing runner's additional fixed read seam, not a new execution owner.
// Both stdout and stderr share one bounded capture; a command error/overflow
// produces no rows. No fallback to the unbounded existing Run is permitted.
func (nfqws2ExecRunner) RunBounded(ctx context.Context, name string, limit int, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(name) || limit <= 0 || limit > backendClassicBytes || len(args) != 3 || args[0] != "-t" || args[2] != "-S" || !slices.Contains([]string{"raw", "mangle", "nat", "filter", "security"}, args[1]) {
		return nil, errBackendInventory
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > backendInventoryTimeout {
		return nil, errBackendInventory
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &backendInventoryOutput{limit: limit, onOverflow: cancel}
	command := exec.CommandContext(runCtx, name, args...)
	command.Stdout, command.Stderr = output, output
	// Bound inherited pipe draining even if an unexpected descendant holds it.
	command.WaitDelay = 100 * time.Millisecond
	if err := errors.Join(command.Run(), runCtx.Err(), ctx.Err()); err != nil {
		return nil, err
	}
	return output.data, nil
}
