// Package commandrun bounds diagnostic subprocesses, including output pipes
// inherited by descendants. It is not a controller for long-lived runtimes.
package commandrun

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

var ErrOutputLimit = errors.New("diagnostic command output limit exceeded")

// Output returns at most limit bytes. A timeout or truncated output is never
// considered successful evidence, even if the retained prefix looks healthy.
func Output(ctx context.Context, timeout time.Duration, limit int, binary string, args ...string) ([]byte, error) {
	if timeout <= 0 || limit <= 0 {
		return nil, errors.New("diagnostic command requires positive time and output limits")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output := &boundedOutput{limit: limit}
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout, command.Stderr = output, output
	// Killing a script does not close pipes held by its children. Bound that
	// wait as well; never let a status/version request hang the UI indefinitely.
	command.WaitDelay = 100 * time.Millisecond
	err := command.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if output.exceeded {
		err = ErrOutputLimit
	}
	return output.data, err
}

type boundedOutput struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - len(b.data)
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}
