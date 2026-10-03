package strategylab

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

var ErrCompatibilityQuiescenceUnknown = errors.New("NFQWS compatibility process quiescence is unknown")

var errCompatibilityBusy = errors.New("NFQWS validation/probe is busy")

func (m *Manager) finishNative() {
	m.mu.Lock()
	m.nativeRunning = false
	m.mu.Unlock()
}

// Completion is returned by a trusted provider, never by CLI/HTTP input.
// Quiescent requires proof for this exact invocation and all descendants.
// A zero exit, PID absence, empty process scan or closed pipes is insufficient.
type CompatibilityCompletion struct {
	Output    []byte
	Started   bool
	Quiescent bool
}

type CompatibilityProvider interface {
	Run(context.Context, string, ...string) (CompatibilityCompletion, error)
}

// Call only while holding Manager.mu. The existing private candidate state
// retains unknown; a delete/reimport or subsequent validation cannot clear it.
func (m *Manager) compatibilityUnknownLocked() bool {
	if m.compatibilityUnknown || m.state.SchemaVersion == compatibilityUnknownSchema {
		return true
	}
	for _, candidate := range m.state.Candidates {
		if candidate.Validation.QuiescenceUnknown {
			return true
		}
	}
	return false
}

const (
	compatibilityCleanupWait   = time.Second
	compatibilityUnknownSchema = 2
)

// CompatibilityProcessProvider bounds direct-process and pipe waiting, but
// deliberately NEVER awards descendant quiescence after a process was started.
// It retains an unknown fence even after a zero exit or eventual child cleanup.
// This is a conservative concrete provider, not the package/opkg supervisor.
// A fresh provider must not be used to bypass an unknown invocation.
type CompatibilityProcessProvider struct {
	mu      sync.Mutex
	running bool
	unknown bool
}

func (p *CompatibilityProcessProvider) Run(parent context.Context, binary string, args ...string) (result CompatibilityCompletion, err error) {
	p.mu.Lock()
	if p.unknown {
		p.mu.Unlock()
		return result, ErrCompatibilityQuiescenceUnknown
	}
	if p.running {
		p.mu.Unlock()
		return CompatibilityCompletion{Quiescent: true}, errors.New("compatibility provider is busy")
	}
	if err := parent.Err(); err != nil {
		p.mu.Unlock()
		return CompatibilityCompletion{Quiescent: true}, err
	}
	p.running = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		if !result.Quiescent {
			p.unknown = true
			err = errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		p.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()
	var output compatibilityOutput
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.WaitDelay = compatibilityCleanupWait / 2
	type completed struct {
		started bool
		err     error
	}
	done := make(chan completed, 1)
	go func() {
		err := cmd.Start()
		started := err == nil
		if started {
			err = cmd.Wait()
		}
		done <- completed{started: started, err: err}
	}()
	finish := func(r completed) (CompatibilityCompletion, error) {
		// Direct Wait only reaps its own child. Do not infer tree quiescence.
		return CompatibilityCompletion{Output: output.snapshot(), Started: r.started, Quiescent: !r.started}, r.err
	}
	select {
	case r := <-done:
		return finish(r)
	case <-ctx.Done():
		// WaitDelay covers inherited pipes; the outer limit also bounds a
		// blocked Start/Wait. Such a pending launch is unknown, not not-started.
		timer := time.NewTimer(compatibilityCleanupWait)
		defer timer.Stop()
		select {
		case r := <-done:
			result, err := finish(r)
			return result, errors.Join(ctx.Err(), err)
		case <-timer.C:
			return CompatibilityCompletion{Output: output.snapshot()}, ctx.Err()
		}
	}
}

type compatibilityOutput struct {
	mu     sync.Mutex
	buffer boundedBuffer
}

func (b *compatibilityOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *compatibilityOutput) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}
