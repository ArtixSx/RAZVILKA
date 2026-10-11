package startuptools

import (
	"bytes"
	"errors"
	"os/exec"
)

// Called only after the actual child is joined and the original source's
// closing check succeeds. Diagnostic bytes remain an errored read, never ACK.
func wgInactivityReadResult(stdout, stderr *output, commandErr, scopeErr error) ([]byte, error) {
	if stdout == nil || stderr == nil {
		return nil, at("WG_INACTIVITY_RESULT", scopeErr)
	}
	outOverflow := stdout.overflow || len(stdout.data) > maxOutputBytes
	errOverflow := stderr.overflow || len(stderr.data) > 4096
	if scopeErr != nil || outOverflow || errOverflow {
		return nil, at("WG_INACTIVITY_RESULT", errors.Join(scopeErr, commandResultFailure("WG_INACTIVITY_COMMAND", commandErr, nil, outOverflow, errOverflow, len(stderr.data) != 0)))
	}
	if commandErr == nil && len(stderr.data) == 0 {
		return bytes.Clone(stdout.data), nil
	}
	// Only a completed ordinary nonzero exit can supply a command diagnostic.
	// Signals, pipe/read failures, WaitDelay and success-with-stderr stay unknown.
	exit, ok := commandErr.(*exec.ExitError)
	if !ok || exit.ProcessState == nil || !exit.Exited() || exit.ExitCode() <= 0 {
		return nil, commandResultFailure("WG_INACTIVITY_COMMAND", commandErr, nil, false, false, len(stderr.data) != 0)
	}
	data := bytes.Clone(stdout.data)
	if len(data) > 0 && len(stderr.data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	if len(data)+len(stderr.data) > maxOutputBytes {
		return nil, at("WG_INACTIVITY_DIAGNOSTIC_LIMIT", commandErr)
	}
	data = append(data, stderr.data...)
	return data, commandResultFailure("WG_INACTIVITY_COMMAND", commandErr, nil, false, false, len(stderr.data) != 0)
}
