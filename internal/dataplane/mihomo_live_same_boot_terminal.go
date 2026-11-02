package dataplane

import (
	"bytes"
	"errors"
)

// Separate from the cold writer: preserve this original cursor's actual
// publication/Close distinction and keep both original slot FDs through retry.
func (c *mihomoSameBootRetirementCursor) publishTerminal(n int, current func() error) error {
	if c == nil || c.self != c {
		return ErrMihomoLiveRetirement
	}
	if c.closed || c.owner == nil || c.owner.inputs == nil || len(c.owner.inputs.records) < 2 || !c.owner.effectsClosed || n < 0 || n > 1 || current == nil || c.terminalCloseErr != nil {
		return errors.Join(ErrMihomoLiveRetirement, c.terminalCloseErr)
	}
	r := c.owner.inputs.records[n]
	var result error
	retryableACK := false
	if bytes.Equal(r.data, c.intent.After) {
		if !c.terminalPending[n] {
			return ErrMihomoLiveRetirement
		}
		readErr := r.current()
		syncErr := errors.Join(r.file.Sync(), syncBootRetirementDirectory(r.root, "."))
		closing := current()
		result = errors.Join(readErr, syncErr, closing)
		retryableACK = readErr == nil && closing == nil && syncErr != nil
	} else {
		f, err := writeMihomoColdRetained(r.root, r.name, c.intent.After, current)
		if f == nil {
			return err
		}
		old := r.file
		r.file, r.data = f, bytes.Clone(c.intent.After)
		var statErr error
		r.info, statErr = f.Stat()
		c.terminalPending[n] = true // Capture before ANY subsequent acknowledgment.
		c.terminalCloseErr = errors.Join(c.terminalCloseErr, old.Close())
		syncErr := syncBootRetirementDirectory(r.root, ".")
		readErr, closing := r.current(), current()
		result = errors.Join(err, statErr, c.terminalCloseErr, syncErr, readErr, closing)
		retryableACK = err == nil && statErr == nil && c.terminalCloseErr == nil && readErr == nil && closing == nil && syncErr != nil
		if result == nil && c.terminalFault != nil {
			result = c.terminalFault(n)
			retryableACK = result != nil
		}
	}
	if result == nil {
		c.terminalPending[n] = false
		if c.retryTerminal == n+1 {
			c.retryTerminal = 0
		}
	} else if retryableACK && c.terminalCloseErr == nil && r.current() == nil && current() == nil {
		c.retryTerminal = n + 1
	}
	return result
}
