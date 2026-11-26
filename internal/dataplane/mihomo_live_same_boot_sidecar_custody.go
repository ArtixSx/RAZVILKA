package dataplane

import (
	"errors"
	"os"
)

// Native PID descriptor custody only, never reconstructed from a saved PID.
// The original five-lease scope closes it after terminal observation or error.
type mihomoSameBootSidecar struct {
	self                                   *mihomoSameBootSidecar
	original                               *mihomoSameBootStatic
	file                                   *os.File
	pid                                    int
	receipt                                string
	validated, attempted, terminal, closed bool
	closeErr                               error
}

func (s *mihomoSameBootSidecar) close() error {
	if s == nil || s.self != s {
		return ErrMihomoLiveRetirement
	}
	if !s.closed {
		s.closed = true
		if s.file != nil {
			s.closeErr = errors.Join(s.closeErr, s.file.Close())
		}
	}
	return s.closeErr
}
