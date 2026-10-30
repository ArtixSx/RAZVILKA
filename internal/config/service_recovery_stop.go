package config

import (
	"reflect"
	"time"
)

// CommitServiceRecoveryStop is only the configuration publication of an
// explicitly reviewed, independently inactive degraded NFQWS2 Stop transaction.
// Caller must retain the Manager transaction and complete ownership review.
// The complete old image (including SafeMode) is restored by the normal undo.
func (s *Store) CommitServiceRecoveryStop(expected Config, resolved map[string]string) (func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.cfg, expected) || !s.cfg.SafeMode || s.cfg.ServiceControl.Stopped || s.cfg.Revision == ^uint64(0) {
		return nil, ErrRevisionChanged
	}
	return s.commitNFQWS2StopLocked(expected, resolved, time.Now())
}
