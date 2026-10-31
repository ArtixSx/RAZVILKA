package dataplane

import (
	"errors"
	"path/filepath"
)

// Reuse the existing original authored-record FD/bytes reader; it contains no
// Xray launch authority. Both files are authored through their SAME held roots,
// including after failed socket cleanup. No retry reopens a named directory.
func newNFQWSProbeRecords(s *executionResourceScope) (*xraySelectedTCPExecutionRecords, error) {
	if s == nil || s.execution == nil || s.manager == nil || s.managerRoot != s.manager.StateRoot || s.root != filepath.Join(s.managerRoot, "transactions", s.execution.PlanID) {
		return nil, ErrExecutionJournal
	}
	d := &xraySelectedTCPExecutionRecords{scope: s}
	var err error
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(s.managerRoot)
	if err == nil {
		d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(s.root)
	}
	if err != nil {
		return nil, errors.Join(err, d.close())
	}
	return d, nil
}

func (e *nfqwsProbeExecution) publishRecords(data []byte) error {
	if e == nil || e.self != e || e.records == nil || e.resource == nil || e.records.scope != e.resource.scope {
		return ErrExecutionJournal
	}
	d := e.records
	if err := d.beforePublication(); err != nil {
		return err
	}
	var result error
	for i := range 2 {
		root, name := d.recordPath(i)
		file, err := root.WriteAtomicRetained(name, data, 0600)
		if err == nil {
			info, statErr := file.Stat()
			err = statErr
			if err == nil {
				err = d.captureOriginalRecord(i, file, info, data, root, name)
			}
			if err != nil {
				_ = file.Close()
			}
		}
		result = errors.Join(result, err)
	}
	return result
}
