package dataplane

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// SuspendedDNS reads the exact policy saved by the successful Stop transaction.
// No second configuration store is introduced. The caller must still compare
// the service definition/scope and build a fresh network-bound plan; this is
// saved intent, never a successful current probe or permission to activate.
func (m *Manager) SuspendedDNS(expected Plan) (*ScopedDNSPlan, error) {
	state, err := m.suspendedDNSState(expected)
	if err != nil {
		return nil, err
	}
	return state.DNS, nil
}

func (m *Manager) suspendedDNSState(expected Plan) (*scopedDNSState, error) {
	if !expected.SuspendDNS || expected.DNS != nil || len(expected.Routes) != 0 || expected.State != "committed" || !slices.Contains(expected.RetiringAdapters, scopedDNSAdapterID) || len(expected.PlanID) != 19 || !strings.HasPrefix(expected.PlanID, "dp-") || strings.Trim(expected.PlanID[3:], "0123456789abcdef") != "" {
		return nil, errors.New("no committed DNS suspension")
	}
	if err := m.checkExecutionRecovery(); err != nil {
		return nil, err
	}
	current, exists, err := m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return nil, ErrReviewChanged
	}
	data, err := readScopedDNSFile(filepath.Join(m.StateRoot, "transactions", expected.PlanID, scopedDNSAdapterID, "snapshot.json"))
	if err != nil {
		return nil, err
	}
	var saved scopedDNSSnapshot
	if json.Unmarshal(data, &saved) != nil || !validScopedDNSSnapshotState(saved) || saved.settingsScope() == nil || validateScopedSettingsSnapshot(saved, nil, true) != nil {
		return nil, errors.New("suspended DNS snapshot is invalid")
	}
	current, exists, err = m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return nil, ErrReviewChanged
	}
	return saved.settingsScope(), nil
}
