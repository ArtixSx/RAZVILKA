package dnscontrol

import (
	"math"
	"reflect"
)

// ServiceSelectionReview is a bounded settings snapshot for the existing
// dataplane transaction journal. It contains no credentials, probe PASS or
// independent execution authority. Target may retain the applied selection,
// use the saved draft or remove the binding (empty string).
type ServiceSelectionReview struct {
	ServiceID       string `json:"service_id"`
	Draft           string `json:"draft"`
	Applied         string `json:"applied"`
	Target          string `json:"target"`
	Revision        uint64 `json:"revision"`
	ProfileIdentity string `json:"profile_identity,omitempty"`
}

// ServiceSelectionReceipt can be saved BEFORE CommitServiceSelection: its
// generation is deterministic. Recovery can undo a completed write or a
// write that never happened without overwriting a later transaction.
type ServiceSelectionReceipt struct {
	Review   ServiceSelectionReview `json:"review"`
	Revision uint64                 `json:"revision"`
}

func (m *Manager) ReviewServiceSelection(serviceID, target string) (ServiceSelectionReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return serviceSelectionReview(m.doc, serviceID, target)
}

func serviceSelectionReview(doc document, serviceID, target string) (ServiceSelectionReview, error) {
	r := ServiceSelectionReview{ServiceID: serviceID, Draft: doc.ServiceDrafts[serviceID], Applied: doc.ServiceApplied[serviceID], Target: target, Revision: doc.ServiceRevisions[serviceID]}
	if !validServiceID(serviceID) || doc.Applied.ProfileID != "automatic" || target != "" && target != r.Draft && target != r.Applied {
		return r, ErrServiceDNSChanged
	}
	if target != "" {
		var err error
		// Stop may preserve a configured choice even if its credentials were
		// removed in the editor. Eligibility is checked by the runtime adapter
		// before activation; retaining settings must not prevent cleanup.
		r.ProfileIdentity, err = profileDefinitionIdentity(doc, target, target != r.Applied)
		if err != nil {
			return r, err
		}
	}
	if r.Revision > math.MaxUint64-2 { // reserve one generation for undo
		return r, ErrServiceDNSChanged
	}
	return r, nil
}

func (r ServiceSelectionReview) Receipt() ServiceSelectionReceipt {
	revision := r.Revision
	if r.Target != r.Applied {
		revision++
	}
	return ServiceSelectionReceipt{Review: r, Revision: revision}
}

func (m *Manager) CheckServiceSelection(r ServiceSelectionReview) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	current, err := serviceSelectionReview(m.doc, r.ServiceID, r.Target)
	if err != nil || !reflect.DeepEqual(current, r) {
		return ErrServiceDNSChanged
	}
	return nil
}

func (m *Manager) CheckCommittedServiceSelection(receipt ServiceSelectionReceipt) error {
	if receipt != receipt.Review.Receipt() {
		return ErrServiceDNSChanged
	}
	r := receipt.Review
	r.Applied, r.Revision = r.Target, receipt.Revision
	return m.CheckServiceSelection(r)
}

// CommitServiceSelection changes only the applied binding. Drafts, unrelated
// services, provider configuration and probe telemetry retain their values.
// The caller must first activate and verify the matching client policy.
func (m *Manager) CommitServiceSelection(r ServiceSelectionReview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := serviceSelectionReview(m.doc, r.ServiceID, r.Target)
	if err != nil || !reflect.DeepEqual(current, r) {
		return ErrServiceDNSChanged
	}
	if r.Target == r.Applied {
		return nil
	}
	return m.setServiceAppliedLocked(r.ServiceID, r.Target, r.Receipt().Revision)
}

func (m *Manager) setServiceAppliedLocked(id, profile string, revision uint64) error {
	previous := cloneDocument(m.doc)
	if m.doc.ServiceApplied == nil {
		m.doc.ServiceApplied = map[string]string{}
	}
	if m.doc.ServiceRevisions == nil {
		m.doc.ServiceRevisions = map[string]uint64{}
	}
	if profile == "" {
		delete(m.doc.ServiceApplied, id)
	} else {
		m.doc.ServiceApplied[id] = profile
	}
	m.doc.ServiceRevisions[id] = revision
	if err := m.saveLocked(); err != nil {
		m.doc = previous
		return err
	}
	return nil
}

// RestoreServiceSelection is generation-checked and idempotent. A new draft
// stays available after rollback. A later applied change (including A→B→A)
// is never mistaken for this transaction's write.
func (m *Manager) RestoreServiceSelection(receipt ServiceSelectionReceipt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := receipt.Review
	if !validServiceID(r.ServiceID) || r.Revision > math.MaxUint64-2 || receipt != r.Receipt() {
		return ErrServiceDNSChanged
	}
	if r.Applied != "" {
		if _, ok := profileByID(r.Applied); !ok {
			return ErrServiceDNSChanged
		}
	}
	current, revision := m.doc.ServiceApplied[r.ServiceID], m.doc.ServiceRevisions[r.ServiceID]
	if current == r.Applied && (revision == r.Revision || revision == receipt.Revision+1 && r.Target != r.Applied) {
		return nil // write never happened, or this undo already completed
	}
	if current != r.Target || revision != receipt.Revision || r.Target == r.Applied {
		return ErrServiceDNSChanged
	}
	return m.setServiceAppliedLocked(r.ServiceID, r.Applied, revision+1)
}

// VerifyServiceSelection reads applied state only. A settings record does
// not claim that a resolver is listening or that the service is reachable.
func (m *Manager) VerifyServiceSelection(serviceID, profileID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !validServiceID(serviceID) || m.doc.ServiceApplied[serviceID] != profileID {
		return ErrServiceDNSChanged
	}
	return nil
}
