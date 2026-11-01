package dataplane

import "testing"

// Pointer/slot model only. No native owner, cleanup or known standby proof is
// constructed. The real unpublished fixture covers the subsequent writer.
func TestDomainStandbyPendingReservationReleasesWriterMutex(t *testing.T) {
	m := &Manager{}
	original := &DomainTCPOriginalScope{}
	original.self = original
	s := &executionResourceScope{manager: m, domainTCPOwner: original}
	records := &xraySelectedTCPExecutionRecords{scope: s}
	p := &XrayDomainTCPExecutionResource{scope: s, records: records}
	p.self = p
	original.process = p
	owner := &domainTCPStandbyOwner{original: original, process: p}
	owner.self = owner
	r := &retainedXrayExecution{scope: s, records: records, standby: owner, pending: true}
	r.self = r
	if err := m.reservePendingDomainStandby(r); err != nil {
		t.Fatal(err)
	}
	if !m.retainedXrayMu.TryLock() {
		t.Fatal("pending reservation held mutex required by actual journal writer")
	}
	if m.retainedXray != r || !r.pending {
		m.retainedXrayMu.Unlock()
		t.Fatal("reservation lost original cleanup-only custody")
	}
	m.retainedXrayMu.Unlock()
	if m.reservePendingDomainStandby(r) == nil || m.retainedXrayOwner() != r || !r.pending {
		t.Fatal("duplicate reservation replaced or promoted original owner")
	}
	copy := *r
	other := &Manager{}
	if other.reservePendingDomainStandby(&copy) == nil || other.retainedXrayOwner() != nil {
		t.Fatal("copied original pending owner admitted")
	}
}
