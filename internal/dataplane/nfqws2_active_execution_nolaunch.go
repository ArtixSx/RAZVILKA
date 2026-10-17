package dataplane

// Issued only by the original producer after it has returned from a refusal
// before resource admission. It is not a process-absence proof: retirement
// still requires the original fresh physical and journal observations.
type nfqws2ActiveNoLaunch struct {
	execution *nfqws2ActiveExecution
	command   string
}

// Caller holds e.mu. launchInvoked remains sticky for diagnostics and cannot
// itself authorize retirement.
func (e *nfqws2ActiveExecution) producerUnlaunched() bool {
	return e.noLaunch != nil && e.noLaunch.execution == e && e.material != nil &&
		e.noLaunch.command == nfqws2ActiveCommandDigest(e.material.command)
}

func (e *nfqws2ActiveExecution) unusedLaunch() bool {
	return !e.launchInvoked || e.producerUnlaunched()
}
