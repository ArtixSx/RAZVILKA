//go:build !linux

package dataplane

import "context"

func (*NFQWS2Adapter) runManagedNFQWSProcess(context.Context, nfqws2ManagedProcessCommand, []string) (nfqws2ManagedProcessLease, error) {
	return nfqws2ManagedProcessLease{}, ErrNFQWSManagedProcessUnknown
}

func (*NFQWS2Adapter) runManagedNFQWSProcessWithAdmission(context.Context, nfqws2ManagedProcessCommand, []string, nfqws2ManagedProcessAdmission) (nfqws2ManagedProcessLease, error) {
	return nfqws2ManagedProcessLease{}, ErrNFQWSManagedProcessUnknown
}

func RunNFQWSManagedProcessSupervisor(string, string, string) int { return 1 }

func nfqws2ManagedObservationPath(string) error { return ErrNFQWSManagedProcessUnknown }

func (*NFQWS2Adapter) observeManagedNFQWSProcessRunning(context.Context) (nfqws2ManagedProcessLease, error) {
	return nfqws2ManagedProcessLease{}, ErrNFQWSManagedProcessUnknown
}
