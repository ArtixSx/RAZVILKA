//go:build !linux

package dataplane

import "context"

func (*NFQWS2Adapter) startPreparedNFQWSProcess(context.Context, context.Context, nfqws2ActiveProcessCommand, []string, nfqws2ActiveProcessAdmission) (*NFQWSPreparedHandle, error) {
	return nil, ErrNFQWSManagedProcessUnknown
}
