//go:build !linux

package dataplane

import (
	"context"
	"net"
)

func (*domainTCPDirectScope) connect(context.Context) (net.Conn, error) {
	return nil, ErrDomainTCPBaselineKernel
}
