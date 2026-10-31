//go:build !linux

package dataplane

import (
	"context"
	"net"
)

type domainTCPBaselineNative struct{}

func (*domainTCPBaselineNative) connection() net.Conn { return nil }

func (*domainTCPBaselineNative) closeNative() error { return ErrDomainTCPBaselineKernel }

func (*domainTCPBaselineExecutionResource) connectNative(context.Context) (*domainTCPBaselineNative, error) {
	return nil, ErrDomainTCPBaselineKernel
}
