//go:build !linux

package dataplane

import "net"

func domainPolicyTCPCaptureSupported() bool { return false }

func observeDomainPolicyTCPSocket(*net.TCPConn) (DomainPolicyTCPSocket, error) {
	return DomainPolicyTCPSocket{}, ErrDomainPolicyTCPConsumer
}
