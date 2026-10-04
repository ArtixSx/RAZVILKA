//go:build !linux

package dataplane

import "syscall"

func nodeRouterDeviceBindingAvailable() bool { return false }

func nodeRouterSystemBindSocket(syscall.RawConn, string) error {
	return errNodeRouterHTTPSUnavailable
}
