//go:build linux

package dataplane

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func nodeRouterDeviceBindingAvailable() bool { return true }

func nodeRouterSystemBindSocket(raw syscall.RawConn, device string) error {
	return nodeRouterCheckedSocketBinding(raw, device,
		func(fd int, name string) error {
			return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		},
		func(fd int) (string, error) { return unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE) })
}
