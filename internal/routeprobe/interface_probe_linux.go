//go:build linux

package routeprobe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindProbeSocket(raw syscall.RawConn, device string) error {
	if raw == nil || device == "" {
		return errProbeInterfaceRoute
	}
	var bound bool
	err := raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			return
		}
		current, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		bound = err == nil && current == device
	})
	if err != nil || !bound {
		return errProbeInterfaceRoute
	}
	return nil
}
