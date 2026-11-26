//go:build !linux

package routeprobe

import "syscall"

func bindProbeSocket(syscall.RawConn, string) error {
	return errProbeInterfaceRoute
}
