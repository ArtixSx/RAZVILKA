//go:build !linux

package dataplane

import (
	"errors"
	"syscall"
)

func wgBindSocket(string) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("WireGuard device-bound probes require Linux")
	}
}
