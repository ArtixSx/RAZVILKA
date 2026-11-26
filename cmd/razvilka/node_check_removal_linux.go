//go:build linux

package main

import (
	"errors"
	"syscall"
)

// No bind/listen or namespace change. Only a kernel EAFNOSUPPORT proves the
// unavailable family; permission, resource and other failures prove nothing.
func exactNodeIPv6Unavailable() bool {
	return exactNodeIPv6UnavailableWithSocket(func() (int, error) {
		return syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	}, syscall.Close)
}

func exactNodeIPv6UnavailableWithSocket(socket func() (int, error), close func(int) error) bool {
	fd, err := socket()
	if err != nil {
		return errors.Is(err, syscall.EAFNOSUPPORT)
	}
	_ = close(fd)
	return false
}
