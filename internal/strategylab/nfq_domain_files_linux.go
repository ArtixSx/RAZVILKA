//go:build linux

package strategylab

import "syscall"

func nfqDomainReadFlags() int { return syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
