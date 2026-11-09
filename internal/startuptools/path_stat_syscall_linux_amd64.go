//go:build linux && amd64

package startuptools

import "syscall"

const freshPathStatSyscall = syscall.SYS_NEWFSTATAT
