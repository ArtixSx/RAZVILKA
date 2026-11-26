//go:build linux && arm64

package startuptools

import "syscall"

const freshPathStatSyscall = syscall.SYS_FSTATAT
