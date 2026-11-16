package dataplane

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Private, pass-local read handles. The Linux platform supplies the only
// production factory; ordinary directory models are installed by tests only.
// These handles never carry runtime ownership or permission to act on a PID.
type inactiveProcFactory func(context.Context, string, int) (inactiveProcPass, error)

type inactiveProcPass interface {
	Entries() ([]os.DirEntry, error)
	OpenPID(int) (inactiveProcPID, error)
	GoneBeforeOpen(int) bool
	Close() error
}

type inactiveProcPID interface {
	Stat() ([]byte, error)
	Command() ([]byte, error)
	Executable() (string, error)
	Current() error
	Terminal() bool
	Close() error
}

// Closed internal distinction preserves existing diagnostic stages without
// exposing raw stat text, paths, birth values, or a reusable identity token.
type inactiveProcStatFailure struct{ birth bool }

func (e *inactiveProcStatFailure) Error() string { return "inactive process stat refused" }
func (e *inactiveProcStatFailure) Unwrap() error { return ErrProxyRuntimeInactive }

func inactiveProcOpenMissing(err error) bool {
	// Only a missing initial open, never a joined failure after acquiring an FD.
	return err == os.ErrNotExist || err == syscall.ENOENT
}

func inactiveProcRetireError(err error) bool {
	missing := false
	var visit func(error) bool
	visit = func(e error) bool {
		if e == nil {
			return true
		}
		if e == syscall.ENOENT || e == syscall.ESRCH || e == os.ErrNotExist {
			missing = true
			return true
		}
		if e == ErrProxyRuntimeInactive {
			return true
		}
		if many, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				if !visit(child) {
					return false
				}
			}
			return true
		}
		if one := errors.Unwrap(e); one != nil {
			return visit(one)
		}
		return false
	}
	return visit(err) && missing
}

func inactiveProcThreads(raw []byte, pid int) (byte, string, int, error) {
	state, _, ticks, err := proxyInactiveProcStat(raw, pid)
	if err != nil {
		return 0, "", 0, err
	}
	text := string(raw)
	fields := strings.Fields(text[strings.LastIndex(text, ")")+1:])
	threads, err := strconv.ParseUint(fields[17], 10, 32)
	if err != nil || threads == 0 || strconv.FormatUint(threads, 10) != fields[17] {
		return 0, "", 0, ErrProxyRuntimeInactive
	}
	return state, ticks, int(threads), nil
}
