//go:build linux

package components

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

type mihomoProbeNativeLinux struct {
	command                    *exec.Cmd
	control                    *operationgate.ControlEpochReview
	cleanupReview              *operationgate.ExclusiveCleanupReview
	binary, profile, directory *os.File
	parent                     *ownedfs.Root
	name                       string
	directoryInfo              os.FileInfo
	done                       chan struct{}
	waitErr                    error // published by close(done), exactly one Cmd.Wait
	started                    bool
	closed                     bool
}

// RunProbe owns one finite native process. The caller must already have
// registered its original COMMON intent; the callback observes the real child
// and performs the separately scoped service check. This method never marks a
// listener, service or route ready. On an unconfirmed cleanup it returns the
// SAME owner, retains all files and refuses source.Close.
func (s *MihomoProbeSource) RunProbe(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, observe func(context.Context, *MihomoProbeProcess) error) (process *MihomoProbeProcess, result error) {
	return s.RunProbeAdmitted(ctx, control, cleanup, func(_ context.Context, begin func() error) error { return begin() }, observe)
}

// RunProbeAdmitted additionally enters the original COMMON resource's start
// barrier. The supplied admission cannot replace actual control.WithStart or
// replay its syscall. It must not retain begin after the synchronous call.
func (s *MihomoProbeSource) RunProbeAdmitted(ctx context.Context, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, admission func(context.Context, func() error) error, observe func(context.Context, *MihomoProbeProcess) error) (process *MihomoProbeProcess, result error) {
	if s == nil || s.self != s || ctx == nil || control == nil || cleanup == nil || observe == nil {
		return nil, ErrMihomoProbePending
	}
	if admission == nil {
		return nil, ErrMihomoProbePending
	}
	deadline, finite := ctx.Deadline()
	if !finite || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		return nil, ErrMihomoProbePending
	}
	if err := control.Current(ctx); err != nil {
		return nil, err
	}
	if err := control.CurrentForCleanupOperation(ctx, cleanup); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.probeUsed || s.probe != nil {
		s.mu.Unlock()
		return nil, ErrMihomoProbePending
	}
	if err := s.currentLocked(ctx); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	native := &mihomoProbeNativeLinux{control: control, cleanupReview: cleanup, done: make(chan struct{})}
	process = &MihomoProbeProcess{source: s, native: native, running: true}
	process.self = process
	s.probe, s.probeUsed = process, true
	data := append([]byte(nil), s.profile...)
	s.mu.Unlock()
	defer clear(data)
	// Also runs during panic. Unconfirmed cleanup stays reachable from s.probe
	// even when control never reaches the return statement.
	defer func() {
		process.mu.Lock()
		process.running = false
		process.mu.Unlock()
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		result = errors.Join(result, process.Cleanup(bounded))
	}()
	if err := native.open(ctx, s, data); err != nil {
		return process, err
	}
	if err := s.Current(ctx); err != nil {
		return process, err
	}
	native.command = exec.Command("/proc/self/fd/3", "-f", "/proc/self/fd/4", "-d", "/proc/self/fd/5")
	native.command.Args[0] = "mihomo"
	native.command.Env = []string{}
	native.command.ExtraFiles = []*os.File{native.binary, native.profile, native.directory}
	native.command.Stdout, native.command.Stderr = io.Discard, io.Discard
	var startMu sync.Mutex
	called, repeated, open := false, false, true
	defer func() { startMu.Lock(); open = false; startMu.Unlock() }()
	startErr := admission(ctx, func() error {
		startMu.Lock()
		defer startMu.Unlock()
		if !open {
			return ErrMihomoProbePending
		}
		if called {
			repeated = true
			return ErrMihomoProbePending
		}
		called = true
		return control.WithStart(ctx, func() error {
			err := native.command.Start()
			native.started = err == nil
			if native.started {
				// Establish the sole Wait before any enclosing admission can
				// return an error or panic after the actual Start succeeded.
				go func() { native.waitErr = native.command.Wait(); close(native.done) }()
			}
			return err
		})
	})
	startMu.Lock()
	open = false
	if repeated {
		startErr = errors.Join(startErr, ErrMihomoProbePending)
	}
	startMu.Unlock()
	if startErr != nil || !native.started {
		return process, errors.Join(startErr, ErrMihomoProbePending)
	}
	// Request cancellation stops the original child even while the finite
	// observer is unwinding. It does not close its borrowed descriptors. Join
	// this signal callback before final cleanup can retire those descriptors.
	watchDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() {
		defer close(watchDone)
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		process.mu.Lock()
		defer process.mu.Unlock()
		_ = native.signal(bounded) // Cleanup retries and reports any refusal.
	})
	defer func() {
		if !stopWatch() {
			<-watchDone
		}
	}()
	if err := process.Current(ctx); err != nil {
		return process, err
	}
	if err := observe(ctx, process); err != nil {
		return process, err
	}
	return process, process.Current(ctx)
}

func (n *mihomoProbeNativeLinux) open(ctx context.Context, s *MihomoProbeSource, data []byte) error {
	if err := withMihomoArtifact(ctx, s.artifacts, s.image, func(_ context.Context, f *os.File) error {
		fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err == nil {
			n.binary = os.NewFile(uintptr(fd), "[held reviewed Mihomo]")
		}
		return err
	}); err != nil {
		return err
	}
	fd, err := unix.MemfdCreate("razvilka-mihomo-probe", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return err
	}
	n.profile = os.NewFile(uintptr(fd), "[sealed Mihomo probe profile]")
	if _, err := n.profile.Write(data); err != nil {
		return err
	}
	if _, err := n.profile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(n.profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return err
	}
	n.parent, err = ownedfs.Open(os.TempDir())
	if err != nil {
		return err
	}
	n.name, err = n.parent.MkdirTemp(".", ".razvilka-mihomo-probe-")
	if err != nil {
		return err
	}
	n.directoryInfo, err = n.parent.Stat(n.name)
	if err != nil {
		return err
	}
	if n.directoryInfo.Mode().Perm() != 0700 {
		return restorejournal.ErrConflict
	}
	n.directory, err = n.parent.OpenFile(n.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	return err
}

func (n *mihomoProbeNativeLinux) pid() int {
	if n == nil || !n.started || n.command == nil || n.command.Process == nil {
		return 0
	}
	return n.command.Process.Pid
}

func (n *mihomoProbeNativeLinux) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || n.closed || n.pid() == 0 {
		return ErrMihomoProbePending
	}
	select {
	case <-n.done:
		return ErrMihomoProbePending
	default:
	}
	if err := n.control.Current(ctx); err != nil {
		return err
	}
	for _, f := range []*os.File{n.binary, n.profile, n.directory} {
		if f == nil {
			return ErrMihomoProbePending
		}
		if _, err := f.Stat(); err != nil {
			return err
		}
	}
	return n.homeCurrent()
}

func (n *mihomoProbeNativeLinux) file(kind string, actual os.FileInfo) bool {
	if n.closed || actual == nil {
		return false
	}
	var file *os.File
	switch kind {
	case "binary":
		file = n.binary
	case "profile":
		file = n.profile
	case "home":
		file = n.directory
	default:
		return false
	}
	if file == nil {
		return false
	}
	held, err := file.Stat()
	return err == nil && os.SameFile(held, actual) && held.Mode() == actual.Mode() && held.Size() == actual.Size()
}

func (n *mihomoProbeNativeLinux) homeCurrent() error {
	if n.parent == nil || n.directory == nil || n.directoryInfo == nil {
		return ErrMihomoProbePending
	}
	named, err := n.parent.Stat(n.name)
	held, heldErr := n.directory.Stat()
	if err != nil || heldErr != nil || !os.SameFile(n.directoryInfo, named) || !os.SameFile(n.directoryInfo, held) || named.Mode() != n.directoryInfo.Mode() || held.Mode() != n.directoryInfo.Mode() {
		return restorejournal.ErrConflict
	}
	return nil
}

func (n *mihomoProbeNativeLinux) cleanup(ctx context.Context) error {
	if n.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrMihomoProbePending
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrMihomoProbePending
	}
	if n.started {
		if err := n.signal(ctx); err != nil {
			return err
		}
		select {
		case <-n.done:
		case <-ctx.Done():
			return errors.Join(ErrMihomoProbePending, ctx.Err())
		}
		var exit *exec.ExitError
		if n.command.ProcessState == nil || n.waitErr != nil && !errors.As(n.waitErr, &exit) {
			return errors.Join(ErrMihomoProbePending, n.waitErr)
		}
	}
	if n.name != "" {
		if err := n.homeCurrent(); err != nil {
			return err
		}
		if err := n.parent.RemoveAll(n.name); err != nil {
			return err
		}
		n.name = ""
	}
	var result error
	for _, f := range []*os.File{n.binary, n.profile, n.directory} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	if n.parent != nil {
		result = errors.Join(result, n.parent.Close())
	}
	if result == nil {
		n.closed = true
	}
	return result
}

func (n *mihomoProbeNativeLinux) signal(ctx context.Context) error {
	select {
	case <-n.done:
		return nil
	default:
	}
	// Signal the retained os.Process; never reopen a serialized PID.
	return n.control.WithCleanupStart(ctx, n.cleanupReview, func() error {
		err := n.command.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	})
}
