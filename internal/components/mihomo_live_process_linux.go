//go:build linux

package components

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

type mihomoLiveNativeLinux struct {
	mu                           sync.Mutex
	owner                        *MihomoLiveProcess
	binary, profile, directory   *os.File
	parent                       *ownedfs.Root
	name                         string
	homeInfo                     os.FileInfo
	command                      *exec.Cmd
	validation                   *exec.Cmd
	validationDone               chan struct{}
	validationStarted            bool
	validationErr                error
	startDone, done, creatorDone chan struct{}
	startCalled, started, closed bool
	startErr, waitErr, closeErr  error
	panicValue                   any
}

func newMihomoLiveNative(ctx context.Context, p *MihomoLiveProcess) (mihomoLiveNative, error) {
	n := &mihomoLiveNativeLinux{owner: p, startDone: make(chan struct{}), done: make(chan struct{}), creatorDone: make(chan struct{})}
	if err := p.source.Current(ctx); err != nil {
		return n, err
	}
	err := withMihomoArtifact(ctx, p.source.artifacts, p.source.image, func(_ context.Context, f *os.File) error {
		fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err == nil {
			n.binary = os.NewFile(uintptr(fd), "[held live Mihomo executable]")
		}
		return err
	})
	if err != nil {
		return n, err
	}
	fd, err := unix.MemfdCreate("razvilka-mihomo-live", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return n, err
	}
	n.profile = os.NewFile(uintptr(fd), "[sealed live Mihomo profile]")
	if _, err := n.profile.Write(p.profile.config); err != nil {
		return n, err
	}
	if _, err := n.profile.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	if _, err := unix.FcntlInt(n.profile.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return n, err
	}
	n.parent, err = ownedfs.Open(os.TempDir())
	if err != nil {
		return n, err
	}
	n.name, err = n.parent.MkdirTemp(".", ".razvilka-mihomo-live-")
	if err != nil {
		return n, err
	}
	n.homeInfo, err = n.parent.Stat(n.name)
	if err != nil || n.homeInfo.Mode().Perm() != 0700 {
		return n, errors.Join(ErrMihomoLiveOwner, err)
	}
	n.directory, err = n.parent.OpenFile(n.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return n, err
	}
	return n, n.filesCurrent(ctx)
}

func (n *mihomoLiveNativeLinux) makeCommand(ctx context.Context, validation bool) *exec.Cmd {
	args := []string{"-f", "/proc/self/fd/4", "-d", "/proc/self/fd/5"}
	var command *exec.Cmd
	if validation {
		args = append([]string{"-t"}, args...)
		command = exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	} else {
		command = exec.Command("/proc/self/fd/3", args...)
	}
	command.Args[0] = "mihomo"
	command.Env = []string{}
	command.ExtraFiles = []*os.File{n.binary, n.profile, n.directory}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command
}

func (n *mihomoLiveNativeLinux) start(ctx context.Context, admission func(context.Context, func() error) error) error {
	n.mu.Lock()
	if n.closed || n.startCalled {
		n.mu.Unlock()
		return ErrMihomoLiveOwner
	}
	n.startCalled = true
	go n.runStarter(ctx, admission)
	n.mu.Unlock()
	select {
	case <-n.startDone:
		if n.panicValue != nil {
			panic(n.panicValue)
		}
		return n.startErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *mihomoLiveNativeLinux) runStarter(ctx context.Context, admission func(context.Context, func() error) error) {
	// PR_SET_PDEATHSIG belongs to the creating THREAD. Keep that exact thread
	// alive until the original Cmd's sole Wait has completed, across Apply.
	runtime.LockOSThread()
	defer func() { runtime.UnlockOSThread(); close(n.creatorDone) }()
	creatorTID := unix.Gettid()
	n.startErr = func() (result error) {
		defer func() {
			if value := recover(); value != nil {
				n.panicValue = value
				result = ErrMihomoLiveOwner
			}
		}()
		if err := n.owner.source.Current(ctx); err != nil {
			return err
		}
		if err := n.filesCurrent(ctx); err != nil {
			return err
		}
		// The config test is a real owned native command, using the SAME held
		// files. It is joined before the runtime Start; it creates no listener.
		n.validation = n.makeCommand(ctx, true)
		n.validationDone = make(chan struct{})
		err := n.owner.control.WithStart(ctx, func() error {
			err := n.validation.Start()
			n.validationStarted = err == nil
			if n.validationStarted {
				go func() { n.validationErr = n.validation.Wait(); close(n.validationDone) }()
			}
			return err
		})
		if n.validationStarted {
			<-n.validationDone
		}
		if err != nil || !n.validationStarted || n.validationErr != nil {
			return errors.Join(ErrMihomoNativeValidation, err, n.validationErr)
		}
		if err := n.owner.source.Current(ctx); err != nil {
			return err
		}
		if err := n.filesCurrent(ctx); err != nil {
			return err
		}
		n.command = n.makeCommand(ctx, false)
		var callMu sync.Mutex
		called, repeated, open := false, false, true
		defer func() { callMu.Lock(); open = false; callMu.Unlock() }()
		begin := func() error {
			callMu.Lock()
			defer callMu.Unlock()
			if !open || called || unix.Gettid() != creatorTID {
				repeated = true
				return ErrMihomoLiveOwner
			}
			called = true
			return n.owner.control.WithStart(ctx, func() error {
				err := n.command.Start()
				n.started = err == nil
				if n.started {
					go func() { n.waitErr = n.command.Wait(); close(n.done) }()
				}
				return err
			})
		}
		err = admission(ctx, begin)
		callMu.Lock()
		open = false
		invalid := repeated || !called
		callMu.Unlock()
		if invalid || !n.started {
			return errors.Join(ErrMihomoLiveOwner, err)
		}
		return err
	}()
	close(n.startDone)
	if n.validationStarted {
		<-n.validationDone
	}
	if n.started {
		<-n.done
	}
}

func (n *mihomoLiveNativeLinux) filesCurrent(ctx context.Context) error {
	if err := mihomoLiveFinite(ctx); err != nil {
		return err
	}
	if n.closed || n.closeErr != nil || n.owner == nil || n.owner.self != n.owner || n.binary == nil || n.profile == nil || n.directory == nil {
		return ErrMihomoLiveOwner
	}
	hash, err := originHash(ctx, n.binary)
	if err != nil || hash != n.owner.source.reference.BinarySHA256 {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	seals, err := unix.FcntlInt(n.profile.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		return ErrMihomoLiveOwner
	}
	hash, err = originHash(ctx, n.profile)
	if err != nil || hash != n.owner.profile.configSHA {
		return errors.Join(ErrMihomoLiveOwner, err)
	}
	return n.homeCurrent()
}
func (n *mihomoLiveNativeLinux) homeCurrent() error {
	if n.parent == nil || n.directory == nil || n.homeInfo == nil {
		return ErrMihomoLiveOwner
	}
	named, err := n.parent.Stat(n.name)
	held, heldErr := n.directory.Stat()
	if err != nil || heldErr != nil || !os.SameFile(n.homeInfo, named) || !os.SameFile(n.homeInfo, held) || named.Mode() != n.homeInfo.Mode() || held.Mode() != n.homeInfo.Mode() {
		return restorejournal.ErrConflict
	}
	return nil
}
func (n *mihomoLiveNativeLinux) current(ctx context.Context) error {
	return n.currentMode(ctx, nil)
}
func (n *mihomoLiveNativeLinux) currentForCleanup(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	if cleanup == nil {
		return ErrMihomoLiveOwner
	}
	return n.currentMode(ctx, cleanup)
}
func (n *mihomoLiveNativeLinux) currentMode(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.startDone:
	default:
		return ErrMihomoLiveOwner
	}
	if !n.started || n.command == nil || n.command.Process == nil || n.closed {
		return ErrMihomoLiveOwner
	}
	select {
	case <-n.done:
		return ErrMihomoLiveOwner
	default:
	}
	if n.command.Path != "/proc/self/fd/3" || !slices.Equal(n.command.Args, []string{"mihomo", "-f", "/proc/self/fd/4", "-d", "/proc/self/fd/5"}) || len(n.command.Env) != 0 || n.command.Cancel != nil || len(n.command.ExtraFiles) != 3 || n.command.ExtraFiles[0] != n.binary || n.command.ExtraFiles[1] != n.profile || n.command.ExtraFiles[2] != n.directory || n.command.SysProcAttr == nil || n.command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		return ErrMihomoLiveOwner
	}
	var controlErr error
	if cleanup == nil {
		controlErr = n.owner.control.ObserveCurrent(ctx)
	} else {
		controlErr = n.owner.control.CurrentForCleanupOperation(ctx, cleanup)
	}
	if controlErr != nil {
		return controlErr
	}
	return n.filesCurrent(ctx)
}
func (n *mihomoLiveNativeLinux) pid() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.startDone:
	default:
		return 0
	}
	if !n.started || n.command == nil || n.command.Process == nil {
		return 0
	}
	return n.command.Process.Pid
}
func (n *mihomoLiveNativeLinux) file(kind string, actual os.FileInfo) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || actual == nil {
		return false
	}
	var f *os.File
	switch kind {
	case "binary":
		f = n.binary
	case "profile":
		f = n.profile
	case "home":
		f = n.directory
	default:
		return false
	}
	if f == nil {
		return false
	}
	held, err := f.Stat()
	return err == nil && os.SameFile(held, actual) && held.Mode() == actual.Mode() && held.Size() == actual.Size()
}
func (n *mihomoLiveNativeLinux) cleanup(ctx context.Context, review *operationgate.ExclusiveCleanupReview) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	if n.closeErr != nil {
		return errors.Join(ErrMihomoLiveOwner, n.closeErr)
	}
	if n.startCalled {
		n.mu.Unlock()
		select {
		case <-n.startDone:
		case <-ctx.Done():
			n.mu.Lock()
			return ctx.Err()
		}
		n.mu.Lock()
		if n.validationStarted {
			select {
			case <-n.validationDone:
			default:
				if err := n.owner.control.WithCleanupStart(ctx, review, func() error {
					err := n.validation.Process.Kill()
					if errors.Is(err, os.ErrProcessDone) {
						return nil
					}
					return err
				}); err != nil {
					return err
				}
			}
			select {
			case <-n.validationDone:
			case <-ctx.Done():
				return ctx.Err()
			}
			var exit *exec.ExitError
			if n.validation.ProcessState == nil || n.validationErr != nil && !errors.As(n.validationErr, &exit) && !errors.Is(n.validationErr, context.Canceled) && !errors.Is(n.validationErr, context.DeadlineExceeded) {
				return errors.Join(ErrMihomoLiveOwner, n.validationErr)
			}
		}
		if n.started {
			select {
			case <-n.done:
			default:
				if err := n.owner.control.WithCleanupStart(ctx, review, func() error {
					err := n.command.Process.Kill()
					if errors.Is(err, os.ErrProcessDone) {
						return nil
					}
					return err
				}); err != nil {
					return err
				}
			}
			select {
			case <-n.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			var exit *exec.ExitError
			if n.command.ProcessState == nil || n.waitErr != nil && !errors.As(n.waitErr, &exit) {
				return errors.Join(ErrMihomoLiveOwner, n.waitErr)
			}
		}
		select {
		case <-n.creatorDone:
		case <-ctx.Done():
			return ctx.Err()
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
	for _, f := range []*os.File{n.binary, n.profile, n.directory} {
		if f != nil {
			n.closeErr = errors.Join(n.closeErr, f.Close())
		}
	}
	if n.parent != nil {
		n.closeErr = errors.Join(n.closeErr, n.parent.Close())
	}
	if n.closeErr != nil {
		return errors.Join(ErrMihomoLiveOwner, n.closeErr)
	}
	n.closed = true
	return nil
}
