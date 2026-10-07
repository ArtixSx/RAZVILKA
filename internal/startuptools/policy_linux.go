//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (l *Lease) runPolicy(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := l.retain(ctx); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if l.review == nil || l.review.ipEntry == nil || l.profile.ipAlias == "" || l.provider == nil || l.digest == "" {
		return nil, at("POLICY_UNISSUED", nil)
	}
	if !boundedArguments(args) {
		return nil, at("POLICY_ABI", nil)
	}
	frozen := append([]string(nil), args...)
	index := -1
	for i, alias := range l.profile.aliases {
		if name == alias {
			index = i
		}
	}
	if name == l.profile.ipAlias {
		index = 2
	}
	if index < 0 {
		return nil, at("POLICY_ALIAS", nil)
	}
	if index < 2 && readArguments(frozen) || index == 2 && ipReadArguments(frozen) {
		return l.policyRead(ctx, index, frozen)
	}
	if !effectArguments(index, frozen) {
		return nil, at("POLICY_ABI", nil)
	}
	return l.policyEffect(ctx, index, frozen)
}

func (l *Lease) policyRead(ctx context.Context, index int, args []string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return nil, err
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	var data []byte
	err := l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
		if actual != l.identity || !l.profile.acceptsIdentity(actual) {
			return at("READ_IDENTITY", nil)
		}
		var err error
		data, err = l.execute(held, index, maxOutputBytes, args...)
		return err
	})
	if err != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("READ", errors.Join(err, c.Err()))
	}
	return append([]byte(nil), data...), nil
}

func (l *Lease) policyEffect(original context.Context, index int, args []string) ([]byte, error) {
	c, cancel := context.WithTimeout(original, 25*time.Second)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	name, image := l.commandImage(index)
	if name == "" || image == nil {
		return nil, at("POLICY_ALIAS", nil)
	}
	stdout, stderr := &output{limit: maxOutputBytes, cancel: cancel}, &output{limit: 4096, cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", args...)
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
	started := false
	// Keep the caller on the same kernel thread through CORE's original
	// barrier and Provider's opening/actual-start/closing observations.
	runtime.LockOSThread()
	thread := syscall.Gettid()
	admissionErr := invokeAdmission(original, name, args, l.digest, func() bool { return syscall.Gettid() == thread }, func() error {
		start, startCancel := context.WithTimeout(c, operationTimeout)
		defer startCancel()
		if err := l.lock(start); err != nil {
			return err
		}
		defer l.unlock()
		return l.provider.WithCurrent(start, func(held context.Context, actual netidentity.Identity) error {
			if actual != l.identity || !l.profile.acceptsIdentity(actual) || original.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
				return at("EFFECT_IDENTITY", nil)
			}
			if err := l.review.unchanged(held); err != nil {
				return err
			}
			if held.Err() != nil || original.Err() != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
				return at("EFFECT_START_CONTEXT", nil)
			}
			if err := command.Start(); err != nil {
				return at("EFFECT_START", err)
			}
			started = true
			return nil
		})
	})
	runtime.UnlockOSThread()
	if !started {
		return nil, at("EFFECT_NOT_STARTED", admissionErr)
	}
	if admissionErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	if admissionErr != nil || waitErr != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 {
		return nil, at("EFFECT_UNKNOWN", errors.Join(admissionErr, waitErr))
	}
	// Successful Wait after the exact admitted Start acknowledges the write.
	// Do not erase that ACK if cancellation races after the child exited: the
	// receipt owner records it before checking cancellation. Every failed
	// admission, closing identity observation or Wait above remains Unknown.
	return append([]byte(nil), stdout.data...), nil
}
