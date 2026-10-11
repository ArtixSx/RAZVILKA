//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This producer accepts only the negative source's closed read ABI. Generic
// WG/policy effects retain their existing strict write ACK result handling.
func (l *Lease) runWGInactivity(original context.Context, name string, args ...string) ([]byte, error) {
	if err := l.retain(original); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	return l.runWGInactivityHeld(original, name, args...)
}

// Both entry points retain THIS lease through actual Start, sole Wait and
// closing review. The original WG runner has already checked its own WG ABI.
func (l *Lease) runWGInactivityHeld(original context.Context, name string, args ...string) ([]byte, error) {
	if _, finite := original.Deadline(); !finite {
		return nil, at("WG_INACTIVITY_DEADLINE", nil)
	}
	frozen := slices.Clone(args)
	_, profileErr := wgRequiredEntry(l.profile.wgEngine)
	if profileErr != nil || l.review == nil || l.provider == nil || l.digest == "" || !wgInactivitySourceArguments(l, name, frozen) {
		return nil, at("WG_INACTIVITY_ABI", nil)
	}
	index := -1
	for i, alias := range l.profile.aliases {
		if name == alias {
			index = i
		}
	}
	if name == l.profile.ipAlias {
		index = 2
	}
	for i, image := range l.review.wgEntry {
		if image != nil && name == image.path {
			index = i + 3
		}
	}
	actualName, image := l.commandImage(index)
	if image == nil || actualName == "" || actualName != name {
		return nil, at("WG_INACTIVITY_ALIAS", nil)
	}
	actual, stockRead := wgStockNumericRuleArguments(frozen)
	stockRead = stockRead && l.profile.stock && index == 2
	if stockRead {
		var err error
		original, err = wgStockReadContext(original, name, l.digest, frozen, actual)
		if err != nil {
			return nil, err
		}
		frozen = actual
	}
	c, cancel := context.WithTimeout(original, 25*time.Second)
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	stdout, stderr := &output{limit: maxOutputBytes, cancel: cancel}, &output{limit: 4096, cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", frozen...)
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
	started := false
	runtime.LockOSThread()
	thread := syscall.Gettid()
	admissionErr := func() error {
		start, startCancel := context.WithTimeout(c, operationTimeout)
		defer startCancel()
		if err := l.lock(start); err != nil {
			return err
		}
		defer l.unlock()
		return l.provider.WithCurrent(start, func(held context.Context, actual netidentity.Identity) error {
			if actual != l.identity || !l.profile.acceptsIdentity(actual) || original.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
				return at("WG_INACTIVITY_IDENTITY", nil)
			}
			if err := l.review.unchanged(held); err != nil {
				return err
			}
			if held.Err() != nil || original.Err() != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
				return at("WG_INACTIVITY_START_CONTEXT", nil)
			}
			return invokeAdmission(original, name, frozen, l.digest, func() bool { return syscall.Gettid() == thread }, func() error {
				if err := command.Start(); err != nil {
					return at("WG_INACTIVITY_START", err)
				}
				started = true
				return nil
			})
		})
	}()
	runtime.UnlockOSThread()
	if !started {
		return nil, at("WG_INACTIVITY_NOT_STARTED", admissionErr)
	}
	if admissionErr != nil {
		cancel()
	}
	// Join the one actual child before reacquiring any tool/Provider gate.
	waitErr := command.Wait()
	scopeErr := errors.Join(admissionErr, c.Err(), original.Err(), l.lifetime.Err())
	if scopeErr == nil && !stdout.overflow && !stderr.overflow {
		scopeErr = func() error {
			closing, closeCancel := context.WithTimeout(c, operationTimeout)
			defer closeCancel()
			if err := l.lock(closing); err != nil {
				return err
			}
			defer l.unlock()
			return l.current(closing, l.identity, false)
		}()
	}
	if l.closed.Load() {
		scopeErr = errors.Join(scopeErr, at("WG_INACTIVITY_CLOSED", nil))
	}
	scopeErr = errors.Join(scopeErr, c.Err(), original.Err(), l.lifetime.Err())
	data, err := wgInactivityReadResult(stdout, stderr, waitErr, scopeErr)
	if err == nil && stockRead {
		data, err = stockNumericRules(data)
	}
	return data, err
}
