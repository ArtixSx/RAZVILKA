//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os/exec"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// WithReadOnlyToolObservation brackets one synchronous pure observation.
// No tool gate/Provider lock spans use. The original lifetime holds all FDs;
// revocation cancels and joins every nested held read before closing SHA.
// use must remain a synchronous pure observation: it must not close this
// owner or invoke any lifecycle/effect transition. External Close still
// cancels and joins the complete observation before releasing descriptors.
func (l *Lease) WithReadOnlyToolObservation(ctx context.Context, expected netidentity.Identity, review string, use func(context.Context) error) (result error) {
	if l == nil || ctx == nil || use == nil || expected.Validate() != nil {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return at("READ_DEADLINE", nil)
	}
	if o, present := readObservationMarker(ctx); present {
		release, _, err := l.registerReadObservation(ctx)
		if err != nil {
			return err
		}
		defer release()
		if o.identity != expected || o.digest != review {
			return at("READ_OBSERVATION_SCOPE", nil)
		}
		return errors.Join(use(ctx), l.readObservationCurrent(ctx), ctx.Err()) // Same enclosing original observation.
	}
	if err := l.retain(ctx); err != nil {
		return err
	}
	defer l.retained.Done()
	if err := l.observationBytes(ctx, expected, review); err != nil {
		return err
	}
	base, cancel := context.WithCancel(ctx)
	o := &toolReadObservation{lease: l, review: l.review, identity: expected, digest: review, deadline: deadline, active: true}
	o.self = o
	scoped := context.WithValue(base, toolReadObservationKey{}, o)
	o.ctx = scoped
	stopLife := context.AfterFunc(l.lifetime, cancel)
	defer stopLife()
	defer func() {
		o.mu.Lock()
		o.active = false
		o.mu.Unlock()
		cancel()
		o.users.Wait()
		result = errors.Join(result, l.observationBytes(ctx, expected, review), ctx.Err())
	}()
	return use(scoped)
}

func (l *Lease) observationBytes(ctx context.Context, expected netidentity.Identity, review string) error {
	leaf, cancel, err := boundedReadContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := l.lock(leaf); err != nil {
		return err
	}
	defer l.unlock()
	stopLife := context.AfterFunc(l.lifetime, cancel)
	defer stopLife()
	if l.review == nil || l.provider == nil || review == "" || review != l.digest || expected != l.identity {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	err = l.provider.WithCurrent(leaf, func(held context.Context, id netidentity.Identity) error {
		if id != expected || !l.profile.acceptsIdentity(id) {
			return at("READ_IDENTITY", nil)
		}
		return errors.Join(l.review.unchanged(held), held.Err())
	})
	if l.closed.Load() || l.lifetime.Err() != nil || leaf.Err() != nil {
		return at("READ_OBSERVATION_SCOPE", errors.Join(err, l.lifetime.Err(), leaf.Err()))
	}
	return err
}

// Called only with the original gate held. A marker never silently falls back
// after revocation or on another lease; ordinary reads keep the full SHA path.
func (l *Lease) readObservationBytesCurrent(ctx context.Context) error {
	if _, present := readObservationMarker(ctx); !present {
		return l.review.unchanged(ctx)
	}
	if err := l.readObservationCurrent(ctx); err != nil {
		return err
	}
	return errors.Join(l.review.versionMetadataCurrent(ctx), l.readObservationCurrent(ctx))
}

// Context cancellation/sole Wait retain the original Cmd. The scope mutex
// linearizes ONLY actual Start with revocation, never Wait or user callbacks.
func (l *Lease) runObservedRead(ctx context.Context, command *exec.Cmd) error {
	o, present := readObservationMarker(ctx)
	if !present {
		return command.Run()
	}
	if o == nil {
		return at("READ_OBSERVATION_SCOPE", nil)
	}
	if !l.observedReadCommand(command) {
		return at("READ_OBSERVATION_EFFECT", nil)
	}
	o.mu.Lock()
	if err := o.currentLocked(ctx, l); err != nil {
		o.mu.Unlock()
		return err
	}
	startErr := command.Start()
	var stop func() bool
	var cancelled chan struct{}
	var cancelErr error
	if startErr == nil {
		cancelled = make(chan struct{})
		stop = context.AfterFunc(o.ctx, func() {
			defer close(cancelled)
			if command.Cancel != nil {
				cancelErr = command.Cancel()
			}
		})
	}
	o.mu.Unlock()
	if startErr != nil {
		return startErr
	}
	waitErr := command.Wait()
	if !stop() {
		<-cancelled
	}
	return errors.Join(waitErr, cancelErr, o.ctx.Err())
}

func (l *Lease) observedReadCommand(command *exec.Cmd) bool {
	if l == nil || command == nil || command.Path != "/proc/self/fd/3" || len(command.Args) == 0 || len(command.ExtraFiles) != 1 || command.Dir != "/" || command.Stdin != nil || !slices.Equal(command.Env, l.profile.environment()) {
		return false
	}
	out, outOK := command.Stdout.(*output)
	errOut, errOK := command.Stderr.(*output)
	if !outOK || !errOK || out.limit <= 0 || out.limit > maxOutputBytes || errOut.limit <= 0 || errOut.limit > 4096 {
		return false
	}
	args := command.Args[1:]
	for index := 0; index <= 4; index++ {
		name, image := l.commandImage(index)
		if name == "" || image == nil || name != command.Args[0] || image.file != command.ExtraFiles[0] {
			continue
		}
		if index < 2 {
			return readArguments(args) || slices.Equal(args, []string{"--version"})
		}
		if index == 2 {
			return slices.Equal(args, []string{"-Version"}) || observedPolicyIPRead(l.profile.stock, args) || !l.profile.stock && l.syntheticDNSIssued() && domainBaselineObservedRead(args)
		}
		return slices.Equal(args, []string{"--version"})
	}
	return false
}
