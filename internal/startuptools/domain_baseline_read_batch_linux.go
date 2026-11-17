//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type domainBaselineReadStage uint8

const (
	domainBaselineReadQueue domainBaselineReadStage = iota
	domainBaselineReadProvider
	domainBaselineReadProviderBody
	domainBaselineReadOpening
	domainBaselineReadClosing
	domainBaselineReadPhaseCount
)

// Only the four original synthetic-baseline queries may borrow their SAME
// synchronous readonly source. Its full SHA closes before any outer result
// can succeed. Every actual child still has independent FD/name/metadata,
// namespace, cancellation and sole-Wait bookends. Ordinary callers retain
// the original full-byte policyRead path, including its per-command budget.
func (l *Lease) domainBaselineRead(ctx context.Context, args []string) ([]byte, error) {
	if l == nil || ctx == nil || !domainBaselineObservedRead(args) {
		return nil, at("DOMAIN_BASELINE_READ", nil)
	}
	_, scoped := readObservationMarker(ctx)
	timing := beginDomainBaselineReadMeasurement(args, scoped)
	var data []byte
	var err error
	if scoped {
		data, err = l.domainBaselineReadObserved(ctx, args, timing)
	} else {
		data, err = l.policyReadMeasured(ctx, 2, args, timing)
	}
	timing.finish(err == nil)
	return data, err
}

func (l *Lease) domainBaselineReadObserved(ctx context.Context, args []string, timing *domainBaselineReadMeasurement) ([]byte, error) {
	if l.profile.stock || !l.syntheticDNSIssued() {
		return nil, at("DOMAIN_BASELINE_READ", nil)
	}
	frozen := slices.Clone(args)
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	queueStart := timing.now()
	lockErr := l.lock(c)
	timing.phase(domainBaselineReadQueue, queueStart)
	if lockErr != nil {
		return nil, lockErr
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	var data []byte
	providerStart := timing.now()
	err := l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
		if domainBaselineReadTimingEnabled && timing != nil {
			defer timing.phase(domainBaselineReadProviderBody, timing.now())
		}
		if actual != l.identity || !l.profile.acceptsIdentity(actual) {
			return at("READ_IDENTITY", nil)
		}
		name, image := l.commandImage(2)
		if name == "" || image == nil || l.review == nil || !domainBaselineObservedRead(frozen) {
			return at("DOMAIN_BASELINE_READ", nil)
		}
		openingStart := timing.now()
		openingErr := l.readObservationBytesCurrent(held)
		timing.phase(domainBaselineReadOpening, openingStart)
		if openingErr != nil {
			return openingErr
		}
		leaf, stopLeaf := context.WithCancel(held)
		defer stopLeaf()
		stdout := &output{limit: maxOutputBytes, cancel: stopLeaf}
		stderr := &output{limit: 4096, cancel: stopLeaf}
		command := exec.CommandContext(leaf, "/proc/self/fd/3", frozen...)
		command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
		command.ExtraFiles = []*os.File{image.file}
		command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
		runErr := l.runObservedReadMeasured(leaf, command, timing)
		timing.output(stdout.overflow, stderr.overflow, len(stderr.data) != 0)
		if command.Process != nil {
			domainNativeToolStarted("original-read")
		}
		var observed error
		if runErr != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || leaf.Err() != nil {
			observed = commandResultFailure("COMMAND_RESULT", runErr, leaf.Err(), stdout.overflow, stderr.overflow, len(stderr.data) != 0)
		}
		closingStart := timing.now()
		closing := l.readObservationBytesCurrent(held)
		timing.phase(domainBaselineReadClosing, closingStart)
		if err := errors.Join(observed, closing, held.Err()); err != nil {
			return err
		}
		data = slices.Clone(stdout.data)
		return nil
	})
	timing.phase(domainBaselineReadProvider, providerStart)
	if err != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("READ", errors.Join(err, c.Err(), l.lifetime.Err()))
	}
	return data, nil
}
