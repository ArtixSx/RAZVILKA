//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type classicSaveScopeKey struct{}
type classicSaveScope struct {
	lease   *Lease
	lock    *classicSaveLock
	command *exec.Cmd
	ctx     context.Context
	family  int
	active  bool
}

// One byte budget covers both streams and both children. The ordinary output
// type and every other command contract remain unchanged.
type classicSaveBudget struct {
	mu        sync.Mutex
	remaining int
	overflow  bool
	cancel    context.CancelFunc
}
type classicSaveOutput struct {
	sink   *output
	budget *classicSaveBudget
}

func (w *classicSaveOutput) Write(p []byte) (int, error) {
	w.budget.mu.Lock()
	if len(p) > w.budget.remaining {
		w.budget.overflow = true
		w.budget.mu.Unlock()
		w.budget.cancel()
		return 0, at("OUTPUT_LIMIT", nil)
	}
	w.budget.remaining -= len(p)
	w.budget.mu.Unlock()
	return w.sink.Write(p)
}

func (l *Lease) classicSaveSupported() bool {
	if l == nil || l.profile.stock || !l.profile.classicSaveABI || l.profile.arch != "amd64" {
		return false
	}
	p := ubuntuProfile()
	return l.profile.aliases == p.aliases && l.profile.main == p.main && (l.profile.version == "1.8.10 (legacy)" || l.profile.version == "1.8.11 (legacy)")
}

func (l *Lease) classicSaveImage(family int) (string, *heldImage) {
	if !l.classicSaveSupported() || family < 0 || family > 1 || l.review == nil {
		return "", nil
	}
	_, image := l.commandImage(family)
	if image == nil || image.file == nil || image.path != l.profile.main || l.review.images[image.path] != image || hex.EncodeToString(image.hash[:]) != l.profile.mainSHA {
		return "", nil
	}
	return l.profile.aliases[family] + "-save", image
}

// A complete image uses two original held multicall applets, with the same
// nonblocking xtables lock held across both. Unsupported is decided BEFORE
// any read/lock/child; once attempted, every partial failure refuses.
func (l *Lease) ReadBoundedClassicInventory(ctx context.Context, expected netidentity.Identity, review string, paths [2]string, limit int, tables [2][]string) (result [2][]byte, supported bool, err error) {
	if !l.classicSaveSupported() {
		return result, false, nil
	}
	supported = true
	var zero [2][]byte
	if ctx == nil || expected.Validate() != nil || limit <= 0 || limit > maxOutputBytes {
		return zero, true, at("CLASSIC_SAVE_SCOPE", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || time.Until(deadline) <= 0 {
		return zero, true, at("READ_DEADLINE", ctx.Err())
	}
	for family := range tables {
		if len(tables[family]) > 64 {
			return zero, true, at("CLASSIC_SAVE_TABLES", nil)
		}
		tables[family] = slices.Clone(tables[family])
		for i, table := range tables[family] {
			if !readArguments([]string{"-t", table, "-S"}) || slices.Contains(tables[family][:i], table) {
				return zero, true, at("CLASSIC_SAVE_TABLES", nil)
			}
		}
	}
	if len(tables[0])+len(tables[1]) == 0 {
		return zero, true, at("CLASSIC_SAVE_TABLES", nil)
	}
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return zero, true, err
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if l.review == nil || l.provider == nil || review == "" || review != l.digest || expected != l.identity || paths != l.profile.aliases {
		return zero, true, at("CLASSIC_SAVE_SCOPE", nil)
	}
	err = l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) (observed error) {
		if actual != expected || !l.profile.acceptsIdentity(actual) {
			return at("READ_IDENTITY", nil)
		}
		if err := l.classicBatchBytesCurrent(held); err != nil {
			return err
		}
		lock, err := openClassicSaveLock(held)
		if err != nil {
			return err
		}
		defer func() { observed = errors.Join(observed, lock.close()) }()
		remaining := limit
		budget := &classicSaveBudget{remaining: limit, cancel: cancel}
		for family := range tables {
			if len(tables[family]) == 0 {
				continue
			}
			result[family], observed = l.readClassicSaveFamily(held, lock, budget, family, remaining)
			if observed != nil {
				break
			}
			remaining -= len(result[family])
		}
		return errors.Join(observed, l.classicBatchBytesCurrent(held), lock.current(held), held.Err())
	})
	if err != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return zero, true, at("CLASSIC_SAVE_READ", errors.Join(err, c.Err(), l.lifetime.Err()))
	}
	return result, true, nil
}

func (l *Lease) readClassicSaveFamily(ctx context.Context, lock *classicSaveLock, budget *classicSaveBudget, family, limit int) ([]byte, error) {
	if limit <= 0 || limit > maxOutputBytes || lock == nil || !lock.locked || budget == nil || budget.cancel == nil {
		return nil, at("CLASSIC_SAVE_SCOPE", nil)
	}
	name, image := l.classicSaveImage(family)
	if image == nil {
		return nil, at("CLASSIC_SAVE_IMAGE", nil)
	}
	leaf, cancel, err := boundedReadContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	scope := &classicSaveScope{lease: l, lock: lock, family: family, active: true}
	defer func() { scope.active = false; scope.command = nil }()
	c := context.WithValue(leaf, classicSaveScopeKey{}, scope)
	scope.ctx = c
	if err := errors.Join(l.review.versionMetadataCurrent(c), lock.current(c)); err != nil {
		return nil, err
	}
	stdout, stderr := &output{limit: limit, cancel: cancel}, &output{limit: min(limit, 4096), cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3")
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = &classicSaveOutput{stdout, budget}, &classicSaveOutput{stderr, budget}, 100*time.Millisecond
	scope.command = command
	runErr := l.runObservedRead(c, command)
	if command.Process != nil {
		domainNativeToolStarted("original-read-classic-save")
	}
	var observed error
	if runErr != nil || stdout.overflow || stderr.overflow || budget.overflow || len(stderr.data) != 0 || c.Err() != nil {
		observed = commandResultFailure("COMMAND_RESULT", runErr, c.Err(), stdout.overflow || budget.overflow, stderr.overflow, len(stderr.data) != 0)
	}
	closing := errors.Join(l.review.versionMetadataCurrent(c), lock.current(c))
	if observed != nil || closing != nil {
		return nil, errors.Join(observed, closing)
	}
	return stdout.data, nil
}

// A save applet is NOT part of the generic read-command allowlist. Only this
// original lock/leaf/command tuple can reach the existing Start/sole Wait path.
func (l *Lease) observedClassicSaveCommand(ctx context.Context, command *exec.Cmd) bool {
	if ctx == nil || command == nil {
		return false
	}
	s, ok := ctx.Value(classicSaveScopeKey{}).(*classicSaveScope)
	if !ok || s == nil || !s.active || s.lease != l || s.ctx != ctx || s.command != command || s.lock == nil || !s.lock.locked || s.lock.current(ctx) != nil {
		return false
	}
	name, image := l.classicSaveImage(s.family)
	if image == nil || command.Path != "/proc/self/fd/3" || !slices.Equal(command.Args, []string{name}) || len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != image.file || command.Dir != "/" || command.Stdin != nil || !slices.Equal(command.Env, l.profile.environment()) {
		return false
	}
	out, outOK := command.Stdout.(*classicSaveOutput)
	errOut, errOK := command.Stderr.(*classicSaveOutput)
	return outOK && errOK && out != nil && errOut != nil && out != errOut && out.sink != nil && errOut.sink != nil && out.budget != nil && out.budget == errOut.budget && out.budget.cancel != nil && out.sink.limit > 0 && out.sink.limit <= maxOutputBytes && errOut.sink.limit > 0 && errOut.sink.limit <= 4096
}
