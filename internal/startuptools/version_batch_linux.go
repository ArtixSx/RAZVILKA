//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"time"
)

// versionReadBatch is confined to one synchronous Check, while the original
// Lease lock and Provider scope remain held. It cannot run reads or effects.
// Every Start still checks the complete metadata graph; complete byte hashes
// bracket the three fixed observations together rather than each observation.
type versionReadBatch struct {
	self   *versionReadBatch
	lease  *Lease
	ctx    context.Context
	active bool
	next   int
}

func (l *Lease) versionBatchCurrent(ctx context.Context) error {
	if l == nil || l.review == nil || ctx == nil || ctx.Err() != nil {
		return at("VERSION_BATCH_SCOPE", nil)
	}
	if err := l.versionBatchBoundary(ctx); err != nil {
		return err
	}
	scoped, cancel := context.WithCancel(ctx)
	defer cancel()
	b := &versionReadBatch{lease: l, ctx: scoped, active: true}
	b.self = b
	defer func() { b.active = false }()
	fact, err := l.retainedVersionFact(scoped)
	if err != nil {
		return err
	}
	if fact != nil && l.profile.ipAlias == "" {
		// An alias-only profile needs its own complete metadata observation.
		// With IP, the mandatory actual child's full Start/closing metadata
		// pair brackets these fixed alias values too: the intervening two
		// projections have no callback, effect, or escaping result. Preserve
		// every actual IP invocation and both of its metadata observations.
		if err := l.review.versionMetadataCurrent(scoped); err != nil {
			return err
		}
	}
	var observed error
	for i := range l.profile.aliases {
		if fact != nil {
			observed = b.retainStatic(scoped, l, i, fact)
		} else {
			observed = b.read(scoped, l, i)
		}
		if observed != nil {
			break
		}
	}
	if observed == nil && l.profile.ipAlias != "" {
		observed = b.read(scoped, l, 2)
	}
	// Every child has its own full metadata closing check even on failure.
	// An enclosing original observation also closes the full byte graph.
	closing := l.versionBatchBoundary(ctx)
	if l.closed.Load() || l.lifetime == nil || l.lifetime.Err() != nil {
		closing = errors.Join(closing, at("VERSION_BATCH_SCOPE", nil))
	}
	return errors.Join(observed, closing, ctx.Err())
}

func (b *versionReadBatch) retainStatic(ctx context.Context, l *Lease, index int, f *scopedVersionFact) error {
	if b == nil || b.self != b || !b.active || b.lease != l || ctx != b.ctx || index != b.next || index < 0 || index > 1 {
		return at("VERSION_FACT_SCOPE", nil)
	}
	current, err := l.retainedVersionFact(ctx)
	if err != nil || current != f || f == nil {
		return at("VERSION_FACT_SCOPE", err)
	}
	b.next++
	return nil
}

// Under the SAME original readonly observation, each actual child's complete
// metadata Start/closing pair already brackets this fixed, callback-free
// batch. Avoid two additional complete metadata traversals, preserving the
// original scope/identity/lifetime checks here and outer full SHA bookends.
// Ordinary checks retain their existing complete byte checks unchanged.
func (l *Lease) versionBatchBoundary(ctx context.Context) error {
	if _, present := readObservationMarker(ctx); present {
		return l.readObservationCurrent(ctx) // Invalid/foreign markers never fall back.
	}
	return l.readObservationBytesCurrent(ctx)
}

func (b *versionReadBatch) read(ctx context.Context, l *Lease, index int) error {
	if b == nil || b.self != b || !b.active || b.lease != l || ctx == nil || ctx != b.ctx || ctx.Err() != nil || l == nil || l.review == nil || l.closed.Load() || l.lifetime == nil || l.lifetime.Err() != nil || index != b.next || index < 0 || index > 2 || index == 2 && l.profile.ipAlias == "" {
		return at("VERSION_BATCH_SCOPE", nil)
	}
	name, image := l.commandImage(index)
	if image == nil || name == "" {
		return at("VERSION_BATCH_IMAGE", nil)
	}
	arg, expected, stage := "--version", "", "BACKEND_VERSION"
	if index == 2 {
		arg, expected, stage = "-Version", l.profile.ipVersion, "IP_VERSION"
	} else {
		expected = [2]string{"iptables", "ip6tables"}[index] + " v" + l.profile.version + "\n"
	}
	if err := l.review.versionMetadataCurrent(ctx); err != nil {
		return err
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout, stderr := &output{limit: 256, cancel: cancel}, &output{limit: 256, cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", arg)
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
	runErr := l.runObservedRead(c, command)
	if command.Process != nil {
		noteVersionChildStart(l.review, index)
	}
	var observed error
	if runErr != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || c.Err() != nil {
		observed = commandResultFailure("COMMAND_RESULT", runErr, c.Err(), stdout.overflow, stderr.overflow, len(stderr.data) != 0)
	} else if string(stdout.data) != expected {
		observed = at(stage, nil)
	}
	closing := l.review.versionMetadataCurrent(ctx)
	if observed != nil || closing != nil {
		return errors.Join(at(stage, observed), closing)
	}
	b.next++
	return nil
}

// No data memoization: every file descriptor, named path, symlink, negative
// lookup and extension membership is observed anew before and after each
// literal command. sameNode includes ctime for every non-directory object.
func (r *heldReview) versionMetadataCurrent(ctx context.Context) error {
	noteVersionMetadataAttempt(r)
	if err := r.pathsCurrent(ctx); err != nil {
		return err
	}
	for _, image := range r.images {
		info, err := image.file.Stat()
		named, namedErr := os.Lstat(image.path)
		if err != nil || namedErr != nil || !sameNode(image.info, info) || !sameNode(info, named) {
			return at("CHECK_HELD_FILE", errors.Join(err, namedErr))
		}
	}
	canonical, err := r.versionExtensionPath()
	if err != nil {
		return err
	}
	file, err := openDirectory(canonical, r.nodes[canonical].info)
	if err != nil {
		return at("CHECK_EXTENSIONS", err)
	}
	entries, readErr := file.ReadDir(257)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 256 {
		return at("CHECK_EXTENSIONS", errors.Join(readErr, closeErr))
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, r.extensions) {
		return at("CHECK_EXTENSION_SET", nil)
	}
	return r.pathsCurrent(ctx)
}
