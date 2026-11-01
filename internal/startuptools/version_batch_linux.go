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
	if err := l.review.unchanged(ctx); err != nil {
		return err
	}
	scoped, cancel := context.WithCancel(ctx)
	defer cancel()
	b := &versionReadBatch{lease: l, ctx: scoped, active: true}
	b.self = b
	defer func() { b.active = false }()
	var observed error
	for i := range l.profile.aliases {
		if observed = b.read(scoped, l, i); observed != nil {
			break
		}
	}
	if observed == nil && l.profile.ipAlias != "" {
		observed = b.read(scoped, l, 2)
	}
	// Even a failed command cannot hide a concurrent graph mutation.
	closing := l.review.unchanged(ctx)
	if l.closed.Load() || l.lifetime == nil || l.lifetime.Err() != nil {
		closing = errors.Join(closing, at("VERSION_BATCH_SCOPE", nil))
	}
	return errors.Join(observed, closing, ctx.Err())
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
	runErr := command.Run()
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
	canonical, err := r.resolveExisting(r.profile.extension)
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
