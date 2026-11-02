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

type classicTableReadCommand struct {
	family int
	table  string
}
type classicTableReadBatch struct {
	self     *classicTableReadBatch
	lease    *Lease
	ctx      context.Context
	active   bool
	next     int
	commands []classicTableReadCommand
}

// ReadBoundedClassicTables observes one complete registered-table image using
// the same original held source as RunBounded. No callback or context token
// escapes. Full byte hashes bracket the whole image; every literal Start and
// completion freshly checks all held FD/path/ctime/extension/absence metadata.
// The caller's existing aggregate deadline is retained; each command remains
// independently capped at two seconds, including reviewed stock aggregation.
func (l *Lease) ReadBoundedClassicTables(ctx context.Context, expected netidentity.Identity, review string, paths [2]string, limit int, tables [2][]string) (result [2][][]byte, err error) {
	var zero [2][][]byte
	if l == nil || ctx == nil || expected.Validate() != nil || limit <= 0 || limit > maxOutputBytes {
		return zero, at("CLASSIC_BATCH_SCOPE", nil)
	}
	deadline, finite := ctx.Deadline()
	if !finite || time.Until(deadline) <= 0 {
		return zero, at("READ_DEADLINE", ctx.Err())
	}
	// These are the existing whole inventory budgets, not longer leaf grants.
	whole := operationTimeout
	if l.profile.stock {
		whole = 6 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, whole)
	defer cancel()
	lockCtx, stopLock := context.WithTimeout(c, operationTimeout)
	lockErr := l.lock(lockCtx)
	stopLock()
	if lockErr != nil {
		return zero, lockErr
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	if l.review == nil || l.provider == nil || review == "" || review != l.digest || expected != l.identity || paths != l.profile.aliases {
		return zero, at("CLASSIC_BATCH_SCOPE", nil)
	}
	b := &classicTableReadBatch{lease: l, active: true}
	b.self = b
	for family := range tables {
		if len(tables[family]) > 64 {
			return zero, at("CLASSIC_BATCH_TABLES", nil)
		}
		seen := map[string]bool{}
		for _, table := range slices.Clone(tables[family]) {
			if !readArguments([]string{"-t", table, "-S"}) || seen[table] {
				return zero, at("CLASSIC_BATCH_TABLES", nil)
			}
			seen[table] = true
			b.commands = append(b.commands, classicTableReadCommand{family, table})
		}
	}
	if len(b.commands) == 0 {
		return zero, at("CLASSIC_BATCH_TABLES", nil)
	}
	defer func() { b.active = false }()
	err = l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
		if actual != expected || !l.profile.acceptsIdentity(actual) {
			return at("READ_IDENTITY", nil)
		}
		if err := l.classicBatchBytesCurrent(held); err != nil {
			return err
		}
		scoped, stop := context.WithCancel(held)
		defer stop()
		b.ctx = scoped
		remaining := limit
		var observed error
		for i, command := range b.commands {
			var output []byte
			output, observed = b.read(scoped, l, i, remaining)
			if observed != nil {
				break
			}
			remaining -= len(output)
			result[command.family] = append(result[command.family], output)
		}
		return errors.Join(observed, l.classicBatchBytesCurrent(held), held.Err())
	})
	if err != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return zero, at("CLASSIC_BATCH_READ", errors.Join(err, c.Err(), l.lifetime.Err()))
	}
	return result, nil
}

func (l *Lease) classicBatchBytesCurrent(ctx context.Context) error {
	leaf, cancel, err := boundedReadContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	return errors.Join(l.readObservationBytesCurrent(leaf), leaf.Err())
}

func (b *classicTableReadBatch) read(ctx context.Context, l *Lease, index, limit int) ([]byte, error) {
	if b == nil || b.self != b || !b.active || ctx == nil || ctx != b.ctx || ctx.Err() != nil || b.lease != l || l == nil || l.review == nil || l.closed.Load() || l.lifetime == nil || l.lifetime.Err() != nil || index != b.next || index < 0 || index >= len(b.commands) || limit <= 0 || limit > maxOutputBytes {
		return nil, at("CLASSIC_BATCH_SCOPE", nil)
	}
	spec := b.commands[index]
	if spec.family < 0 || spec.family > 1 || !readArguments([]string{"-t", spec.table, "-S"}) {
		return nil, at("CLASSIC_BATCH_SCOPE", nil)
	}
	name, image := l.commandImage(spec.family)
	if image == nil || name != l.profile.aliases[spec.family] {
		return nil, at("CLASSIC_BATCH_IMAGE", nil)
	}
	c, cancel, err := boundedReadContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := l.review.versionMetadataCurrent(c); err != nil {
		return nil, err
	}
	stdout, stderr := &output{limit: limit, cancel: cancel}, &output{limit: min(limit, 4096), cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", "-t", spec.table, "-S")
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
	runErr := l.runObservedRead(c, command)
	if command.Process != nil {
		domainNativeToolStarted("original-read-classic-batch")
	}
	var observed error
	if runErr != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || c.Err() != nil {
		observed = commandResultFailure("COMMAND_RESULT", runErr, c.Err(), stdout.overflow, stderr.overflow, len(stderr.data) != 0)
	}
	closing := l.review.versionMetadataCurrent(c)
	if observed != nil || closing != nil {
		return nil, errors.Join(observed, closing)
	}
	b.next++
	return stdout.data, nil
}
