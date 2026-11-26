//go:build linux

package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// /bin/sh on Keenetic is firmware CLI, not a POSIX parser. Production Entware
// scripts must use its own exact root-owned interpreter; generic Linux model
// installations retain the system POSIX shell without weakening alias guards.
func reviewScriptInterpreter(installation string) (string, string, func() error, error) {
	if installation == "/opt" {
		return reviewOwnedScriptInterpreter("/opt/bin/sh", "/opt/bin/busybox", "/")
	}
	path, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		return "", "", nil, err
	}
	return reviewOwnedScriptInterpreter(path, path, "/")
}

func reviewOwnedScriptInterpreter(alias, busybox, boundary string) (string, string, func() error, error) {
	aliasGeneration, err := os.Lstat(alias)
	if err != nil {
		return "", "", nil, err
	}
	aliasCurrent, err := reviewOwnedDaemonPath(alias, busybox, boundary)
	if err != nil {
		return "", "", nil, err
	}
	info, err := os.Lstat(alias)
	if err != nil {
		return "", "", nil, err
	}
	path := alias
	if info.Mode()&os.ModeSymlink != 0 {
		path = busybox
	}
	sha, err := hashRegularFile(path, MaximumBinaryBytes)
	if err != nil {
		return "", "", nil, err
	}
	targetGeneration, err := os.Lstat(path)
	if err != nil {
		return "", "", nil, err
	}
	generationCurrent := func() error {
		link, err := os.Lstat(alias)
		if err != nil || !sameScriptInterpreterGeneration(aliasGeneration, link) {
			return errOrdinaryPreparation
		}
		target, err := os.Lstat(path)
		if err != nil || !sameScriptInterpreterGeneration(targetGeneration, target) {
			return errOrdinaryPreparation
		}
		return aliasCurrent()
	}
	current := func() error {
		if err := generationCurrent(); err != nil {
			return err
		}
		actual, err := hashRegularFile(path, MaximumBinaryBytes)
		if err != nil || actual != sha {
			return errOrdinaryPreparation
		}
		// Close the observation with the same generation checks, not only
		// the legacy inode/mode guard: an inode may be reused during hashing.
		return generationCurrent()
	}
	if err := current(); err != nil {
		return "", "", nil, err
	}
	return path, sha, current, nil
}

func runReviewedScriptSyntax(ctx context.Context, installation, script string, admission func(context.Context, string, func() error) error, before, tick, after func() error) error {
	path, sha, current, err := reviewScriptInterpreter(installation)
	if err != nil {
		return err
	}
	return runPinnedScriptSyntax(ctx, path, sha, script, current, admission, before, tick, after)
}

func runPinnedScriptSyntax(ctx context.Context, path, sha, script string, current func() error, admission func(context.Context, string, func() error) error, before, tick, after func() error) error {
	if current == nil || admission == nil || before == nil || tick == nil || after == nil {
		return errOrdinaryPreparation
	}
	wrap := func(owner func() error) func() error {
		return func() error {
			if err := current(); err != nil {
				return err
			}
			if err := owner(); err != nil {
				return err
			}
			return current()
		}
	}
	admit := func(c context.Context, effect string, begin func() error) error {
		return admission(c, effect, func() error {
			// The owner admission may wait. Recheck the reviewed alias and
			// image inside its actual Start callback, without reentering the
			// owner's control lock or substituting another execution path.
			if err := current(); err != nil {
				return err
			}
			return begin()
		})
	}
	output, err := ordinaryImageCommand(ctx, path, sha, []string{"-n", script}, "ordinary-prepare-syntax", admit, wrap(before), wrap(tick), wrap(after))
	if err != nil || output != "" {
		return errors.Join(errOrdinaryPreparation, err)
	}
	return nil
}

// Keep command supervision with the existing caller. This constructor changes
// only interpreter selection and pins its actual executable descriptor; it
// supplies no process receipt, effect admission or alternative Wait owner.
func newReviewedScriptCommand(ctx context.Context, installation string, args []string) (*exec.Cmd, func() error, func(), error) {
	path, sha, reviewCurrent, err := reviewScriptInterpreter(installation)
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, nil, nil, err
	}
	program, err := root.OpenFile(filepath.Base(path), os.O_RDONLY, 0)
	root.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			program.Close()
		}
	}()
	held, err := program.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Mode().Perm()&0100 == 0 || held.Size() > MaximumBinaryBytes {
		return nil, nil, nil, errOrdinaryPreparation
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(program, MaximumBinaryBytes+1))
	if err != nil || n > MaximumBinaryBytes || hex.EncodeToString(hash.Sum(nil)) != sha {
		return nil, nil, nil, errOrdinaryPreparation
	}
	if _, err := program.Seek(0, io.SeekStart); err != nil {
		return nil, nil, nil, err
	}
	current := func() error {
		if err := reviewCurrent(); err != nil {
			return err
		}
		now, err := os.Lstat(path)
		if err != nil || !os.SameFile(held, now) {
			return errOrdinaryPreparation
		}
		return nil
	}
	if err := current(); err != nil {
		return nil, nil, nil, err
	}
	var command *exec.Cmd
	if ctx == nil {
		command = exec.Command("/proc/self/fd/3", args...)
	} else {
		command = exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	}
	command.Args[0] = "/bin/sh" // BusyBox dispatches its POSIX shell applet by argv[0].
	command.ExtraFiles = []*os.File{program}
	failed = false
	return command, current, func() { _ = program.Close() }, nil
}

// An unlink/recreate may immediately reuse an inode. Retain ctime and the
// original metadata generation as well as inode identity; a new alias cannot
// silently inherit an old parser review just because it points to the same file.
func sameScriptInterpreterGeneration(before, after os.FileInfo) bool {
	if before == nil || after == nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	b, bok := before.Sys().(*syscall.Stat_t)
	a, aok := after.Sys().(*syscall.Stat_t)
	return bok && aok && b.Uid == a.Uid && b.Gid == a.Gid && b.Nlink == a.Nlink && b.Ctim == a.Ctim
}
