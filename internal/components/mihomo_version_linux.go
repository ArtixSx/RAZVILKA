//go:build linux

package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type mihomoVersionOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *mihomoVersionOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := (8 << 10) - w.Len(); len(p) > remaining {
		w.overflow = true
		p = p[:remaining]
	}
	_, _ = w.Buffer.Write(p)
	return n, nil
}

// A version command must execute the SAME fully verified FD. The name is
// observed at bookends only; neither directory nor inode replacement can
// redirect exec to different bytes between hashing and Start.
func verifyMihomoArtifactRelease(parent context.Context, artifacts string, image restorejournal.Image, start func(context.Context, func() error) error) (err error) {
	if parent == nil || start == nil {
		return restorejournal.ErrInvalid
	}
	ref, err := mihomoArtifactReferenceOf(image)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	root, err := ownedfs.Open(artifacts)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	anchor, err := root.RootInfo()
	if _, ok := hevRetainedOwner(anchor, true); err != nil || !ok {
		return restorejournal.ErrConflict
	}
	name := ref.SHA256 + ".bin"
	f, err := root.OpenFile(name, hevRetainedReadFlags, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	original, err := f.Stat()
	if err != nil || !mihomoArtifactOwner(original) || original.Size() != ref.Size {
		return restorejournal.ErrConflict
	}
	current := func() error {
		namedRoot, e := os.Lstat(artifacts)
		heldRoot, he := root.RootInfo()
		named, ne := root.Stat(name)
		held, fe := f.Stat()
		if e != nil || he != nil || ne != nil || fe != nil || !os.SameFile(anchor, namedRoot) || !os.SameFile(anchor, heldRoot) || anchor.Mode() != namedRoot.Mode() || !os.SameFile(original, named) || !os.SameFile(original, held) || !mihomoArtifactOwner(named) || !mihomoArtifactOwner(held) || held.Size() != original.Size() || named.Size() != original.Size() || !held.ModTime().Equal(original.ModTime()) || !named.ModTime().Equal(original.ModTime()) {
			return restorejournal.ErrConflict
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	verifyHeldBytes := func() error {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.CopyBuffer(hash, io.LimitReader(mihomoContextReader{ctx, f}, ref.Size+1), make([]byte, 64<<10))
		if err != nil || n != ref.Size || hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
			return errors.Join(err, restorejournal.ErrConflict)
		}
		return current()
	}
	if err := verifyHeldBytes(); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-v")
	cmd.Args[0] = "mihomo"
	cmd.ExtraFiles = []*os.File{f}
	cmd.WaitDelay = time.Second
	var output mihomoVersionOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	// Only the actual Start syscall enters the original control barrier. File
	// hashing and the sole Wait remain outside it, so Stop need not wait on IO.
	started, called := false, false
	startErr := start(ctx, func() error {
		if called {
			return restorejournal.ErrInvalid
		}
		called = true
		e := cmd.Start()
		started = e == nil
		return e
	})
	if !started {
		return errors.Join(startErr, restorejournal.ErrUnavailable)
	}
	if startErr != nil {
		_ = cmd.Process.Kill()
	}
	runErr := errors.Join(startErr, cmd.Wait())
	if err := errors.Join(runErr, current()); err != nil {
		return err
	}
	if err := verifyHeldBytes(); err != nil {
		return err
	}
	fields := strings.Fields(output.String())
	if output.overflow || len(fields) < 3 || fields[0] != "Mihomo" || fields[1] != "Meta" || strings.TrimPrefix(fields[2], "v") != ReviewedMihomoVersion {
		return errors.New("Mihomo version does not match reviewed release")
	}
	return nil
}
