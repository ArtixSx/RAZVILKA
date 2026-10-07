//go:build linux

package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func (a *SelfUpdateFileAdapter) confirmFileLiveHealth(ctx context.Context, review fileReview, runtime fileProcess, version string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	root, err := ownedfs.Open(a.installation)
	if err != nil {
		return ErrFileProtocol
	}
	defer root.Close()
	image, err := root.OpenFile("bin/razvilka", os.O_RDONLY, 0)
	if err != nil {
		return ErrFileProtocol
	}
	defer image.Close()
	verify := func() error {
		if err := a.Authority(probeCtx, review.ID, review.Revision); err != nil {
			return err
		}
		if fileProcessMatches(runtime) != nil {
			return ErrFileProtocol
		}
		info, err := image.Stat()
		path, pathErr := root.Stat("bin/razvilka")
		proc, procErr := os.Stat("/proc/" + strconv.Itoa(runtime.PID) + "/exe")
		if err != nil || pathErr != nil || procErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || !os.SameFile(info, path) || !os.SameFile(info, proc) {
			return ErrFileProtocol
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Size() > MaximumBinaryBytes {
			return ErrFileProtocol
		}
		if _, err := image.Seek(0, io.SeekStart); err != nil {
			return ErrFileProtocol
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(image, MaximumBinaryBytes+1))
		if err != nil || n > MaximumBinaryBytes || hex.EncodeToString(hash.Sum(nil)) != runtime.ExecutableSHA256 {
			return ErrFileProtocol
		}
		return probeCtx.Err()
	}
	if err := verify(); err != nil {
		return err
	}
	command, err := os.Open("/proc/" + strconv.Itoa(runtime.PID) + "/cmdline")
	if err != nil {
		return ErrFileProtocol
	}
	data, readErr := io.ReadAll(io.LimitReader(command, 8193))
	command.Close()
	if readErr != nil || len(data) == 0 || len(data) > 8192 || data[len(data)-1] != 0 {
		return ErrFileProtocol
	}
	endpoint, err := fileLiveEndpoint(strings.Split(string(data[:len(data)-1]), "\x00"))
	if err != nil {
		return err
	}
	for _, recipe := range []struct {
		effect, endpoint, output string
		pid                      int
	}{{fileLiveVersionEffect, "", version + "\n", 0}, {fileLiveHealthEffect, endpoint, "healthy: " + version + "\n", runtime.PID}} {
		if err := verify(); err != nil {
			return err
		}
		output, err := a.runFileLiveProbe(probeCtx, review.ID, image, recipe.effect, recipe.endpoint, recipe.pid)
		if err != nil || output != recipe.output {
			return errors.Join(ErrFileProtocol, err)
		}
		if err := verify(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (a *SelfUpdateFileAdapter) runFileLiveProbe(ctx context.Context, id string, image *os.File, effect, endpoint string, pid int) (string, error) {
	args, err := fileLiveProbeArgs(effect, endpoint, pid)
	if err != nil || image == nil {
		return "", ErrFileProtocol
	}
	// Inherit the reviewed descriptor as fd3. A replaced pathname cannot
	// select another executable between verification and actual Cmd.Start.
	commandCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(commandCtx, "/proc/self/fd/3", args...)
	command.ExtraFiles = []*os.File{image}
	command.Env = commandEnvironment()
	stdout, stderr := &cappedOutput{maximum: 128}, &cappedOutput{maximum: 1024}
	command.Stdout, command.Stderr = stdout, stderr
	configureBoundedCommand(command)
	_, done, admissionErr := startInstallerHelperCommand(commandCtx, command, func(begin func() error) error {
		return a.EffectAdmission(commandCtx, id, "start/live", effect, begin)
	})
	if done == nil {
		return "", errors.Join(ErrFileProtocol, admissionErr)
	}
	if admissionErr != nil {
		cancel()
		cleanupCommand(command)
	}
	// Wait/cleanup occur after CORE's protected control lock has released.
	var waitErr, revokeErr error
	if admissionErr != nil {
		waitErr = <-done
	} else {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		joined := false
		for !joined {
			select {
			case waitErr = <-done:
				joined = true
			case <-ctx.Done():
				revokeErr = ctx.Err()
			case <-tick.C:
				revokeErr = a.checkStop(ctx, id, "start/live")
			}
			if revokeErr != nil && !joined {
				cancel()
				cleanupCommand(command)
				waitErr = <-done
				joined = true
			}
		}
	}
	if admissionErr != nil || revokeErr != nil || waitErr != nil || ctx.Err() != nil || stderr.Len() != 0 {
		return "", errors.Join(ErrFileProtocol, admissionErr, revokeErr, waitErr, ctx.Err())
	}
	if err := a.checkStop(ctx, id, "start/live"); err != nil {
		return "", err
	}
	return stdout.String(), nil
}
