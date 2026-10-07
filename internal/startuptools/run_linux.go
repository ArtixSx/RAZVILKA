//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (l *Lease) execute(ctx context.Context, index, limit int, args ...string) ([]byte, error) {
	name, image := l.commandImage(index)
	if name == "" || image == nil || limit <= 0 || limit > maxOutputBytes || ctx.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("COMMAND_SCOPE", nil)
	}
	if err := l.review.unchanged(ctx); err != nil {
		return nil, err
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout, stderr := &output{limit: limit, cancel: cancel}, &output{limit: min(limit, 4096), cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", args...)
	// Execute the genuine held entry fd. argv[0] preserves its fixed alias,
	// including the xtables family/legacy selection required by multicall.
	command.Args[0] = name
	command.ExtraFiles = []*os.File{image.file}
	command.Env = l.profile.environment()
	command.Dir = "/"
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = 100 * time.Millisecond
	if err := command.Run(); err != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || c.Err() != nil {
		return nil, commandResultFailure("COMMAND_RESULT", err, c.Err(), stdout.overflow, stderr.overflow, len(stderr.data) != 0)
	}
	if err := l.review.unchanged(c); err != nil {
		return nil, err
	}
	return stdout.data, nil
}

func (l *Lease) commandImage(index int) (string, *heldImage) {
	if l.review == nil {
		return "", nil
	}
	if index >= 0 && index < len(l.profile.aliases) {
		return l.profile.aliases[index], l.review.entry[index]
	}
	if index == 2 && l.profile.ipAlias != "" {
		return l.profile.ipAlias, l.review.ipEntry
	}
	return "", nil
}

func (l *Lease) ipVersion(ctx context.Context) error {
	data, err := l.execute(ctx, 2, 256, "-Version")
	if err != nil || string(data) != l.profile.ipVersion {
		return at("IP_VERSION", err)
	}
	return ctx.Err()
}

func (l *Lease) version(ctx context.Context, index int) error {
	data, err := l.execute(ctx, index, 256, "--version")
	name := [2]string{"iptables", "ip6tables"}[index]
	if err != nil || string(data) != name+" v"+l.profile.version+"\n" {
		return at("BACKEND_VERSION", err)
	}
	return ctx.Err()
}

func (l *Lease) RunBounded(ctx context.Context, name string, limit int, args ...string) ([]byte, error) {
	if ctx == nil || !readArguments(args) || limit <= 0 || limit > maxOutputBytes {
		return nil, at("READ_ABI", nil)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > operationTimeout {
		return nil, at("READ_DEADLINE", nil)
	}
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return nil, err
	}
	defer l.unlock()
	index := -1
	for i, alias := range l.profile.aliases {
		if name == alias {
			index = i
		}
	}
	if index < 0 || l.review == nil || l.provider == nil {
		return nil, at("READ_ALIAS", nil)
	}
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	var data []byte
	err := l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
		if actual != l.identity || !l.profile.acceptsIdentity(actual) {
			return at("READ_IDENTITY", nil)
		}
		var err error
		data, err = l.execute(held, index, limit, args...)
		if err != nil {
			return err
		}
		return held.Err()
	})
	if err != nil || c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("READ", errors.Join(err, c.Err()))
	}
	return append([]byte(nil), data...), nil
}
