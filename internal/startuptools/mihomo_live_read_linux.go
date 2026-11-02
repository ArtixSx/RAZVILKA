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

func (l *Lease) runMihomoLiveRead(original context.Context, name string, args ...string) ([]byte, error) {
	if err := l.retain(original); err != nil {
		return nil, err
	}
	defer l.retained.Done()
	if l.review == nil || l.provider == nil || l.digest == "" {
		return nil, at("MIHOMO_READ_UNISSUED", nil)
	}
	c, cancel, err := boundedReadContext(original)
	if err != nil {
		return nil, err
	}
	defer cancel()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	index := -1
	for i, alias := range l.profile.aliases {
		if alias == name {
			index = i
		}
	}
	if name == l.profile.ipAlias {
		index = 2
	}
	frozen := slices.Clone(args)
	if !mihomoLiveReadArguments(index, frozen) {
		return nil, at("MIHOMO_READ_ABI", nil)
	}
	frozen = mihomoLiveCanonicalReadArguments(index, frozen)
	if err = l.lock(c); err != nil {
		return nil, err
	}
	defer l.unlock()
	var data []byte
	err = l.provider.WithCurrent(c, func(held context.Context, actual netidentity.Identity) error {
		if actual != l.identity || !l.profile.acceptsIdentity(actual) || l.closed.Load() || l.lifetime.Err() != nil {
			return at("MIHOMO_READ_IDENTITY", nil)
		}
		if err := l.review.unchanged(held); err != nil {
			return err
		}
		alias, image := l.commandImage(index)
		if alias != name || image == nil {
			return at("MIHOMO_READ_ALIAS", nil)
		}
		combined := &output{limit: maxOutputBytes, cancel: cancel}
		command := exec.CommandContext(c, "/proc/self/fd/3", frozen...)
		command.Args[0] = name
		command.ExtraFiles = []*os.File{image.file}
		command.Env = l.profile.environment()
		command.Dir = "/"
		// Identical writer pointers make os/exec use the SAME child pipe,
		// preserving the actual order of known failed-read diagnostics.
		command.Stdout, command.Stderr = combined, combined
		command.WaitDelay = 100 * time.Millisecond
		commandErr := l.runObservedRead(held, command)
		closing := l.review.unchanged(held)
		if combined.overflow || closing != nil || c.Err() != nil {
			return at("MIHOMO_READ_RESULT", errors.Join(commandErr, closing, c.Err()))
		}
		data = append([]byte(nil), combined.data...)
		if commandErr != nil {
			return at("MIHOMO_READ_RESULT", commandErr)
		}
		return nil
	})
	if c.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("MIHOMO_READ_SCOPE", errors.Join(err, c.Err()))
	}
	return data, err
}
