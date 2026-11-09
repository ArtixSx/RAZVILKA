//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// Exact original numeric RPDB reads only. All command/FD/output/source and
// sole-Wait checks match execute; only full bytes move to the existing outer
// observation. Actual complete metadata remains before and after each child.
func (l *Lease) executeNFQWSLANRPDB(ctx context.Context, s *nfqLANRPDBScope, args []string) ([]byte, error) {
	if l == nil || s == nil || s.lease != l || l.profile.stock || !ipReadArguments(args) {
		return nil, at("NFQ_LAN_RPDB_SCOPE", nil)
	}
	s.mu.Lock()
	err := s.currentLocked(ctx, s.runner)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	name, image := l.commandImage(2)
	if name == "" || image == nil || ctx.Err() != nil || l.closed.Load() || l.lifetime.Err() != nil {
		return nil, at("COMMAND_SCOPE", nil)
	}
	if err := l.readObservationBytesCurrent(ctx); err != nil {
		return nil, err
	}
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout, stderr := &output{limit: maxOutputBytes, cancel: cancel}, &output{limit: 4096, cancel: cancel}
	command := exec.CommandContext(c, "/proc/self/fd/3", args...)
	command.Args[0], command.Env, command.Dir = name, l.profile.environment(), "/"
	command.ExtraFiles = []*os.File{image.file}
	command.Stdout, command.Stderr, command.WaitDelay = stdout, stderr, 100*time.Millisecond
	defer func() {
		if command.Process != nil {
			domainNativeToolStarted("original-read")
		}
	}()
	if err := l.runObservedRead(c, command); err != nil || stdout.overflow || stderr.overflow || len(stderr.data) != 0 || c.Err() != nil {
		return nil, commandResultFailure("COMMAND_RESULT", err, c.Err(), stdout.overflow, stderr.overflow, len(stderr.data) != 0)
	}
	if err := l.readObservationBytesCurrent(c); err != nil {
		return nil, err
	}
	return stdout.data, nil
}
