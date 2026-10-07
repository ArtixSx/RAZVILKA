//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

// ReadReviewedStockInterfaces is a fixed, bounded, read-only NDMC observation.
// Only the concrete reviewed stock provider can issue it. The returned text
// supplies facts, never a retained capability, Home inference or effect grant.
func (p *Provider) ReadReviewedStockInterfaces(ctx context.Context) ([]byte, error) {
	if p == nil || p.profile == nil || p.profile.hash() != nc1812Profile().hash() {
		return nil, ErrUnknown
	}
	var result []byte
	err := p.WithCurrent(ctx, func(c context.Context, identity Identity) error {
		if identity.Kind != ReviewedSingleInitNet {
			return ErrUnknown
		}
		_, nodes, err := protectedPath("/etc")
		if err != nil {
			return ErrUnknown
		}
		if _, err := os.Lstat("/etc/ld.so.preload"); !errors.Is(err, os.ErrNotExist) {
			return ErrUnknown
		}
		images := &systemImages{seen: map[string]bool{}}
		defer images.close()
		image, err := images.open(c, "/bin/ndmc", true)
		if err != nil || images.dependencies(c, image) != nil || !images.unchanged(c) {
			return ErrUnknown
		}
		stdout, stderr := &cappedOutput{limit: 1 << 20}, &cappedOutput{limit: 1024}
		command := exec.CommandContext(c, "/proc/self/fd/3", "-c", "show interface")
		command.Args[0] = "/bin/ndmc"
		command.ExtraFiles = []*os.File{image.file}
		command.Env = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "LD_LIBRARY_PATH=/lib:/usr/lib", "LANG=C", "LC_ALL=C"}
		command.Dir = "/"
		command.Stdout, command.Stderr = stdout, stderr
		command.WaitDelay = 50 * time.Millisecond
		if command.Run() != nil || stdout.exceeded || stderr.exceeded || len(stderr.data) != 0 || len(stdout.data) == 0 || c.Err() != nil || !images.unchanged(c) {
			return ErrUnknown
		}
		if _, err := os.Lstat("/etc/ld.so.preload"); !errors.Is(err, os.ErrNotExist) || !nodesUnchanged(nodes) {
			return ErrUnknown
		}
		result = append([]byte(nil), stdout.data...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
