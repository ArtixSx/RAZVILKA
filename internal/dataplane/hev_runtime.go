package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var hevVersionLine = regexp.MustCompile(`^Version: ([0-9]+\.[0-9]+\.[0-9]+)(?: [A-Za-z0-9._-]+)?$`)

// HEV has no --check mode: --version prints usage and exits 255 upstream.
// This only reviews dialect/lifecycle compatibility. It never marks the
// generated profile native_validated or creates a TUN as a syntax test.
func (a *ProxyTunnelAdapter) preflightHEVRuntime(ctx context.Context) error {
	if a.effectiveSidecar() != "hev" {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.hevInstalledCheck != nil {
		if err := a.hevInstalledCheck(ctx); err != nil {
			return err
		}
	}
	attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := a.run(attempt, a.sidecarBinary(), "--version")
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := attempt.Err(); err != nil {
		return err
	}
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 255 {
			return errors.New("HEV version observation failed")
		}
	}
	found := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if match := hevVersionLine.FindStringSubmatch(strings.TrimSpace(line)); len(match) > 0 {
			if found != "" {
				return errors.New("HEV version observation is ambiguous")
			}
			found = match[1]
		}
	}
	if found != backendprofile.ReviewedHEVVersion {
		return errors.New("HEV requires the reviewed 2.17.1 runtime; older Entware and unreviewed versions cannot use this managed dialect")
	}
	if a.hevInstalledCheck != nil {
		if err := a.hevInstalledCheck(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Every forward or rollback restart retains the same original controller,
// argv and ownership files. A dialect refusal never starts a different core.
func (a *ProxyTunnelAdapter) startOwnedSidecar(ctx context.Context) error {
	// Rollback can restore a retained sidecar image. A boot backend choice
	// must never launch that image through another dialect's executable.
	if err := a.checkSidecarIdentity(); err != nil {
		return err
	}
	if err := a.preflightHEVRuntime(ctx); err != nil {
		return err
	}
	return a.Processes.Start(ctx, a.sidecarProcess())
}
