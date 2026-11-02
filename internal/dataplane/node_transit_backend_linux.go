//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readNodeRouterProc(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrNodeTransitUnavailable
	}
	return raw, nil
}

// Read-only capability check. Production never rewrites host sysctls for a
// health probe. Strict reverse filtering needs a separately supported verifier.
func nodeRouterReturnPath(ctx context.Context, device string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !proxyFirewallInterface.MatchString(device) || device == "lo" {
		return ErrNodeTransitUnavailable
	}
	values := map[string]int{}
	for _, name := range []string{"all", "default", device} {
		for _, setting := range []string{"rp_filter", "src_valid_mark"} {
			raw, err := readNodeRouterProc(filepath.Join("/proc/sys/net/ipv4/conf", name, setting), 16)
			if err != nil || len(raw) > 16 {
				return ErrNodeTransitUnavailable
			}
			value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			limit := 2
			if setting == "src_valid_mark" {
				limit = 1
			}
			if err != nil || value < 0 || value > limit {
				return ErrNodeTransitUnavailable
			}
			values[name+"/"+setting] = value
		}
	}
	if max(values["all/rp_filter"], values[device+"/rp_filter"]) == 1 {
		return errors.New("strict reverse-path capability is unsupported for router TUN health")
	}
	return ctx.Err()
}

func (a *ProxyTunnelAdapter) nodeRouterBackendDisjoint(ctx context.Context, manifest proxyNodeManifest, source, pin netip.Addr) error {
	endpoints := map[netip.Addr]bool{}
	for _, endpoint := range manifest.Endpoints {
		address, err := netip.ParseAddr(endpoint.IP)
		if err != nil || address == pin || address == source {
			return nodeTransitPhase("backend-endpoint", ErrNodeTransitUnavailable)
		}
		endpoints[address] = true
	}
	if len(endpoints) == 0 {
		return nodeTransitPhase("backend-empty-endpoints", ErrNodeTransitUnavailable)
	}
	for index, spec := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		phase := "backend-engine"
		if index == 1 {
			phase = "backend-sidecar"
		}
		if err := func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, err := a.verifyNodeProcess(spec, ""); err != nil {
				return nodeTransitPhase("backend-process-initial", err)
			}
			pid, err := readManagedPID(spec)
			if err != nil {
				return nodeTransitPhase("backend-managed-pid", err)
			}
			return inspectOriginalNodeRouterBackendSockets(ctx, pid, source, pin, endpoints, func(c context.Context) error {
				_, err := a.verifyNodeProcess(spec, "")
				return err
			})
		}(); err != nil {
			return nodeTransitPhase(phase, err)
		}
	}
	return ctx.Err()
}
