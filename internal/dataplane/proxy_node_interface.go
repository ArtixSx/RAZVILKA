package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

type nodeInterfaceLease struct {
	Schema     int    `json:"schema"`
	Boot       string `json:"boot"`
	Interface  string `json:"interface"`
	Index      int    `json:"ifindex"`
	ConfigHash string `json:"config_sha256"`
}

var errNodeInterfaceAbsent = errors.New("scoped interface absent")

func (a *ProxyTunnelAdapter) nodeInterfacePath() string {
	return filepath.Join(a.runtimeRoot(), "interface.json")
}

func (a *ProxyTunnelAdapter) scopedInterfaceIndex(ctx context.Context) (int, error) {
	if ctx == nil || a == nil {
		return 0, errors.New("scoped interface inventory unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	output, err := a.run(ctx, a.ip(), "-j", "link", "show", "dev", a.Interface)
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	var exited interface{ ExitCode() int }
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
		errors.As(err, &exited) && exited.ExitCode() == 255 && wgEndpointUnknownOption(output, "-j") {
		return a.scopedOSInterfaceIndex(ctx)
	}
	if err != nil {
		output, err = a.run(ctx, a.ip(), "-j", "link", "show")
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err != nil {
			return 0, err
		}
		var inventory []struct {
			Index int    `json:"ifindex"`
			Name  string `json:"ifname"`
		}
		if len(output) > 1<<20 || json.Unmarshal(output, &inventory) != nil || len(inventory) > 4096 {
			return 0, errors.New("scoped interface inventory unavailable")
		}
		for _, link := range inventory {
			if link.Name == a.Interface {
				return 0, errors.New("scoped interface exists but exact read failed")
			}
		}
		return 0, errNodeInterfaceAbsent
	}
	var links []struct {
		Index int    `json:"ifindex"`
		Name  string `json:"ifname"`
	}
	if len(output) > 4096 || json.Unmarshal(output, &links) != nil || len(links) != 1 || links[0].Index < 1 || links[0].Name != a.Interface {
		return 0, errors.New("scoped TUN ifindex readback is unavailable")
	}
	return links[0].Index, nil
}

// Old Entware iproute2 cannot print JSON. Only its exact unsupported-option
// diagnostic selects this Linux OS inventory; failed or malformed observations
// never establish absence. This reads no historical lease or command receipt.
func (a *ProxyTunnelAdapter) scopedOSInterfaceIndex(ctx context.Context) (int, error) {
	observe := a.nodeInterfaceInventory
	if observe == nil {
		if runtime.GOOS != "linux" {
			return 0, errors.New("scoped OS interface inventory unavailable")
		}
		observe = net.Interfaces
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	name := a.Interface
	links, err := observe()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err != nil || name == "" || a.Interface != name || len(links) == 0 || len(links) > 4096 {
		return 0, errors.New("scoped OS interface inventory unavailable")
	}
	names, indices := map[string]bool{}, map[int]bool{}
	loopback, index := false, 0
	for _, link := range links {
		if link.Name == "" || link.Index < 1 || names[link.Name] || indices[link.Index] {
			return 0, errors.New("scoped OS interface inventory unavailable")
		}
		names[link.Name], indices[link.Index] = true, true
		loopback = loopback || link.Name == "lo"
		if link.Name == name {
			index = link.Index
		}
	}
	if !loopback {
		return 0, errors.New("scoped OS interface inventory unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if index == 0 {
		return 0, errNodeInterfaceAbsent
	}
	return index, nil
}

func (a *ProxyTunnelAdapter) recordScopedNodeInterface(ctx context.Context) error {
	index, err := a.scopedInterfaceIndex(ctx)
	if err != nil {
		return err
	}
	boot, err := a.currentBootIdentity()
	if err != nil {
		return err
	}
	m, err := a.readNodeManifest(a.nodeManifestPath())
	if err != nil {
		return err
	}
	if _, err := a.verifyNodeProcess(a.engineProcess(), ""); err != nil {
		return err
	}
	if _, err := a.verifyNodeProcess(a.sidecarProcess(), ""); err != nil {
		return err
	}
	data, _ := json.Marshal(nodeInterfaceLease{Schema: 1, Boot: boot, Interface: a.Interface, Index: index, ConfigHash: m.ConfigHash})
	return writeAtomic(a.nodeInterfacePath(), data, 0600)
}

func (a *ProxyTunnelAdapter) verifyScopedNodeInterface(ctx context.Context) error {
	data, err := readBoundedSidecar(a.nodeInterfacePath())
	if err != nil {
		return err
	}
	var lease nodeInterfaceLease
	if json.Unmarshal(data, &lease) != nil || lease.Schema != 1 || lease.Interface != a.Interface || lease.Index < 1 {
		return errors.New("invalid scoped interface lease")
	}
	boot, err := a.currentBootIdentity()
	if err != nil || boot != lease.Boot {
		return errors.New("scoped interface belongs to another boot")
	}
	config, err := readBoundedProxyConfig(a.engineConfigPath())
	if err != nil {
		return err
	}
	defer clear(config)
	if routeidentity.Hash(config) != lease.ConfigHash {
		return errors.New("scoped interface belongs to another config")
	}
	index, err := a.scopedInterfaceIndex(ctx)
	if err != nil || index != lease.Index {
		return errors.New("scoped TUN interface was replaced")
	}
	return nil
}

func (a *ProxyTunnelAdapter) removeScopedNodeInterface(ctx context.Context) error {
	if _, err := a.scopedInterfaceIndex(ctx); err != nil {
		if errors.Is(err, errNodeInterfaceAbsent) {
			return nil
		}
		return err
	}
	if err := a.verifyScopedNodeInterface(ctx); err != nil {
		return err
	}
	if a.Processes.Running(a.sidecarProcess()) {
		return errors.New("scoped sidecar is still running")
	}
	if _, err := a.run(ctx, a.ip(), "link", "delete", "dev", a.Interface); err != nil {
		return err
	}
	if _, err := a.scopedInterfaceIndex(ctx); !errors.Is(err, errNodeInterfaceAbsent) {
		return errors.New("scoped interface absence unconfirmed after cleanup")
	}
	if err := os.Remove(a.nodeInterfacePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
