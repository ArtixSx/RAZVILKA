package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

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
	output, err := a.run(ctx, a.ip(), "-j", "link", "show", "dev", a.Interface)
	if err != nil {
		output, err = a.run(ctx, a.ip(), "-j", "link", "show")
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
