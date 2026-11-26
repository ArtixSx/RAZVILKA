package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const proxyPartialStopFile = "partial-stop-interface.v1"

type partialStopAction int

const (
	partialStopBegin partialStopAction = iota
	partialStopObserve
	partialStopFinish
)

func (a *ProxyTunnelAdapter) requirePartialStopComplete() error {
	if _, err := os.Lstat(filepath.Join(a.StateRoot, proxyPartialStopFile)); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrProxyPolicyUnknown, errors.New("previous Stop requires interface readback"), err)
	}
	return nil
}

func (a *ProxyTunnelAdapter) verifyReleasedTunnel(ctx context.Context) error {
	if _, err := a.scopedOSInterfaceIndex(ctx); !errors.Is(err, errNodeInterfaceAbsent) {
		return errors.Join(ErrProxyPolicyUnknown, fmt.Errorf("cannot confirm removal of interface %s", a.Interface), err)
	}
	return ctx.Err()
}

// A partial Stop may consume the only PID or forwarding lease before it can
// verify the TUN release. This record only requests another observation.
// It never conveys authority to remove a link, firewall rule, or process.
func (a *ProxyTunnelAdapter) partialStopInterface(ctx context.Context, action partialStopAction) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := ownedfs.Open(a.StateRoot)
	if action != partialStopBegin && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	owner, err := root.RootInfo()
	if err != nil {
		return err
	}
	defer func() {
		if result == nil {
			current, err := os.Lstat(a.StateRoot)
			if err != nil || !os.SameFile(owner, current) {
				result = errors.Join(ErrProxyPolicyUnknown, err)
			}
		}
	}()
	want := "release-tun-v1 " + a.ID() + " " + a.Interface + "\n"
	image, identity, err := readProxyXrayImage(root, proxyPartialStopFile, 256)
	if err != nil {
		return err
	}
	if !image.exists {
		if action != partialStopBegin {
			return nil
		}
		if err := root.WriteAtomic(proxyPartialStopFile, []byte(want), 0600); err != nil {
			return err
		}
		image, _, err = readProxyXrayImage(root, proxyPartialStopFile, 256)
		if err != nil {
			return err
		}
	}
	if string(image.data) != want {
		return ErrProxyPolicyUnknown
	}
	if action == partialStopBegin {
		if err := ctx.Err(); err != nil {
			return err
		}
		return syncDataplaneJournalDirectory(root)
	}
	if err := a.verifyReleasedTunnel(ctx); err != nil {
		return err
	}
	closing, current, err := readProxyXrayImage(root, proxyPartialStopFile, 256)
	if err != nil || !closing.exists || !os.SameFile(identity, current) || string(closing.data) != want {
		return errors.Join(ErrProxyPolicyUnknown, err)
	}
	if action == partialStopObserve {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Remove(proxyPartialStopFile); err != nil {
		return err
	}
	return syncDataplaneJournalDirectory(root)
}
