//go:build linux

package dataplane

import (
	"bytes"
	"context"
)

// Retain the original staged inode before the only admitted rename. A failed
// ACK does not cause a pathname read to become a replacement writer owner.
func (n *mihomoLiveSidecar) publishIdentity(ctx context.Context, index int, name string, data []byte) error {
	if index < 0 || index >= len(n.identities) || n.identities[index] != nil {
		return errMihomoLiveMaterial
	}
	d := &mihomoLiveSidecarIdentityFile{name: name, temporary: name + ".pending", data: bytes.Clone(data)}
	n.identities[index] = d
	return publishMihomoLiveFile(ctx, n.root, n.owner, d)
}

func (n *mihomoLiveSidecar) identityFileCurrent(d *mihomoLiveSidecarIdentityFile, name string) error {
	return mihomoLiveFileCurrent(n.root, d, name)
}

// Called only after the exact original child's sole Wait. Both possible
// names are compared to the original authored inode, including failed ACKs.
func (n *mihomoLiveSidecar) removeIdentity(ctx context.Context, index int, remove func(func() error) error) error {
	d := n.identities[index]
	if err := removeMihomoLiveFile(ctx, n.root, d, remove); err != nil {
		return err
	}
	n.identities[index] = nil
	return nil
}
