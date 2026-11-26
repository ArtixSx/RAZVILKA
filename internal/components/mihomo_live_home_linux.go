//go:build linux

package components

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const MihomoLiveHomeReceiptName = ".razvilka-origin-v1.json"

func (n *mihomoLiveNativeLinux) createHomeReceipt(ctx context.Context) error {
	parent, err := n.parent.RootInfo()
	if err != nil {
		return err
	}
	ps, ok := parent.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrMihomoLiveOwner
	}
	hs, ok := n.homeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrMihomoLiveOwner
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	// Receipt contains no node credentials or profile bytes.
	receipt := MihomoLiveHomeReceipt{Schema: 1, Source: n.owner.source.Reference(), ProfileSHA: n.owner.profile.configSHA, Nonce: hex.EncodeToString(nonce[:]), ParentDevice: uint64(ps.Dev), ParentInode: ps.Ino, Device: uint64(hs.Dev), Inode: hs.Ino}
	n.homeReceiptRaw, err = json.Marshal(receipt)
	if err != nil {
		return err
	}
	root, err := ownedfs.Open(filepath.Join(os.TempDir(), n.name))
	if err != nil {
		return err
	}
	defer root.Close()
	// Exclusive creation, same actual directory inode, never adopt a receipt.
	actual, err := root.RootInfo()
	if err != nil || !os.SameFile(actual, n.homeInfo) {
		return ErrMihomoLiveOwner
	}
	f, err := root.OpenFile(MihomoLiveHomeReceiptName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	n.homeReceipt = f
	count, writeErr := f.Write(n.homeReceiptRaw)
	if writeErr == nil && count != len(n.homeReceiptRaw) {
		writeErr = io.ErrShortWrite
	}
	n.homeReceiptInfo, err = f.Stat()
	if err = errors.Join(err, writeErr, f.Sync(), root.Sync(), ctx.Err()); err != nil {
		return err
	}
	n.homeRef = MihomoLiveHomeReference{Schema: 1, Parent: filepath.Clean(os.TempDir()), Name: n.name, ParentDevice: uint64(ps.Dev), ParentInode: ps.Ino, Device: uint64(hs.Dev), Inode: hs.Ino, ReceiptSHA256: digest(n.homeReceiptRaw)}
	return n.homeRef.Validate()
}
func (n *mihomoLiveNativeLinux) homeReceiptCurrent() error {
	if n.homeReceipt == nil || n.homeReceiptInfo == nil || n.homeRef.Validate() != nil {
		return ErrMihomoLiveOwner
	}
	held, err := n.homeReceipt.Stat()
	named, namedErr := n.parent.Stat(filepath.Join(n.name, MihomoLiveHomeReceiptName))
	if err != nil || namedErr != nil || !os.SameFile(held, n.homeReceiptInfo) || !os.SameFile(named, held) || held.Mode().Perm() != 0600 || named.Mode() != held.Mode() || held.Size() != int64(len(n.homeReceiptRaw)) || named.Size() != held.Size() {
		return ErrMihomoLiveOwner
	}
	raw := make([]byte, len(n.homeReceiptRaw))
	count, err := n.homeReceipt.ReadAt(raw, 0)
	if err != nil || count != len(raw) || !bytes.Equal(raw, n.homeReceiptRaw) || digest(raw) != n.homeRef.ReceiptSHA256 {
		return ErrMihomoLiveOwner
	}
	return nil
}
func (n *mihomoLiveNativeLinux) homeReference(ctx context.Context) (MihomoLiveHomeReference, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := errors.Join(ctx.Err(), n.filesCurrent(ctx)); err != nil {
		return MihomoLiveHomeReference{}, err
	}
	return n.homeRef, nil
}
