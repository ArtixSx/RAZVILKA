package components

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// Comparison data only. A path/inode/receipt cannot construct a warm owner or
// grant deletion. Cold retirement also requires original parent lineage,
// complete native absence and its independent exclusive maintenance role.
type MihomoLiveHomeReference struct {
	Schema        int    `json:"schema"`
	Parent        string `json:"parent"`
	Name          string `json:"name"`
	ParentDevice  uint64 `json:"parent_device"`
	ParentInode   uint64 `json:"parent_inode"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}

// Comparison receipt only; no serialized record grants deletion.
type MihomoLiveHomeReceipt struct {
	Schema       int                 `json:"schema"`
	Source       MihomoLiveReference `json:"source"`
	ProfileSHA   string              `json:"profile_sha256"`
	Nonce        string              `json:"nonce"`
	ParentDevice uint64              `json:"parent_device"`
	ParentInode  uint64              `json:"parent_inode"`
	Device       uint64              `json:"device"`
	Inode        uint64              `json:"inode"`
}

func (r MihomoLiveHomeReference) Validate() error {
	if r.Schema != 1 || !filepath.IsAbs(r.Parent) || filepath.Clean(r.Parent) != r.Parent || !strings.HasPrefix(r.Name, ".razvilka-mihomo-live-") || filepath.Base(r.Name) != r.Name || r.ParentInode == 0 || r.Inode == 0 || len(r.ReceiptSHA256) != 64 {
		return ErrMihomoLiveOwner
	}
	for _, c := range r.ReceiptSHA256 {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return ErrMihomoLiveOwner
			}
		}
	}
	return nil
}

// PrepareNative creates private descriptors only, while the caller already
// retains this child. It must be journaled before any validation Cmd.Start.
func (p *MihomoLiveProcess) PrepareNative(ctx context.Context) error {
	if p == nil || p.self != p || mihomoLiveFinite(ctx) != nil {
		return ErrMihomoLiveOwner
	}
	if err := errors.Join(p.source.Current(ctx), p.control.Current(ctx)); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.startUsed {
		return ErrMihomoLiveOwner
	}
	if p.native == nil {
		var err error
		p.native, err = newMihomoLiveNative(ctx, p)
		if err != nil {
			return err
		}
	}
	_, err := p.native.homeReference(ctx)
	return err
}
func (p *MihomoLiveProcess) NativeHomeReference(ctx context.Context) (MihomoLiveHomeReference, error) {
	if p == nil || p.self != p {
		return MihomoLiveHomeReference{}, ErrMihomoLiveOwner
	}
	if err := errors.Join(p.source.Current(ctx), p.control.ObserveCurrent(ctx)); err != nil {
		return MihomoLiveHomeReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.native == nil || p.closeErr != nil {
		return MihomoLiveHomeReference{}, ErrMihomoLiveOwner
	}
	return p.native.homeReference(ctx)
}
