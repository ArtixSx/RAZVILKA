package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// CheckHEVReleaseIdle is bounded, read-only admission for startup and other
// component/self-update operations. It never initializes or recovers state.
func (m *Manager) CheckHEVReleaseIdle(ctx context.Context) error {
	if m == nil {
		return errors.New("original HEV component owner is required")
	}
	return m.checkHEVReleaseIdle(ctx)
}

// CheckInstalledHEV observes this manager's original pinned installation. It
// neither initializes nor recovers journals, and grants no process/route health.
func (m *Manager) CheckInstalledHEV(ctx context.Context) (path string, err error) {
	if m == nil {
		return "", errors.New("original HEV component owner is required")
	}
	if ctx == nil {
		return "", errors.New("HEV observation context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !m.mu.TryLock() {
		return "", restorejournal.ErrBusy
	}
	defer m.mu.Unlock()
	spec, _ := lookup("hev-socks5-tunnel")
	info, err := hevPinnedRelease(spec, m.Arch)
	if err != nil {
		return "", err
	}
	s, err := m.openHEVRelease(false)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, s.close()) }()
	if err := s.j.RequireIdle(ctx); err != nil {
		return "", err
	}
	binary, err := s.files["a_binary"].Read(ctx)
	if err != nil || !binary.Exists {
		return "", errors.Join(errors.New("HEV pinned executable is absent"), err)
	}
	receipt, err := s.files["b_receipt"].Read(ctx)
	if err != nil || !receipt.Exists {
		return "", errors.Join(errors.New("HEV original receipt is absent"), err)
	}
	digest := sha256.Sum256(binary.Data)
	actual := hex.EncodeToString(digest[:])
	var binding externalReceipt
	if actual != info.PinnedSHA256 || json.Unmarshal(receipt.Data, &binding) != nil || binding.Version != info.Version || binding.SHA256 != actual {
		return "", errors.New("HEV current bytes/receipt do not match official reviewed pin")
	}
	path = s.paths["a_binary"]
	if err := verifyHEVRelease(ctx, path); err != nil {
		return "", err
	}
	after, err := s.files["a_binary"].Read(ctx)
	if err != nil || !after.Exists || !bytes.Equal(after.Data, binary.Data) {
		return "", errors.Join(errors.New("HEV changed during version observation"), err)
	}
	receiptAfter, err := s.files["b_receipt"].Read(ctx)
	if err != nil || !receiptAfter.Exists || !bytes.Equal(receiptAfter.Data, receipt.Data) {
		return "", errors.Join(errors.New("HEV receipt changed during version observation"), err)
	}
	return path, nil
}
