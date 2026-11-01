package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Passive inventory never executes an unknown installed file. It reports only
// a same-owner receipt matching the complete actual executable, with bounded
// memory. This grants neither runtime ownership nor installation authority.
func mihomoInstalledReceiptVersion(ctx context.Context, path string) string {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Base(path) != "mihomo" {
		return ""
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return ""
	}
	defer root.Close()
	anchor, err := root.RootInfo()
	if err != nil {
		return ""
	}
	receiptName := ".mihomo.razvilka.json"
	receiptInfo, err := root.Stat(receiptName)
	if err != nil {
		return ""
	}
	raw, err := readHEVRetainedFile(root, receiptName, 2048, receiptInfo)
	if err != nil {
		return ""
	}
	var receipt externalReceipt
	approved, pinErr := mihomoReviewedRawArtifact(runtime.GOARCH)
	if pinErr != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Version != ReviewedMihomoVersion || receipt.SHA256 != approved.SHA256 {
		return ""
	}
	before, err := root.Stat("mihomo")
	if err != nil || !mihomoInstalledOwner(before) || before.Size() != approved.Size {
		return ""
	}
	f, err := root.OpenFile("mihomo", hevRetainedReadFlags, 0)
	if err != nil {
		return ""
	}
	held, err := f.Stat()
	if err != nil || !os.SameFile(before, held) || !mihomoInstalledOwner(held) {
		_ = f.Close()
		return ""
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(mihomoContextReader{ctx, f}, before.Size()+1), make([]byte, 64<<10))
	closed := f.Close()
	if err != nil || closed != nil || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != receipt.SHA256 {
		return ""
	}
	after, err := root.Stat("mihomo")
	namedRoot, e := os.Lstat(filepath.Dir(path))
	currentReceipt, e2 := root.Stat(receiptName)
	if err != nil || e != nil || e2 != nil || !os.SameFile(anchor, namedRoot) || !os.SameFile(before, after) || !mihomoInstalledOwner(after) || !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() || !os.SameFile(receiptInfo, currentReceipt) || receiptInfo.Size() != currentReceipt.Size() || !receiptInfo.ModTime().Equal(currentReceipt.ModTime()) || ctx.Err() != nil {
		return ""
	}
	return receipt.Version
}
