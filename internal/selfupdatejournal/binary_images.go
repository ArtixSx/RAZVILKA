package selfupdatejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// BinaryImage binds a retained controller to the validated immutable image
// digest. It is a trusted read-only inventory, never an HTTP destination.
type BinaryImage struct {
	Path   string
	SHA256 string
}

func (s *Store) RetainedBinaryImages(ctx context.Context) ([]BinaryImage, error) {
	images, _, err := s.retainedBinaryImages(ctx, "", false)
	return images, err
}

// This inventory permits only the matching current pending transaction. It
// admits reader formats, never command completion or runtime effects.
func (s *Store) RetainedBinaryImagesForSettlement(ctx context.Context, id string) ([]BinaryImage, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrMismatch
	}
	images, _, err := s.retainedBinaryImages(ctx, id, false)
	return images, err
}

// RequiredReadVersion is a bounded read-only scan. Pending/unknown commands
// remain pending; scanning their canonical format grants no recovery authority.
func (s *Store) RequiredReadVersion(ctx context.Context) (int, error) {
	_, required, err := s.retainedBinaryImages(ctx, "", true)
	return required, err
}

func (s *Store) retainedBinaryImages(ctx context.Context, pendingID string, scan bool) ([]BinaryImage, int, error) {
	required := 1
	current, present, err := s.Current()
	if err != nil {
		return nil, 0, err
	}
	directory, err := s.journalFiles.Open(".")
	if err != nil {
		return nil, 0, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(258)
	if err != nil && err != io.EOF {
		return nil, 0, err
	}
	if len(entries) > 257 {
		return nil, 0, ErrMismatch
	}
	var images []BinaryImage
	found := false
	marker := false
	transactions := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if entry.Name() == ".writer.lock" {
			info, err := s.journal.Stat(entry.Name())
			data, readErr := s.journal.ReadLimited(entry.Name(), 64)
			if runtime.GOOS == "windows" && readErr != nil && err == nil {
				if observed, ok := ctx.Value(writerObservationKey{}).(*writerObservation); ok && observed.active.Load() && observed.directory == s.journalFiles.Name() && observed.info != nil && os.SameFile(info, observed.info) {
					data, readErr = []byte("RAZVILKA self update writer v1\n"), nil
				}
			}
			if err != nil || readErr != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 || string(data) != "RAZVILKA self update writer v1\n" {
				return nil, 0, ErrMismatch
			}
			marker = true
			continue
		}
		if entry.Name() == "current.json" {
			data, err := s.journal.ReadLimited(entry.Name(), 4096)
			var pointer struct {
				Schema int    `json:"schema"`
				ID     string `json:"id"`
			}
			if err != nil || decode(data, &pointer) != nil || pointer.ID != current.ID || (pointer.Schema != 1 && pointer.Schema != Schema && pointer.Schema != StoppedSchema && pointer.Schema != PairedSchema) {
				return nil, 0, ErrMismatch
			}
			canonical, _ := json.Marshal(pointer)
			if !bytes.Equal(data, canonical) {
				return nil, 0, ErrMismatch
			}
			continue
		}
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			return nil, 0, ErrMismatch
		}
		data, err := s.journal.ReadLimited(entry.Name()+"/receipt.json", 16<<10)
		if err != nil {
			return nil, 0, err
		}
		var receipt Receipt
		if decode(data, &receipt) != nil || !valid(receipt) || receipt.ID != entry.Name() {
			return nil, 0, ErrMismatch
		}
		if receipt.Pending() && !scan && !(receipt.ID == pendingID && receipt.ID == current.ID && present) {
			return nil, 0, ErrPending
		}
		if receipt.Schema > required {
			required = receipt.Schema
		}
		canonical, err := json.Marshal(receipt)
		if err != nil || !bytes.Equal(data, canonical) {
			return nil, 0, ErrMismatch
		}
		if receipt.ID == current.ID {
			found = true
		}
		transactions++
		if err := s.verifyImages(receipt); err != nil {
			return nil, 0, err
		}
		if err := s.verifyPairedInventory(ctx, receipt, pendingID, scan); err != nil {
			return nil, 0, err
		}
		binaries := 0
		for i, file := range receipt.Files {
			if file.Target != "bin/razvilka" {
				continue
			}
			binaries++
			if receipt.Phase == "archived" {
				continue
			}
			base := filepath.Join(s.journalFiles.Name(), receipt.ID)
			if file.OldPresent {
				images = append(images, BinaryImage{filepath.Join(base, "old-"+strconv.Itoa(i)), file.OldHash})
			}
			images = append(images, BinaryImage{filepath.Join(base, "new-"+strconv.Itoa(i)), file.NewHash})
		}
		if binaries != 1 {
			return nil, 0, ErrMismatch
		}
	}
	if present && (!found || current.Pending() && !scan && current.ID != pendingID) || transactions > 0 && (!present || !marker) {
		return nil, 0, ErrPending
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return images, required, nil
}
