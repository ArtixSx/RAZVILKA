package selfupdatejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	current, present, err := s.Current()
	if err != nil {
		return nil, err
	}
	directory, err := s.journalFiles.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(258)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 257 {
		return nil, ErrMismatch
	}
	var images []BinaryImage
	found := false
	marker := false
	transactions := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Name() == ".writer.lock" {
			info, err := s.journal.Stat(entry.Name())
			data, readErr := s.journal.ReadLimited(entry.Name(), 64)
			if err != nil || readErr != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 || string(data) != "RAZVILKA self update writer v1\n" {
				return nil, ErrMismatch
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
			if err != nil || decode(data, &pointer) != nil || pointer.ID != current.ID || (pointer.Schema != 1 && pointer.Schema != Schema) {
				return nil, ErrMismatch
			}
			canonical, _ := json.Marshal(pointer)
			if !bytes.Equal(data, canonical) {
				return nil, ErrMismatch
			}
			continue
		}
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			return nil, ErrMismatch
		}
		data, err := s.journal.ReadLimited(entry.Name()+"/receipt.json", 16<<10)
		if err != nil {
			return nil, err
		}
		var receipt Receipt
		if decode(data, &receipt) != nil || !valid(receipt) || receipt.ID != entry.Name() || receipt.Pending() {
			return nil, ErrPending
		}
		canonical, err := json.Marshal(receipt)
		if err != nil || !bytes.Equal(data, canonical) {
			return nil, ErrMismatch
		}
		if receipt.ID == current.ID {
			found = true
		}
		transactions++
		if err := s.verifyImages(receipt); err != nil {
			return nil, err
		}
		binaries := 0
		for i, file := range receipt.Files {
			if file.Target != "bin/razvilka" {
				continue
			}
			binaries++
			base := filepath.Join(s.journalFiles.Name(), receipt.ID)
			if file.OldPresent {
				images = append(images, BinaryImage{filepath.Join(base, "old-"+strconv.Itoa(i)), file.OldHash})
			}
			images = append(images, BinaryImage{filepath.Join(base, "new-"+strconv.Itoa(i)), file.NewHash})
		}
		if binaries != 1 {
			return nil, ErrMismatch
		}
	}
	if present && (!found || current.Pending()) || transactions > 0 && (!present || !marker) {
		return nil, ErrPending
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return images, nil
}
